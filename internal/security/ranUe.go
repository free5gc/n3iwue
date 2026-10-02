package security

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/calee0219/fatal"
	"golang.org/x/net/ipv4"

	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas/logger"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

type RanUeContext struct {
	Supi               string
	RanUeNgapId        int64
	AmfUeNgapId        int64
	ULCount            security.Count
	DLCount            security.Count
	CipheringAlg       uint8
	IntegrityAlg       uint8
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	AnType             models.AccessType
	AuthenticationSubs models.AuthenticationSubscription

	SQNIndBitLen     uint8    // Number of index bits (2-16, default: 5)
	SQNWrappingDelta uint64   // Maximum allowed sequence advancement (default: 2^28)
	SQNArray         []uint64 // Array of highest SQN values per index
}

func CalculateIpv4HeaderChecksum(hdr *ipv4.Header) uint32 {
	var Checksum uint32
	Checksum += uint32((hdr.Version<<4|(20>>2&0x0f))<<8 | hdr.TOS)
	Checksum += uint32(hdr.TotalLen)
	Checksum += uint32(hdr.ID)
	Checksum += uint32((hdr.FragOff & 0x1fff) | (int(hdr.Flags) << 13))
	Checksum += uint32((hdr.TTL << 8) | (hdr.Protocol))

	src := hdr.Src.To4()
	Checksum += uint32(src[0])<<8 | uint32(src[1])
	Checksum += uint32(src[2])<<8 | uint32(src[3])
	dst := hdr.Dst.To4()
	Checksum += uint32(dst[0])<<8 | uint32(dst[1])
	Checksum += uint32(dst[2])<<8 | uint32(dst[3])
	return ^(Checksum&0xffff0000>>16 + Checksum&0xffff)
}

func GetAuthSubscription(k, sqn, amf, opc, op string) models.AuthenticationSubscription {
	var authSubs models.AuthenticationSubscription
	authSubs.EncPermanentKey = k
	authSubs.EncOpcKey = opc
	authSubs.EncTopcKey = op
	authSubs.AuthenticationManagementField = amf

	authSubs.SequenceNumber = &models.SequenceNumber{
		Sqn: sqn,
	}
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return authSubs
}

func NewRanUeContext(supi string, ranUeNgapId int64, cipheringAlg, integrityAlg uint8,
	AnType models.AccessType, initialSQN string,
) *RanUeContext {
	ue := RanUeContext{}
	ue.RanUeNgapId = ranUeNgapId
	ue.Supi = supi
	ue.CipheringAlg = cipheringAlg
	ue.IntegrityAlg = integrityAlg
	ue.AnType = AnType

	ue.SQNIndBitLen = 5           // Default: 5 bits for index (32 indices)
	ue.SQNWrappingDelta = 1 << 28 // Default: 2^28 (268M sequences)

	// Initialize SQN array
	arraySize := 1 << ue.SQNIndBitLen
	ue.SQNArray = make([]uint64, arraySize)

	// Initialize SQN from config if provided
	if initialSQN != "" {
		if sqnBytes, err := hex.DecodeString(initialSQN); err == nil && len(sqnBytes) == 6 {
			initialSQNUint := sqnBytesToUint64(sqnBytes)
			ue.setSqnMs(initialSQNUint)
		}
	}

	return &ue
}

func (ue *RanUeContext) DeriveRESstarAndSetKey(
	authSubs models.AuthenticationSubscription, rand []byte, snName string, autn []byte,
) []byte {
	sqn, err := hex.DecodeString(authSubs.SequenceNumber.Sqn)
	if err != nil {
		fatal.Fatalf("DecodeString error: %+v", err)
	}

	k, opc, amf, err := ue.getCryptographicKeys()
	if err != nil {
		fatal.Fatalf("getCryptographicKeys error: %+v", err)
	}

	ik, ck, res, _, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf)
	if err != nil {
		fatal.Fatalf("GenerateAKAParameters error: %+v", err)
	}

	// derive RES*
	key := append(ck, ik...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snName)
	P1 := rand
	P2 := res

	ue.DerivateKamf(key, snName, autn[:])
	ue.DerivateAlgKey()
	kdfVal_for_resStar, err := ueauth.GetKDFValue(
		key,
		FC,
		P0,
		ueauth.KDFLen(P0),
		P1,
		ueauth.KDFLen(P1),
		P2,
		ueauth.KDFLen(P2),
	)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:]
}

func (ue *RanUeContext) DerivateKamf(key []byte, snName string, autn []byte) {
	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SqnXorAK := autn[:6]
	P1 := SqnXorAK
	Kausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	P0 = []byte(snName)
	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}

	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	if err != nil {
		fatal.Fatalf("regexp Compile error: %+v", err)
	}
	groups := supiRegexp.FindStringSubmatch(ue.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *RanUeContext) DerivateAlgKey() {
	// Security Key
	P0 := []byte{security.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{ue.CipheringAlg}
	L1 := ueauth.KDFLen(P1)

	kenc, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{security.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{ue.IntegrityAlg}
	L1 = ueauth.KDFLen(P1)

	kint, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		fatal.Fatalf("GetKDFValue error: %+v", err)
	}
	copy(ue.KnasInt[:], kint[16:32])
}

func (ue *RanUeContext) GetUESecurityCapability() (UESecurityCapability *nasType.UESecurityCapability) {
	UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    2,
		Buffer: []uint8{0x00, 0x00},
	}
	switch ue.CipheringAlg {
	case security.AlgCiphering128NEA0:
		UESecurityCapability.SetEA0_5G(1)
	case security.AlgCiphering128NEA1:
		UESecurityCapability.SetEA1_128_5G(1)
	case security.AlgCiphering128NEA2:
		UESecurityCapability.SetEA2_128_5G(1)
	case security.AlgCiphering128NEA3:
		UESecurityCapability.SetEA3_128_5G(1)
	}

	switch ue.IntegrityAlg {
	case security.AlgIntegrity128NIA0:
		UESecurityCapability.SetIA0_5G(1)
	case security.AlgIntegrity128NIA1:
		UESecurityCapability.SetIA1_128_5G(1)
	case security.AlgIntegrity128NIA2:
		UESecurityCapability.SetIA2_128_5G(1)
	case security.AlgIntegrity128NIA3:
		UESecurityCapability.SetIA3_128_5G(1)
	}

	return
}

func (ue *RanUeContext) Get5GMMCapability() (capability5GMM *nasType.Capability5GMM) {
	return &nasType.Capability5GMM{
		Iei:   nasMessage.RegistrationRequestCapability5GMMType,
		Len:   1,
		Octet: [13]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
}

func (ue *RanUeContext) GetBearerType() uint8 {
	switch ue.AnType {
	case models.AccessType__3_GPP_ACCESS:
		return security.Bearer3GPP
	case models.AccessType_NON_3_GPP_ACCESS:
		return security.BearerNon3GPP
	default:
		return security.OnlyOneBearer
	}
}

// Authentication result constants
const (
	AuthSuccess        = iota // Authentication successful
	SQNOutOfSync              // SQN synchronization needed
	MACFailure                // MAC-A verification failed
	ReplayAttack              // Potential replay attack (old SQN)
	SQNTooFarAhead            // SQN too far ahead (>window)
	AuthParameterError        // Invalid AUTN/RAND parameters
)

// SQN utility functions

// sqnBytesToUint64 converts a 6-byte SQN to uint64 for arithmetic operations
func sqnBytesToUint64(sqn []byte) uint64 {
	if len(sqn) != 6 {
		return 0
	}

	var result uint64
	for i := 0; i < 6; i++ {
		result = (result << 8) | uint64(sqn[i])
	}
	return result
}

// uint64ToSqnBytes converts a uint64 SQN to 6-byte array
func uint64ToSqnBytes(sqn uint64) []byte {
	result := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		result[i] = byte(sqn & 0xFF)
		sqn >>= 8
	}
	return result
}

// getSeqFromSqn extracts the sequence number from a 48-bit SQN
func (ue *RanUeContext) getSeqFromSqn(sqn uint64) uint64 {
	// Clear index bits and shift right
	sqn &= ^((1 << ue.SQNIndBitLen) - 1)
	sqn >>= ue.SQNIndBitLen
	// Mask to 48-bit range
	sqn &= (1 << 48) - 1
	return sqn
}

// getIndFromSqn extracts the index from a 48-bit SQN
func (ue *RanUeContext) getIndFromSqn(sqn uint64) uint64 {
	return sqn & ((1 << ue.SQNIndBitLen) - 1)
}

// getSeqMs returns the highest sequence number among all indices
func (ue *RanUeContext) getSeqMs() uint64 {
	return ue.getSeqFromSqn(ue.getSqnMs())
}

// getSqnMs returns the highest SQN value among all indices
func (ue *RanUeContext) getSqnMs() uint64 {
	var maxSqn uint64
	for _, sqn := range ue.SQNArray {
		if sqn > maxSqn {
			maxSqn = sqn
		}
	}
	return maxSqn
}

func (ue *RanUeContext) setSqnMs(sqn uint64) {
	ind := ue.getIndFromSqn(sqn)
	logger.NasLog.Infof("setSqnMs: sqn=0x%012x, ind=%d", sqn, ind)
	ue.SQNArray[ind] = sqn
}

// getCurrentSqn returns the current SQN as 6-byte array (compatible with existing code)
func (ue *RanUeContext) getCurrentSqn() []byte {
	return uint64ToSqnBytes(ue.getSqnMs())
}

// getCryptographicKeys extracts K, OPc, and AMF from the authentication subscription
func (ue *RanUeContext) getCryptographicKeys() (k, opc, amf []byte, err error) {
	// Decode permanent key (K)
	k, err = hex.DecodeString(ue.AuthenticationSubs.EncPermanentKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode permanent key: %v", err)
	}

	// Decode AMF
	amf, err = hex.DecodeString(ue.AuthenticationSubs.AuthenticationManagementField)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode AMF: %v", err)
	}

	// Decode or generate OPC
	if ue.AuthenticationSubs.EncOpcKey != "" {
		opc, err = hex.DecodeString(ue.AuthenticationSubs.EncOpcKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode OPC: %v", err)
		}
	} else {
		// Generate OPC from OP
		op, err := hex.DecodeString(ue.AuthenticationSubs.EncTopcKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode OP: %v", err)
		}

		opc, err = milenage.GenerateOPc(k, op)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate OPC: %v", err)
		}
	}

	return k, opc, amf, nil
}

// VerifyAUTN performs comprehensive AUTN verification and SQN synchronization check
// Returns: (authResult, error)
func (ue *RanUeContext) VerifyAUTN(autn, rand []byte) (int, error) {
	nasLog := logger.NasLog
	k, opc, _, err := ue.getCryptographicKeys()
	if err != nil {
		return AuthParameterError, fmt.Errorf("failed to get cryptographic keys: %v", err)
	}

	// Input validation
	if len(autn) != 16 || len(rand) != 16 {
		return AuthParameterError,
			fmt.Errorf("invalid parameter length: AUTN=%d, RAND=%d", len(autn), len(rand))
	}

	// nolint:dogsled
	sqn, _, _, _, _, err := milenage.GenerateKeysWithAUTN(opc, k, rand, autn)
	if err != nil {
		var macErr *milenage.MACFailureError
		if errors.As(err, &macErr) {
			return MACFailure, fmt.Errorf("MAC-A verification failed")
		}
		return AuthParameterError, fmt.Errorf("failed to validate AUTN: %v", err)
	}

	// Check SQN after MAC verification
	if err := ue.checkSqn(sqnBytesToUint64(sqn)); err != nil {
		return SQNOutOfSync,
			fmt.Errorf("failed to check SQN: %v", err)
	}

	nasLog.Infof("Extracted SQN from AUTN: %x", sqn)

	return AuthSuccess, nil
}

// checkSqn implements validation SQN algorithm
// SQN = SEQ || IND (TS 33.102 C.1.1)
func (ue *RanUeContext) checkSqn(sqn uint64) error {
	seq := ue.getSeqFromSqn(sqn)
	ind := ue.getIndFromSqn(sqn)

	// Check 1: SQN too far ahead (wrapping delta check)
	seqMs := ue.getSeqMs()
	if seq > seqMs && (seq-seqMs) > ue.SQNWrappingDelta {
		return fmt.Errorf("SQN too far ahead: seq=%d, seqMs=%d, delta=%d",
			seq, seqMs, ue.SQNWrappingDelta)
	}

	// Check 2: Replay attack prevention (SQN must be greater than stored for this index)
	if len(ue.SQNArray) <= int(ind) {
		return fmt.Errorf("invalid SQN index: %d (array size: %d)", ind, len(ue.SQNArray))
	}

	storedSeqForInd := ue.getSeqFromSqn(ue.SQNArray[ind])
	if seq <= storedSeqForInd {
		return fmt.Errorf("SQN replay or too old: seq=%d <= stored_seq=%d for index=%d",
			seq, storedSeqForInd, ind)
	}

	// SQN is acceptable - update the array
	ue.SQNArray[ind] = sqn

	// TS 33.102
	// Sync the SQN for security in config
	if err := factory.SyncConfigSQN(sqn); err != nil {
		return fmt.Errorf("failed to sync config SQN: %v", err)
	}

	return nil
}

// GenerateAUTS generates Authentication Token for re-Synchronization
// AUTS = (SQN_MS ⊕ AK*) || MAC-S
func (ue *RanUeContext) GenerateAUTS(rand []byte) ([]byte, error) {
	if len(rand) != 16 {
		return nil, fmt.Errorf("invalid RAND length: %d", len(rand))
	}

	k, opc, _, err := ue.getCryptographicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get cryptographic keys: %v", err)
	}

	currentSQN := ue.getCurrentSqn()
	auts, err := milenage.GenerateAUTS(opc, k, rand, currentSQN)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AUTS: %v", err)
	}

	return auts, nil
}

package security

import (
	"bytes"
	"encoding/hex"
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

type Milenage struct {
	res   []byte // RES (Expected Response)
	ck    []byte // Cipher Key
	ik    []byte // Integrity Key
	ak    []byte // Anonymity Key
	ak_r  []byte // Anonymity Key for re-synchronization (AK*)
	mac_a []byte // Message Authentication Code A (MAC-A)
	mac_s []byte // Message Authentication Code S (MAC-S for re-sync)
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

	// Increment SQN as per original logic

	// Use optimized milenage calculation
	milenageResult, err := ue.calculateMilenage(sqn, rand, false)
	if err != nil {
		fatal.Fatalf("calculateMilenage error: %+v", err)
	}

	// derive RES*
	key := append(milenageResult.ck, milenageResult.ik...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snName)
	P1 := rand
	P2 := milenageResult.res

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
		Octet: [13]uint8{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
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

// calculateMilenage performs milenage computation
// dummyAmf: if true, uses AMF=0x0000 for re-synchronization; if false, uses configured AMF
func (ue *RanUeContext) calculateMilenage(sqn, rand []byte, dummyAmf bool) (*Milenage, error) {
	// Get cryptographic keys
	k, opc, configAmf, err := ue.getCryptographicKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get cryptographic keys: %v", err)
	}

	// Choose AMF value based on dummyAmf flag
	var amf []byte
	if dummyAmf {
		amf = []byte{0x00, 0x00} // For re-synchronization (TS 33.102)
	} else {
		amf = configAmf // Use configured AMF
	}

	// Allocate result buffers
	result := &Milenage{
		res:   make([]byte, 8),
		ck:    make([]byte, 16),
		ik:    make([]byte, 16),
		ak:    make([]byte, 6),
		ak_r:  make([]byte, 6),
		mac_a: make([]byte, 8),
		mac_s: make([]byte, 8),
	}

	// Generate MAC_A and MAC_S using F1
	err = milenage.F1(opc, k, rand, sqn, amf, result.mac_a, result.mac_s)
	if err != nil {
		return nil, fmt.Errorf("F1 computation failed: %v", err)
	}

	// Generate RES, CK, IK, AK, AK* using F2345
	err = milenage.F2345(opc, k, rand, result.res, result.ck, result.ik,
		result.ak, result.ak_r)
	if err != nil {
		return nil, fmt.Errorf("F2345 computation failed: %v", err)
	}

	return result, nil
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

		opc, err = milenage.GenerateOPC(k, op)
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
	// Input validation
	if len(autn) != 16 || len(rand) != 16 {
		return AuthParameterError,
			fmt.Errorf("invalid parameter length: AUTN=%d, RAND=%d", len(autn), len(rand))
	}

	// Extract AUTN components: (SQN⊕AK) || AMF || MAC-A
	receivedSQNxorAK := autn[:6] // First 6 bytes
	receivedMAC := autn[8:16]    // Last 8 bytes

	// Use direct F2345 to calculate AK for SQN recovery
	currentSQN := ue.getCurrentSqn()
	milenageResult, err := ue.calculateMilenage(currentSQN, rand, false)
	if err != nil {
		return AuthParameterError,
			fmt.Errorf("failed to calculate milenage for AUTS: %v", err)
	}

	// Recover actual SQN = (SQN⊕AK) ⊕ AK
	receivedSQN := make([]byte, 6)
	for i := 0; i < 6; i++ {
		receivedSQN[i] = receivedSQNxorAK[i] ^ milenageResult.ak[i]
	}

	// Now verify MAC-A with the recovered SQN
	milenageResult, err = ue.calculateMilenage(receivedSQN, rand, false)
	if err != nil {
		return AuthParameterError,
			fmt.Errorf("failed to calculate milenage for AUTS: %v", err)
	}

	if !bytes.Equal(milenageResult.mac_a, receivedMAC) {
		return MACFailure,
			fmt.Errorf("MAC-A verification failed")
	}

	// Check SQN after MAC verification
	sqnOk, err := ue.checkSqn(sqnBytesToUint64(receivedSQN))
	if err != nil {
		return SQNOutOfSync,
			fmt.Errorf("failed to check SQN: %v", err)
	}

	if !sqnOk {
		return SQNOutOfSync, err
	}
	nasLog.Infof("Extracted SQN from AUTN: %x", receivedSQN)

	return AuthSuccess, nil
}

// checkSqn implements validation SQN algorithm
// SQN = SEQ || IND (TS 33.102 C.1.1)
func (ue *RanUeContext) checkSqn(sqn uint64) (bool, error) {
	seq := ue.getSeqFromSqn(sqn)
	ind := ue.getIndFromSqn(sqn)

	// Check 1: SQN too far ahead (wrapping delta check)
	seqMs := ue.getSeqMs()
	if seq > seqMs && (seq-seqMs) > ue.SQNWrappingDelta {
		return false,
			fmt.Errorf("SQN too far ahead: seq=%d, seqMs=%d, delta=%d",
				seq, seqMs, ue.SQNWrappingDelta)
	}

	// Check 2: Replay attack prevention (SQN must be greater than stored for this index)
	if len(ue.SQNArray) <= int(ind) {
		return false,
			fmt.Errorf("invalid SQN index: %d (array size: %d)", ind, len(ue.SQNArray))
	}

	storedSeqForInd := ue.getSeqFromSqn(ue.SQNArray[ind])
	if seq <= storedSeqForInd {
		return false,
			fmt.Errorf("SQN replay or too old: seq=%d <= stored_seq=%d for index=%d",
				seq, storedSeqForInd, ind)
	}

	// SQN is acceptable - update the array
	ue.SQNArray[ind] = sqn

	// TS 33.102
	// Sync the SQN for security in config
	if err := factory.SyncConfigSQN(sqn); err != nil {
		return false, fmt.Errorf("failed to sync config SQN: %v", err)
	}

	return true, nil
}

// GenerateAUTS generates Authentication Token for re-Synchronization
// AUTS = (SQN_MS ⊕ AK*) || MAC-S
func (ue *RanUeContext) GenerateAUTS(rand []byte) ([]byte, error) {
	if len(rand) != 16 {
		return nil, fmt.Errorf("invalid RAND length: %d", len(rand))
	}

	currentSQN := ue.getCurrentSqn()

	// Calculate milenage with dummy AMF for re-synchronization
	milenageResult, err := ue.calculateMilenage(currentSQN, rand, true)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate milenage for AUTS: %v", err)
	}

	// Construct AUTS = (SQN_MS ⊕ AK*) || MAC-S
	auts := make([]byte, 14) // 6 + 8 bytes

	// First 6 bytes: SQN_MS ⊕ AK*
	for i := 0; i < 6; i++ {
		auts[i] = currentSQN[i] ^ milenageResult.ak_r[i]
	}

	// Last 8 bytes: MAC-S
	copy(auts[6:], milenageResult.mac_s)

	return auts, nil
}

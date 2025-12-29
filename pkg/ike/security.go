package ike

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

// [TS 24502] 9.3.2.2.2 EAP-Response/5G-NAS message
// Define EAP-Response/5G-NAS message and AN-Parameters Format.

// [TS 24501] 8.2.6.1.1  REGISTRATION REQUEST message content
// For dealing with EAP-5G start, return EAP-5G response including
// "AN-Parameters and NASPDU of Registration Request"

func (s *Server) BuildEAP5GANParameters() []byte {
	ikeLog := logger.IKELog
	var anParameters []byte
	n3ueSelf := s.Context()

	// [TS 24.502] 9.3.2.2.2.3
	// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
	// Therefore, IEI of AN-parameter is not needed to be included.

	// anParameter = AN-parameter Type | AN-parameter Length | Value part of IE

	// Build GUAMI
	anParameter := make([]byte, 2)
	guami := make([]byte, 6)
	amfID, err := n3ueSelf.N3ueInfo.GetAMFID()
	if err != nil {
		ikeLog.Fatalf("GetAMFID: %+v", err)
	}

	copy(guami[:3], n3ueSelf.N3ueInfo.BuildPLMN())
	copy(guami[3:], amfID)

	anParameter[0] = ike_message.ANParametersTypeGUAMI
	anParameter[1] = byte(len(guami))
	anParameter = append(anParameter, guami...)

	anParameters = append(anParameters, anParameter...)

	// Build Establishment Cause
	anParameter = make([]byte, 2)
	establishmentCause := make([]byte, 1)
	establishmentCause[0] = ike_message.EstablishmentCauseMO_Signaling
	anParameter[0] = ike_message.ANParametersTypeEstablishmentCause
	anParameter[1] = byte(len(establishmentCause))
	anParameter = append(anParameter, establishmentCause...)

	anParameters = append(anParameters, anParameter...)

	// Build PLMN ID
	anParameter = make([]byte, 2)
	plmnID := make([]byte, 3)
	copy(plmnID, n3ueSelf.N3ueInfo.BuildPLMN())
	anParameter[0] = ike_message.ANParametersTypeSelectedPLMNID
	anParameter[1] = byte(len(plmnID))
	anParameter = append(anParameter, plmnID...)

	anParameters = append(anParameters, anParameter...)

	// Build NSSAI
	anParameter = make([]byte, 2)
	var nssai []byte

	for _, SmPolicy := range factory.N3ueInfo.SmPolicy {
		// s-nssai = s-nssai length(1 byte) | SST(1 byte) | SD(3 bytes)
		snssai := make([]byte, 5)
		snssai[0] = 4
		snssaiBytes, err := SmPolicy.SNSSAI.ToBytes()
		if err != nil {
			ikeLog.Fatalf("Encode S-NSSAI Fail: %+v", err)
		}
		copy(snssai[1:], snssaiBytes)
		ikeLog.Debugf("S-NSSAI: %+v", snssaiBytes)
		nssai = append(nssai, snssai...)
	}
	anParameter[0] = ike_message.ANParametersTypeRequestedNSSAI
	anParameter[1] = byte(len(nssai))
	anParameter = append(anParameter, nssai...)

	anParameters = append(anParameters, anParameter...)

	return anParameters
}

func ParseIPAddressInformationToChildSecurityAssociation(
	childSecurityAssociation *context.ChildSecurityAssociation,
	trafficSelectorLocal *ike_message.IndividualTrafficSelector,
	trafficSelectorRemote *ike_message.IndividualTrafficSelector,
) error {
	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = net.ParseIP(
		factory.N3iwfInfo.IPSecIfaceAddr,
	)
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(
		factory.N3ueInfo.IPSecIfaceAddr,
	)

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	return nil
}

func GenerateSPI(n3ue *context.N3IWFIkeUe) ([]byte, error) {
	var spi uint32
	spiByte := make([]byte, 4)
	for {
		randomBigInt, err := ike_security.GenerateRandomNumber()
		if err != nil {
			return nil, errors.Wrapf(err, "GenerateSPI()")
		}
		randomUint64 := randomBigInt.Uint64()
		if _, ok := n3ue.N3IWFChildSecurityAssociation[uint32(randomUint64)]; !ok {
			spi = uint32(randomUint64)
			binary.BigEndian.PutUint32(spiByte, spi)
			break
		}
	}
	return spiByte, nil
}

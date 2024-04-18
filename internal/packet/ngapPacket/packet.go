package ngapPacket

import (
	// "github.com/free5gc/openapi/models"
	"encoding/binary"

	"github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap"
)

func GetNGSetupRequest(gnbId []byte, bitlength uint64, name string) ([]byte, error) {
	message := BuildNGSetupRequest()
	// GlobalRANNodeID
	ie := message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[0]
	gnbID := ie.Value.GlobalRANNodeID.GlobalGNBID.GNBID.GNBID
	gnbID.Bytes = gnbId
	gnbID.BitLength = bitlength
	// RANNodeName
	ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[1]
	ie.Value.RANNodeName.Value = name

	return ngap.Encoder(message)
}

func GetInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) ([]byte, error) {
	message := BuildInitialUEMessage(ranUeNgapID, nasPdu, fiveGSTmsi)
	return ngap.Encoder(message)
}

func GetUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	message := BuildUplinkNasTransport(amfUeNgapID, ranUeNgapID, nasPdu)
	return ngap.Encoder(message)
}

func GetInitialContextSetupResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := BuildInitialContextSetupResponseForRegistraionTest(amfUeNgapID, ranUeNgapID)

	return ngap.Encoder(message)
}

func GetInitialContextSetupResponseForServiceRequest(
	amfUeNgapID int64, ranUeNgapID int64, ipv4 string,
) ([]byte, error) {
	message := BuildInitialContextSetupResponse(amfUeNgapID, ranUeNgapID, ipv4, nil)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceSetupResponse(
	pduSessionId int64,
	amfUeNgapID int64,
	ranUeNgapID int64,
	ipv4 string,
) ([]byte, error) {
	message := BuildPDUSessionResourceSetupResponseForRegistrationTest(
		pduSessionId,
		amfUeNgapID,
		ranUeNgapID,
		ipv4,
	)
	return ngap.Encoder(message)
}

func EncodeNasPduWithSecurity(ue *security.RanUeContext, pdu []byte, securityHeaderType uint8,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}
	return security.NASEncode(ue, m, securityContextAvailable, newSecurityContext)
}

func EncodeNasPduInEnvelopeWithSecurity(
	ue *security.RanUeContext,
	pdu []byte,
	securityHeaderType uint8,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}
	return security.NASEnvelopeEncode(ue, m, securityContextAvailable, newSecurityContext)
}

func DecapNasPduFromEnvelope(envelop []byte) ([]byte, int) {
	// According to TS 24.502 8.2.4 and TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg, int(nasLen)
}

func GetUEContextReleaseComplete(
	amfUeNgapID int64,
	ranUeNgapID int64,
	pduSessionIDList []int64,
) ([]byte, error) {
	message := BuildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID, pduSessionIDList)
	return ngap.Encoder(message)
}

func GetUEContextReleaseRequest(
	amfUeNgapID int64,
	ranUeNgapID int64,
	pduSessionIDList []int64,
) ([]byte, error) {
	message := BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID, pduSessionIDList)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceReleaseResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := BuildPDUSessionResourceReleaseResponseForReleaseTest(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}

func GetPathSwitchRequest(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := BuildPathSwitchRequest(amfUeNgapID, ranUeNgapID)
	message.InitiatingMessage.Value.PathSwitchRequest.ProtocolIEs.List = message.
		InitiatingMessage.
		Value.
		PathSwitchRequest.
		ProtocolIEs.List[0:5]
	return ngap.Encoder(message)
}

func GetHandoverRequired(
	amfUeNgapID int64, ranUeNgapID int64, targetGNBID []byte, targetCellID []byte,
) ([]byte, error) {
	message := BuildHandoverRequired(amfUeNgapID, ranUeNgapID, targetGNBID, targetCellID)
	return ngap.Encoder(message)
}

func GetHandoverRequestAcknowledge(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := BuildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}

func GetHandoverNotify(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := BuildHandoverNotify(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceSetupResponseForPaging(
	amfUeNgapID int64,
	ranUeNgapID int64,
	ipv4 string,
) ([]byte, error) {
	message := BuildPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID, ipv4)
	return ngap.Encoder(message)
}

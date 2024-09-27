package handler

import (
	"net"
	"strconv"

	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	"github.com/free5gc/n3iwue/internal/security"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/openapi/models"
)

func SendNasMsg(ue *security.RanUeContext, conn net.Conn, msg []byte) {
	pdu, err := ngapPacket.EncodeNasPduInEnvelopeWithSecurity(
		ue,
		msg,
		nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		true,
		false,
	)
	if err != nil {
		naslog.Errorf("EncodeNasPduWithSecurity: %+v", err)
		return
	}

	_, err = conn.Write(pdu)
	if err != nil {
		naslog.Errorf("tcpConnWithN3IWF.Write: %+v", err)
		return
	}
}

func SendPduSessionEstablishmentRequest(ue *security.RanUeContext,
	conn net.Conn, pduSessionId uint8,
) error {
	sst, err := strconv.ParseInt(factory.N3ueInfo.SmPolicy[0].SNSSAI.SST, 16, 0)
	if err != nil {
		return err
	}

	sNssai := models.Snssai{
		Sst: int32(sst),
		Sd:  factory.N3ueInfo.SmPolicy[0].SNSSAI.SD,
	}

	pdu := nasPacket.GetUlNasTransport_PduSessionEstablishmentRequest(
		pduSessionId,
		nasMessage.ULNASTransportRequestTypeInitialRequest,
		"internet",
		&sNssai,
	)

	forwardData := make([]byte, len(pdu))
	copy(forwardData, pdu[:])

	SendNasMsg(ue, conn, forwardData)
	naslog.Tracef("send nas complete")
	return nil
}

func SendDeregistration() {
	n3ueContext := context.N3UESelf()
	if n3ueContext.GUTI != nil {
		mobileIdentity5GS := nasType.MobileIdentity5GS{
			Len:    n3ueContext.GUTI.Len,
			Buffer: n3ueContext.GUTI.Octet[:],
		}
		deregistrationRequest := nasPacket.GetDeregistrationRequest(0x02, 0x01, 0x00, mobileIdentity5GS)

		SendNasMsg(n3ueContext.RanUeContext, n3ueContext.N3IWFRanUe.TCPConnection, deregistrationRequest)
	}
}

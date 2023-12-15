package handler

import (
	"fmt"
	"net"
	"time"

	"github.com/free5gc/n3iwue/internal/gre"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/nas"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var naslog *logrus.Entry

func init() {
	naslog = logger.NASLog
}

func HandleRegistrationAccept(n3ueSelf *context.N3UE, nasMsg *nas.Message) {
	naslog.Tracef("Get Registration Accept")

	n3ueSelf.RanUeContext.DLCount.AddOne()

	// send NAS Registration Complete Msg
	pdu := nasPacket.GetRegistrationComplete(nil)
	SendNasMsg(n3ueSelf.RanUeContext, n3ueSelf.N3IWFUe.TCPConnection, pdu)

	time.Sleep(500 * time.Millisecond)
	n3ueSelf.CurrentState <- uint8(context.PduSessionEst)
}

func HandleDLNASTransport(n3ueSelf *context.N3UE, nasMsg *nas.Message) {
	payloadContainer := nasMsg.GmmMessage.DLNASTransport.PayloadContainer
	byteArray := payloadContainer.Buffer[:payloadContainer.Len]
	if err := nasMsg.GsmMessageDecode(&byteArray); err != nil {
		naslog.Errorf("NAS Decode Fail: %+v", err)
		return
	}

	switch nasMsg.GsmMessage.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		naslog.Tracef("Get PDUSession Establishment Accept")

		pduAddress, err := nasPacket.GetPDUAddress(nasMsg.GsmMessage.PDUSessionEstablishmentAccept)
		if err != nil {
			naslog.Errorf("GetPDUAddress Fail: %+v", err)
			return
		}

		naslog.Infof("PDU Address: %s", pduAddress.String())

		newGREName := fmt.Sprintf("%s-id-%d", n3ueSelf.N3ueInfo.GreIfaceName, n3ueSelf.N3ueInfo.XfrmiId)

		var linkGRE netlink.Link
		if linkGRE, err = gre.SetupGreTunnel(newGREName, n3ueSelf.TemporaryXfrmiName, n3ueSelf.UEInnerAddr.IP,
			n3ueSelf.TemporaryUPIPAddr, pduAddress, n3ueSelf.TemporaryQosInfo); err != nil {
			naslog.Errorf("Setup GRE tunnel %s Fail %+v", newGREName, err)
			return
		}

		// Add route
		upRoute := &netlink.Route{
			LinkIndex: linkGRE.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.IPv4Mask(0, 0, 0, 0),
			},
		}

		if err := netlink.RouteAdd(upRoute); err != nil {
			naslog.Warnf("netlink.RouteAdd: %+v", err)
		}

		n3ueSelf.PduSessionCount++
		n3ueSelf.CurrentState <- uint8(context.PduSessionEst)
	}
}

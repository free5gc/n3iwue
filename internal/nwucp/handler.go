package nwucp

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/gre"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasType"
)

func (s *Server) handleEvent(evt context.NwucpEvt) {
	switch t := evt.(type) {
	case *context.StartNwucpConnEvt:
		s.handleStartNwucpConnEvt()
	case *context.HandleRegistrationAcceptEvt:
		s.handleRegistrationAccept(t)
	case *context.HandleDLNASTransportEvt:
		s.handleDLNASTransport(t)
	case *context.StartPduSessionEstablishmentEvt:
		s.handleStartPduSessionEstablishmentEvt()
	case *context.SendDeregistrationEvt:
		s.handleSendDeregistrationEvt()
	case *context.HandleDeregistrationReqUeTerminatedEvt:
		s.handleDeregistrationReqUeTerminated(t)
	}
}

func (s *Server) handleStartNwucpConnEvt() {
	errChan := make(chan error)

	s.serverWg.Add(1)
	go s.serveConn(errChan)
	if err, ok := <-errChan; ok {
		logger.NWuCPLog.Errorf("NWUCP service startup failed: %+v", err)
		return
	}
}

func (s *Server) handleRegistrationAccept(evt *context.HandleRegistrationAcceptEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Registration Accept")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg
	n3ueSelf.RanUeContext.DLCount.AddOne()
	n3ueSelf.GUTI = nasMsg.GmmMessage.RegistrationAccept.GUTI5G

	// send NAS Registration Complete Msg
	pdu := nasPacket.GetRegistrationComplete(nil)
	SendNasMsg(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, pdu)

	s.SendProcedureEvt(context.NewSuccessRegistrationEvt())
}

func (s *Server) handleDLNASTransport(evt *context.HandleDLNASTransportEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get DLNAS Transport")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg

	payloadContainer := nasMsg.GmmMessage.DLNASTransport.PayloadContainer
	byteArray := payloadContainer.Buffer[:payloadContainer.Len]
	if err := nasMsg.GsmMessageDecode(&byteArray); err != nil {
		nwucpLog.Errorf("NAS Decode Fail: %+v", err)
		return
	}

	switch nasMsg.GsmMessage.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		nwucpLog.Tracef("Get PDUSession Establishment Accept")

		pduAddress, err := nasPacket.GetPDUAddress(nasMsg.GsmMessage.PDUSessionEstablishmentAccept)
		if err != nil {
			nwucpLog.Errorf("GetPDUAddress Fail: %+v", err)
			return
		}

		nwucpLog.Infof("PDU Address: %s", pduAddress.String())
		n3ueSelf.N3ueInfo.DnIPAddr = pduAddress.String()

		newGREName := fmt.Sprintf("%s-id-%d", n3ueSelf.N3ueInfo.GreIfaceName, n3ueSelf.N3ueInfo.XfrmiId)

		var linkGREs map[uint8]*netlink.Link
		if linkGREs, err = gre.SetupGreTunnels(newGREName, n3ueSelf.TemporaryXfrmiName, n3ueSelf.UEInnerAddr.IP,
			n3ueSelf.TemporaryUPIPAddr, pduAddress, n3ueSelf.TemporaryQosInfo); err != nil {
			nwucpLog.Errorf("Setup GRE tunnel %s Fail: %+v", newGREName, err)
			return
		}

		qfiToTargetMap, err := nasPacket.GetQFItoTargetMap(nasMsg.PDUSessionEstablishmentAccept)
		if err != nil {
			nwucpLog.Errorf("GetQFItoTargetMap Fail: %+v", err)
			return
		}

		// Add route
		for qfi, link := range linkGREs {
			tunnel := *link
			priority := 1 // lower is higher (1 ~ 7)

			var remoteAddress nasType.PacketFilterIPv4RemoteAddress
			var ok bool
			if qfi == uint8(1) { // default qfi
				remoteAddress.Address = net.IPv4zero
				remoteAddress.Mask = net.IPv4Mask(0, 0, 0, 0)
				priority = 7
			} else if remoteAddress, ok = qfiToTargetMap[qfi]; !ok {
				nwucpLog.Errorf("not found target address for QFI [%v] from NAS", qfi)
				continue
			}

			nwucpLog.Infof("Add route: QFI[%+v] remote address[%+v]", qfi, remoteAddress)
			upRoute := &netlink.Route{
				LinkIndex: tunnel.Attrs().Index,
				Dst: &net.IPNet{
					IP:   remoteAddress.Address,
					Mask: remoteAddress.Mask,
				},
				Priority: priority,
			}
			if err := netlink.RouteAdd(upRoute); err != nil {
				nwucpLog.Warnf("netlink.RouteAdd: %+v", err)
			}
		}

		n3ueSelf.PduSessionCount++
		s.SendProcedureEvt(context.NewPduSessionEstablishedEvt())
	}
}

func (s *Server) handleStartPduSessionEstablishmentEvt() {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Start PduSession Establishment")

	n3ueSelf := s.Context()
	err := SendPduSessionEstablishmentRequest(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, n3ueSelf.PduSessionCount)
	if err != nil {
		nwucpLog.Errorf("SendPduSessionEstablishmentRequest Fail: %+v", err)
		return
	}
}

func (s *Server) handleSendDeregistrationEvt() {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Send Deregistration")

	s.SendDeregistration()
}

func (s *Server) handleDeregistrationReqUeTerminated(evt *context.HandleDeregistrationReqUeTerminatedEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Deregistration Request UE Terminated")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg
	deregistrationRequest := nasMsg.GmmMessage.DeregistrationRequestUETerminatedDeregistration
	if deregistrationRequest == nil {
		nwucpLog.Errorf("Deregistration Request UE Terminated is nil")
		return
	}

	deregType := deregistrationRequest.SpareHalfOctetAndDeregistrationType
	deregistrationAccept := nasPacket.GetDeregistrationAccept()
	if deregType.GetReRegistrationRequired() == 1 {
		nwucpLog.Infof("handleDeregistrationReqUeTerminated(): Re-registration required")
		n3ueSelf.ReRegistrationRequired = true
	}

	// Send Deregistration Accept
	SendNasMsg(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, deregistrationAccept)

	// Stop TCP connection
	s.StopTCPConnection()
}

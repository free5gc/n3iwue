package ike

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/util"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/xfrm"
)

const (
	DEFAULT_IKE_PORT    = 500
	DEFAULT_NATT_PORT   = 4500
	IKE_EVENT_CHAN_SIZE = 128
)

type EspHandler func(srcIP, dstIP *net.UDPAddr, espPkt []byte) error

type N3iwue interface {
	Config() *factory.Config
	Context() *n3iwue_context.N3UE
	SendProcedureEvt(evt n3iwue_context.ProcedureEvt)
	TriggerGracefulShutdown(reason string)
}

type Server struct {
	N3iwue
	evtCh        chan n3iwue_context.IkeEvt
	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverWg     sync.WaitGroup
}

func NewServer(n3iwue N3iwue) (*Server, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background())
	return &Server{
		N3iwue:       n3iwue,
		evtCh:        make(chan n3iwue_context.IkeEvt, IKE_EVENT_CHAN_SIZE),
		serverCtx:    serverCtx,
		serverCancel: serverCancel,
	}, nil
}

func (s *Server) Run(wg *sync.WaitGroup) error {
	ikeLog := logger.IKELog
	ip := s.Config().Configuration.N3UEInfo.IPSecIfaceAddr
	ikeAddrPort, err := util.ResolveUDPAddrWithLog(fmt.Sprintf("%s:%d", ip, DEFAULT_IKE_PORT), ikeLog)
	if err != nil {
		return err
	}

	nattAddrPort, err := util.ResolveUDPAddrWithLog(fmt.Sprintf("%s:%d", ip, DEFAULT_NATT_PORT), ikeLog)
	if err != nil {
		return err
	}

	// Listen and serve on both ports
	errChan := make(chan error)

	wg.Add(1)
	s.serverWg.Add(1)
	go s.receiver(ikeAddrPort, errChan, wg)
	if err, ok := <-errChan; ok {
		s.serverCancel() // Cancel server context on error
		return util.WrapServiceError("IKE (port 500)", err)
	}

	errChan = make(chan error)

	wg.Add(1)
	s.serverWg.Add(1)
	go s.receiver(nattAddrPort, errChan, wg)
	if err, ok := <-errChan; ok {
		s.serverCancel() // Cancel server context on error
		return util.WrapServiceError("IKE (port 4500)", err)
	}

	wg.Add(1)
	s.serverWg.Add(1)
	go s.dispatcher(wg)

	ikeLog.Infof("IKE server started with event-driven architecture")
	return nil
}

// receiver implements the UDP message receiving functionality for IKEServer
func (s *Server) receiver(localAddr *net.UDPAddr, errChan chan<- error, wg *sync.WaitGroup) {
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		ikeLog.Infof("IKE receiver stopped")
		s.serverWg.Done() // Signal completion to server waitgroup
		wg.Done()
	}()

	udpListener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		ikeLog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	port := localAddr.Port
	cfg := s.Config().Configuration

	n3iwfAddr := cfg.N3IWFInfo.IPSecIfaceAddr + ":" + strconv.Itoa(port)
	n3iwfUDPAddr, err := util.ResolveUDPAddrWithLog(n3iwfAddr, ikeLog)
	if err != nil {
		errChan <- err
		return
	}

	n3ueAddr := cfg.N3UEInfo.IPSecIfaceAddr + ":" + strconv.Itoa(port)
	n3ueUDPAddr, err := util.ResolveUDPAddrWithLog(n3ueAddr, ikeLog)
	if err != nil {
		errChan <- err
		return
	}

	n3iwueCtx := s.Context()
	n3iwueCtx.IKEConnection[port] = &n3iwue_context.UDPSocketInfo{
		Conn:      udpListener,
		N3IWFAddr: n3iwfUDPAddr,
		UEAddr:    n3ueUDPAddr,
	}

	close(errChan)

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := udpListener.ReadFromUDP(data)
		if err != nil {
			if util.IsConnectionClosedError(err) {
				ikeLog.Warn("IKE UDP connection closed")
				return
			}
			ikeLog.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		if port == DEFAULT_NATT_PORT {
			forwardData, err = handleNattMsg(forwardData, remoteAddr, localAddr, handleESPPacket)
			if err != nil {
				ikeLog.Errorf("Handle NATT msg: %v", err)
				continue
			}
			if forwardData == nil {
				continue
			}
		}

		// Create IKE event and send to dispatcher (no fallback goroutine)
		socketInfo := &n3iwue_context.UDPSocketInfo{
			Conn:      udpListener,
			N3IWFAddr: remoteAddr,
			UEAddr:    localAddr,
		}

		ikeMsg, err := s.checkMessage(forwardData, socketInfo)
		if err != nil {
			ikeLog.Errorf("checkMessage failed: %+v", err)
			continue
		}

		var evt n3iwue_context.IkeEvt
		switch ikeMsg.ExchangeType {
		case ike_message.IKE_SA_INIT:
			evt = n3iwue_context.NewHandleIkeMsgSaInitEvt(socketInfo, ikeMsg, forwardData)
		case ike_message.IKE_AUTH:
			evt = n3iwue_context.NewHandleIkeMsgAuthEvt(socketInfo, ikeMsg, forwardData)
		case ike_message.CREATE_CHILD_SA:
			evt = n3iwue_context.NewHandleIkeMsgCreateChildSaEvt(socketInfo, ikeMsg, forwardData)
		case ike_message.INFORMATIONAL:
			evt = n3iwue_context.NewHandleIkeMsgInformationalEvt(socketInfo, ikeMsg, forwardData)
		default:
			ikeLog.Warnf("receiver(): Unimplemented IKE message type, exchange type: %d", ikeMsg.ExchangeType)
			continue
		}

		select {
		case s.evtCh <- evt:
			// Event sent successfully
		default:
			ikeLog.Errorf("Event channel is full, dropping IKE message")
		}
	}
}

func (s *Server) checkMessage(msg []byte, udpConnInfo *n3iwue_context.UDPSocketInfo) (
	*ike_message.IKEMessage, error,
) {
	var ikeHeader *ike_message.IKEHeader
	var ikeMessage *ike_message.IKEMessage
	var err error

	// parse IKE header and setup IKE context
	ikeHeader, err = ike_message.ParseHeader(msg)
	if err != nil {
		return nil, errors.Wrapf(err, "IKE msg decode header")
	}

	// check major version
	if ikeHeader.MajorVersion > 2 {
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload
		// For response or needed data
		payload := new(ike_message.IKEPayloadContainer)
		payload.BuildNotification(ike_message.TypeNone,
			ike_message.INVALID_MAJOR_VERSION, nil, nil)
		responseIKEMessage := ike_message.NewMessage(ikeHeader.InitiatorSPI, ikeHeader.ResponderSPI,
			ike_message.INFORMATIONAL, true, true, ikeHeader.MessageID, *payload)
		err = s.SendIkeMsgToN3iwf(udpConnInfo, responseIKEMessage, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "Received an IKE message with higher major version")
		}
		return nil, errors.Errorf("Received an IKE message with higher major version")
	}

	if ikeHeader.ExchangeType == ike_message.IKE_SA_INIT {
		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			nil, ike_message.Role_Initiator)
		if err != nil {
			return nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	} else {
		n3ueCtx := s.Context()

		if ikeHeader.InitiatorSPI != n3ueCtx.IkeInitiatorSPI {
			return nil, errors.Errorf("Drop this IKE message due to wrong InitiatorSPI: 0x%016x",
				ikeHeader.InitiatorSPI)
		}
		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation.IKESAKey,
			ike_message.Role_Initiator)
		if err != nil {
			return nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	}

	return ikeMessage, nil
}

func handleNattMsg(
	msgBuf []byte,
	rAddr, lAddr *net.UDPAddr,
	espHandler EspHandler,
) ([]byte, error) {
	if len(msgBuf) == 1 && msgBuf[0] == 0xff {
		// skip NAT-T Keepalive
		return nil, nil
	}

	nonEspMarker := []byte{0, 0, 0, 0} // Non-ESP Marker
	nonEspMarkerLen := len(nonEspMarker)
	if len(msgBuf) < nonEspMarkerLen {
		return nil, errors.Errorf("Received msg is too short")
	}
	if !bytes.Equal(msgBuf[:nonEspMarkerLen], nonEspMarker) {
		// ESP packet
		if espHandler != nil {
			err := espHandler(rAddr, lAddr, msgBuf)
			if err != nil {
				return nil, errors.Wrapf(err, "Handle ESP")
			}
		}
		return nil, nil
	}

	// IKE message: skip Non-ESP Marker
	msgBuf = msgBuf[nonEspMarkerLen:]
	return msgBuf, nil
}

func constructPacketWithESP(srcIP, dstIP *net.UDPAddr, espPacket []byte) ([]byte, error) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP.IP,
		DstIP:    dstIP.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolESP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer,
		options,
		ipLayer,
		gopacket.Payload(espPacket),
	)
	if err != nil {
		return nil, errors.Errorf("Error serializing layers: %v", err)
	}

	packetData := buffer.Bytes()
	return packetData, nil
}

func handleESPPacket(srcIP, dstIP *net.UDPAddr, espPacket []byte) error {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle ESPPacket")

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return errors.Errorf("socket error: %v", err)
	}

	defer func() {
		if err = syscall.Close(fd); err != nil {
			ikeLog.Errorf("Close fd error : %v", err)
		}
	}()

	ipPacket, err := constructPacketWithESP(srcIP, dstIP, espPacket)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{
		Addr: [4]byte(dstIP.IP),
		Port: dstIP.Port,
	}

	err = syscall.Sendto(fd, ipPacket, 0, &addr)
	if err != nil {
		return errors.Errorf("sendto error: %v", err)
	}

	return nil
}

// SendIkeEvt sends an IKE event to the event channel for processing
func (s *Server) SendIkeEvt(evt n3iwue_context.IkeEvt) {
	select {
	case s.evtCh <- evt:
		// Event sent successfully
	default:
		logger.IKELog.Errorf("Event channel is full, dropping IKE event")
	}
}

// Stop implements graceful shutdown of IKE server
func (s *Server) Stop() {
	ikeLog := logger.IKELog
	ikeLog.Infof("Starting IKE server shutdown")

	// Phase 1: Signal all goroutines to prepare for shutdown
	s.serverCancel()

	// Phase 2: Clean up resources
	s.cleanupAllResources()

	// Phase 3: Wait for all server goroutines to exit
	s.serverWg.Wait()

	ikeLog.Info("IKE server shutdown complete")
}

// cleanupAllResources performs final cleanup of IKE server resources
func (s *Server) cleanupAllResources() {
	ikeLog := logger.IKELog
	ikeLog.Infof("Cleaning up all IKE resources")

	n3ueCtx := s.Context()

	for _, udpConn := range n3ueCtx.IKEConnection {
		util.SafeCloseConn(udpConn.Conn, ikeLog, "cleanupAllResources")
	}

	if err := s.CleanChildSAXfrm(); err != nil {
		ikeLog.Errorf("CleanChildSAXfrm error: %v", err)
	}

	ikeSA := n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation
	// Stop DPD Timer
	ikeSA.StopInboundMessageTimer()

	// Stop Retransmit Timer
	ikeSA.StopReqRetransTimer()
}

func (s *Server) CleanChildSAXfrm() error {
	childSAs := s.Context().N3IWFUe.N3IWFChildSecurityAssociation
	for _, childSA := range childSAs {
		if err := xfrm.DeleteChildSAXfrm(childSA); err != nil {
			return errors.Wrapf(err, "CleanChildSAXfrm")
		}
	}
	return nil
}

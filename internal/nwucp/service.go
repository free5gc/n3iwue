package nwucp

import (
	"context"
	"encoding/hex"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	n3ue_security "github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/n3iwue/internal/util"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas"
)

const (
	NWUCP_EVENT_CHAN_SIZE = 128
)

type N3iwue interface {
	Config() *factory.Config
	Context() *n3iwue_context.N3UE
	CancelContext() context.Context
	SendProcedureEvt(evt n3iwue_context.ProcedureEvt)
}

type Server struct {
	N3iwue

	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverWg     sync.WaitGroup
	rcvEvtCh     chan n3iwue_context.NwucpEvt
}

func NewServer(n3iwue N3iwue) (*Server, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background())
	return &Server{
		N3iwue:       n3iwue,
		rcvEvtCh:     make(chan n3iwue_context.NwucpEvt, NWUCP_EVENT_CHAN_SIZE),
		serverCtx:    serverCtx,
		serverCancel: serverCancel,
	}, nil
}

func (s *Server) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	s.serverWg.Add(1)
	go s.dispatcher(wg)
}

func (s *Server) serveConn(errChan chan<- error) {
	nwucpLog := logger.NWuCPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwucpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		nwucpLog.Infof("NWUCP Connection closed")
		s.serverWg.Done()
	}()

	n3ueSelf := s.Context()

	localTCPAddr := &net.TCPAddr{
		IP: n3ueSelf.UEInnerAddr.IP,
	}
	tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3ueSelf.N3iwfNASAddr)
	if err != nil {
		errChan <- util.LogAndWrapError(err, nwucpLog, "TCP dial to N3IWF failed")
		return
	}
	n3ueSelf.N3IWFRanUe.TCPConnection = tcpConnWithN3IWF

	close(errChan)

	nwucpLog.Tracef("Successfully Create CP  %+v", n3ueSelf.N3iwfNASAddr)

	defer func() {
		util.SafeCloseConn(tcpConnWithN3IWF, nwucpLog, "serveConn")
	}()

	nasEnv := make([]byte, 65535)
	for {
		select {
		case <-s.serverCtx.Done():
			nwucpLog.Infof("NWUCP Connection closed by server context")
			return
		default:
			// Continue reading
		}

		if err := tcpConnWithN3IWF.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			nwucpLog.Debugf("serveConn: failed to set read deadline: %v", err)
		}

		n, err := tcpConnWithN3IWF.Read(nasEnv)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			nwucpLog.Errorf("Read TCP connection failed: %+v", err)
			return
		}
		nwucpLog.Tracef("Get NAS PDU from UE:\nNAS length: %d\nNAS content:\n%s", n, hex.Dump(nasEnv[:n]))

		forwardData := make([]byte, n)
		copy(forwardData, nasEnv[:n])

		nasMsg, err := s.DecapNasPdu(forwardData)
		if err != nil {
			nwucpLog.Errorf("Decap Nas Pdu Fail: %+v", err)
			continue
		}

		var evt n3iwue_context.NwucpEvt
		switch nasMsg.GmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationAccept:
			evt = n3iwue_context.NewHandleRegistrationAcceptEvt(nasMsg)
		case nas.MsgTypeDLNASTransport:
			evt = n3iwue_context.NewHandleDLNASTransportEvt(nasMsg)
		default:
			nwucpLog.Warnf("Unknown NAS Message Type: %+v", nasMsg.GmmMessage.GetMessageType())
			continue
		}
		s.SendNwucpEvt(evt)
	}
}

func (s *Server) DecapNasPdu(nasEnv []byte) (*nas.Message, error) {
	nasEnv, _ = ngapPacket.DecapNasPduFromEnvelope(nasEnv[:])
	nasMsg, err := n3ue_security.NASDecode(
		s.Context().RanUeContext,
		nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		nasEnv[:],
	)
	if err != nil {
		return nil, errors.Wrap(err, "NAS Decode Fail")
	}
	return nasMsg, nil
}

func (s *Server) dispatcher(wg *sync.WaitGroup) {
	nwucpLog := logger.NWuCPLog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwucpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			close(s.rcvEvtCh)
		}
		nwucpLog.Infof("NWUCP event dispatcher stopped")
		wg.Done()
		s.serverWg.Done()
	}()

	for {
		select {
		case <-s.serverCtx.Done():
			nwucpLog.Infof("NWUCP event dispatcher stopped by server context")
			return
		case evt := <-s.rcvEvtCh:
			s.handleEvent(evt)
		}
	}
}

func (s *Server) SendNwucpEvt(evt n3iwue_context.NwucpEvt) {
	select {
	case s.rcvEvtCh <- evt:
		// Event sent successfully
	default:
		logger.NWuCPLog.Errorf("Event channel is full, dropping NWUCP event")
	}
}

func (s *Server) Stop() {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Infof("Starting NWUCP server shutdown")

	// Phase 1: Signal all goroutines to prepare for shutdown
	s.serverCancel()

	// Phase 2: Wait for all server goroutines to exit
	s.serverWg.Wait()

	nwucpLog.Info("NWUCP server shutdown complete")
}

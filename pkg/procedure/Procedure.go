package procedure

import (
	"context"
	"fmt"
	"os/exec"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

var AppLog *logrus.Entry

const (
	PROCEDURE_EVENT_CHAN_SIZE = 128
)

func init() {
	// init logger
	AppLog = logger.AppLog
}

type N3iwue interface {
	Config() *factory.Config
	Context() *n3iwue_context.N3UE
	SendIkeEvt(evt n3iwue_context.IkeEvt)
	SendNwucpEvt(evt n3iwue_context.NwucpEvt)
	SignalDeregistrationComplete()
	TriggerGracefulShutdown(reason string)
}

type Server struct {
	N3iwue
	rcvEvtCh     chan n3iwue_context.ProcedureEvt
	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverWg     sync.WaitGroup
}

func NewServer(n3iwue N3iwue) (*Server, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background())
	return &Server{
		N3iwue:       n3iwue,
		serverCtx:    serverCtx,
		serverCancel: serverCancel,
		rcvEvtCh:     make(chan n3iwue_context.ProcedureEvt, PROCEDURE_EVENT_CHAN_SIZE),
	}, nil
}

func (s *Server) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	s.serverWg.Add(1)
	go s.dispatcher(wg)

	// Start Procedure
	s.SendProcedureEvt(n3iwue_context.NewStartRegistrationEvt())
}

func (s *Server) dispatcher(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			AppLog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
		}
		AppLog.Infof("Procedure event dispatcher stopped")
		s.serverWg.Done()
		wg.Done()
	}()

	for {
		select {
		case evt := <-s.rcvEvtCh:
			s.handleEvent(evt)
		case <-s.serverCtx.Done():
			AppLog.Infof("Procedure event dispatcher stopped by server context")
			return
		}
	}
}

func (s *Server) handleEvent(evt n3iwue_context.ProcedureEvt) {
	switch evt.(type) {
	case *n3iwue_context.StartRegistrationEvt:
		// Start IKE SA Establishment
		s.SendIkeEvt(n3iwue_context.NewStartIkeSaEstablishmentEvt())
	case *n3iwue_context.RestartRegistrationEvt:
		AppLog.Warnf("Restarting registration due to connection failure")
		s.SendIkeEvt(n3iwue_context.NewStartIkeSaEstablishmentEvt())
	case *n3iwue_context.NwucpChildSaCreatedEvt:
		// Establish NWUCP connection with N3IWF
		s.SendNwucpEvt(n3iwue_context.NewStartNwucpConnEvt())
	case *n3iwue_context.SuccessRegistrationEvt:
		// Start PduSession Establishment
		s.SendNwucpEvt(n3iwue_context.NewStartPduSessionEstablishmentEvt())
	case *n3iwue_context.DeregistrationCompleteEvt:
		s.handleDeregistrationCompleteEvt()
	case *n3iwue_context.PduSessionEstablishedEvt:
		// Test Connectivity
		AppLog.Info("PduSession Created")
		n3ueSelf := s.Context()

		if err := s.TestConnectivity("9.9.9.9"); err != nil {
			AppLog.Errorf("ping fail : %+v", err)
		}
		if err := s.TestConnectivity("1.1.1.1"); err != nil {
			AppLog.Errorf("ping fail : %+v", err)
		}
		if err := s.TestConnectivity("8.8.8.8"); err != nil {
			AppLog.Errorf("ping fail : %+v", err)
		} else {
			AppLog.Infof("ULCount=%x, DLCount=%x",
				n3ueSelf.RanUeContext.ULCount.Get(),
				n3ueSelf.RanUeContext.DLCount.Get())
			AppLog.Info("Keep connection with N3IWF until receive SIGINT or SIGTERM")
		}
	default:
		AppLog.Errorf("Unknown procedure event: %+v", evt)
	}
}

func (s *Server) TestConnectivity(addr string) error {
	n3ueSelf := s.Context()

	// Calculate the VRF ID used for the last session
	// Since PduSessionCount is incremented after session establishment, we subtract 1
	vrfID := n3ueSelf.PduSessionCount - 1
	vrfName := fmt.Sprintf("vrf-pdu-%d", vrfID)

	AppLog.Infof("Ping %s using VRF %s", addr, vrfName)

	args := []string{"vrf", "exec", vrfName, "ping", "-c", "5"}
	if n3ueSelf.N3ueInfo.DnIPAddr != "" {
		args = append(args, "-I", n3ueSelf.N3ueInfo.DnIPAddr)
	}
	args = append(args, addr)

	// Use ip vrf exec to ping
	cmd := exec.Command("ip", args...)

	// We can capture output to log it
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping failed: %v, output: %s", err, string(output))
	}

	AppLog.Infof("Ping output:\n%s", string(output))
	return nil
}

func (s *Server) SendProcedureEvt(evt n3iwue_context.ProcedureEvt) {
	select {
	case s.rcvEvtCh <- evt:
		// Event sent successfully
	default:
		AppLog.Errorf("Event channel is full, dropping Procedure event")
	}
}

func (s *Server) Stop() {
	AppLog.Infof("Starting Procedure server shutdown")
	s.serverCancel()
	s.serverWg.Wait()
	AppLog.Info("Procedure server shutdown complete")
}

func (s *Server) handleDeregistrationCompleteEvt() {
	AppLog.Info("Deregistration complete event received")

	n3ueSelf := s.Context()
	if n3ueSelf.ReRegistrationRequired {
		AppLog.Info("Re-registration required, triggering reconnection")
		// Trigger IKE reconnection
		s.SendIkeEvt(n3iwue_context.NewIkeReConnectEvt())
	} else {
		AppLog.Info("Re-registration not required, shutting down application")
		// Trigger application graceful shutdown
		s.TriggerGracefulShutdown("deregistration complete without re-registration")
	}
}

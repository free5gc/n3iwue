package service

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/nwucp"
	"github.com/free5gc/n3iwue/internal/util"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike"
	"github.com/free5gc/n3iwue/pkg/procedure"
)

var n3iwueApp *N3iwueApp

// N3iwueApp represents the main N3IWUE application that orchestrates all components
// and manages the lifecycle of the entire n3iwue service.
type N3iwueApp struct {
	// Context management
	parentCtx context.Context    // Parent context from main application
	ctx       context.Context    // Application-specific context for graceful shutdown
	cancel    context.CancelFunc // Function to cancel application context
	wg        sync.WaitGroup     // WaitGroup to synchronize goroutine shutdown

	// Core components
	n3iwueCtx *n3iwue_context.N3UE // Centralized context for UE state management
	cfg       *factory.Config      // Configuration management

	// IKE Server
	ikeServer *ike.Server // IKE server for IPSec tunnel establishment

	// Procedure Server
	procedureServer *procedure.Server // Procedure server for IKE SA establishment

	// NWUCP Server
	nwucpServer *nwucp.Server // NWUCP server for NAS transport

	// Graceful shutdown synchronization
	deregCompleteCh chan struct{} // Channel to signal deregistration completion

	IsDeregistrationComplete bool // Flag to indicate if deregistration is complete
}

// NewApp creates and initializes a new N3IWUE application instance.
// The application initializes the UE context, configuration and IKE server.
func NewApp(ctx context.Context, cfg *factory.Config) (*N3iwueApp, error) {
	// Initialize basic application structure
	n3iwue := &N3iwueApp{
		parentCtx:       ctx,
		cfg:             cfg,
		deregCompleteCh: make(chan struct{}),
	}

	// Create cancellable context for graceful shutdown
	n3iwue.ctx, n3iwue.cancel = context.WithCancel(ctx)

	// Initialize logging configuration
	cfg.SetLogLevel()

	// Initialize UE context
	n3iwue.n3iwueCtx = n3iwue_context.N3UESelf()

	// Initialize IKE server
	var err error
	if n3iwue.ikeServer, err = ike.NewServer(n3iwue); err != nil {
		return nil, err
	}

	// Initialize NWUCP server
	if n3iwue.nwucpServer, err = nwucp.NewServer(n3iwue); err != nil {
		return nil, err
	}

	// Initialize Procedure server
	if n3iwue.procedureServer, err = procedure.NewServer(n3iwue); err != nil {
		return nil, err
	}

	return n3iwue, nil
}

func Start() {
	logger.AppLog.Info("N3UE Start")
	util.InitN3UEContext()

	// Create N3IWUE app
	ctx, cancelCtx := context.WithCancel(context.Background())
	var err error
	n3iwueApp, err = NewApp(ctx, &factory.N3ueConfig)
	if err != nil {
		logger.InitLog.Fatalf("Failed to create N3IWUE app: %+v", err)
	}

	// Graceful Shutdown
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		<-signalChannel
		logger.InitLog.Info("Shutdown signal received, starting graceful shutdown...")

		if n3iwueApp.IsDeregistrationComplete {
			return
		}

		// Send deregistration request through NWUCP server
		if n3iwueApp.nwucpServer != nil {
			logger.InitLog.Info("Sending deregistration request...")
			n3iwueApp.nwucpServer.SendNwucpEvt(n3iwue_context.NewSendDeregistrationEvt())

			// Wait for deregistration completion or timeout
			select {
			case <-n3iwueApp.deregCompleteCh:
				logger.InitLog.Info("Deregistration completed successfully")
			case <-time.After(4 * time.Second):
				logger.InitLog.Warn("Deregistration timeout after 4 seconds, proceeding with shutdown")
			}
		} else {
			logger.InitLog.Warn("NWUCP server not available, skipping deregistration")
		}

		// Now proceed with normal shutdown
		cancelCtx()
		Terminate()
	}()

	defer func() {
		select {
		case signalChannel <- nil: // Send signal in case of returning with error
		default:
		}
	}()

	// Start the app
	if err := n3iwueApp.Run(); err != nil {
		logger.InitLog.Errorf("Start N3IWUE app failed: %+v", err)
		return
	}

	n3iwueApp.WaitRoutineStopped()
}

func Terminate() {
	logger.InitLog.Info("Terminating N3UE...")
	logger.InitLog.Info("Deleting interfaces created by N3UE")
	RemoveIPsecInterfaces()

	if n3iwueApp != nil {
		n3iwueApp.Stop()
	}

	// NWUCP server will be closed by terminateProcedure()
	logger.InitLog.Info("N3UE terminated")
}

// CancelContext returns the application's cancellable context for graceful shutdown
func (a *N3iwueApp) CancelContext() context.Context {
	return a.ctx
}

// Context returns the centralized N3UE context for UE state management
func (a *N3iwueApp) Context() *n3iwue_context.N3UE {
	return a.n3iwueCtx
}

// Config returns the current N3IWUE configuration
func (a *N3iwueApp) Config() *factory.Config {
	return a.cfg
}

// Run starts the N3IWUE application and the IKE server.
// The startup sequence:
// 1. Start shutdown event listener
// 2. Start IKE server
func (a *N3iwueApp) Run() error {
	mainLog := logger.AppLog

	// Start shutdown event listener
	a.wg.Add(1)
	go a.listenShutdownEvent()

	// Start IKE server
	if err := a.ikeServer.Run(&a.wg); err != nil {
		return err
	}
	mainLog.Infof("IKE service running")

	// Start NWUCP server
	a.nwucpServer.Run(&a.wg)
	mainLog.Infof("NWUCP service running")

	// Start Procedure server
	a.procedureServer.Run(&a.wg)
	mainLog.Infof("Procedure service running")

	mainLog.Infof("N3IWUE started")
	return nil
}

// Stop implements graceful shutdown for the N3IWUE application
func (a *N3iwueApp) Stop() {
	mainLog := logger.AppLog
	mainLog.Infof("Stopping N3IWUE")
	a.cancel()

	// Close deregistration channel to prevent any pending signals
	select {
	case <-a.deregCompleteCh:
		mainLog.Info("Deregistration completed, continuing shutdown")
		// Already received signal, continue
	default:
		mainLog.Info("Deregistration not completed, closing channel")
		close(a.deregCompleteCh)
	}

	a.WaitRoutineStopped()
}

// GetApp returns the global N3IWUE application instance
func GetApp() *N3iwueApp {
	return n3iwueApp
}

// listenShutdownEvent listens for application context cancellation and initiates graceful shutdown
func (a *N3iwueApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			logger.AppLog.Fatalf("Panic in shutdown listener: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.terminateProcedure()
}

// WaitRoutineStopped waits for all goroutines to complete
func (a *N3iwueApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.AppLog.Infof("All goroutines stopped")
}

// terminateProcedure performs graceful shutdown of the IKE server
func (a *N3iwueApp) terminateProcedure() {
	mainLog := logger.AppLog
	mainLog.Info("Stopping service created by N3IWUE")

	// Stop IKE server
	if a.ikeServer != nil {
		a.ikeServer.Stop()
	}

	// Stop NWUCP server
	if a.nwucpServer != nil {
		a.nwucpServer.Stop()
	}

	// Stop Procedure server
	if a.procedureServer != nil {
		a.procedureServer.Stop()
	}
}

// SendIkeEvt sends IKE events to the IKE server for processing
func (a *N3iwueApp) SendIkeEvt(evt n3iwue_context.IkeEvt) {
	if a.ikeServer != nil {
		a.ikeServer.SendIkeEvt(evt)
	}
}

// SendProcedureEvt sends Procedure events to the Procedure server for processing
func (a *N3iwueApp) SendProcedureEvt(evt n3iwue_context.ProcedureEvt) {
	if a.procedureServer != nil {
		a.procedureServer.SendProcedureEvt(evt)
	}
}

// SendNwucpEvt sends NWUCP events to the NWUCP server for processing
func (a *N3iwueApp) SendNwucpEvt(evt n3iwue_context.NwucpEvt) {
	if a.nwucpServer != nil {
		a.nwucpServer.SendNwucpEvt(evt)
	}
}

// SignalDeregistrationComplete signals that deregistration is complete
func (a *N3iwueApp) SignalDeregistrationComplete() {
	select {
	case a.deregCompleteCh <- struct{}{}:
		// Signal sent successfully
	default:
		// Channel already closed or full, ignore
	}
}

// TriggerGracefulShutdown triggers application shutdown from internal events
func (a *N3iwueApp) TriggerGracefulShutdown(reason string) {
	mainLog := logger.AppLog
	mainLog.Infof("Triggering graceful shutdown: %s", reason)

	a.IsDeregistrationComplete = true
	a.cancel() // Cancel application context

	// Start shutdown process in a separate goroutine
	go func() {
		mainLog.Info("Starting internal shutdown process")
		a.terminateProcedure()
		mainLog.Info("Internal shutdown completed")
	}()
}

func RemoveIPsecInterfaces() {
	n3ueSelf := n3iwue_context.N3UESelf()
	for _, iface := range n3ueSelf.CreatedIface {
		if err := netlink.LinkDel(*iface); err != nil {
			logger.AppLog.Errorf("Delete interface %s fail: %+v", (*iface).Attrs().Name, err)
		} else {
			logger.AppLog.Infof("Delete interface: %s", (*iface).Attrs().Name)
		}
	}
}

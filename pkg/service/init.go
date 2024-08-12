package service

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/logger"
	nwucp_handler "github.com/free5gc/n3iwue/internal/nwucp/handler"
	"github.com/free5gc/n3iwue/internal/util"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	ike_service "github.com/free5gc/n3iwue/pkg/ike/service"
	"github.com/free5gc/n3iwue/pkg/procedure"
)

func Initialize() error {
	if err := factory.InitConfigFactory("./config/n3ue.yaml"); err != nil {
		return fmt.Errorf("factory.InitConfigFactory: %+v", err)
	}
	if _, err := factory.N3ueConfig.Validate(); err != nil {
		return fmt.Errorf("Validate config fail: %+v", err)
	}
	return nil
}

func Start() {
	logger.AppLog.Info("N3UE Start")
	util.InitN3UEContext()

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
		nwucp_handler.SendDeregistration()
		Terminate()
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	wg := sync.WaitGroup{}

	if err := ike_service.Run(); err != nil {
		logger.InitLog.Errorf("Start IKE service failed: %+v", err)
		return
	}
	logger.InitLog.Info("IKE service running.")
	wg.Add(1)

	logger.InitLog.Info("N3UE running...")
	procedure.StartProcedure()

	wg.Wait()
}

func Terminate() {
	logger.InitLog.Info("Terminating N3UE...")
	logger.InitLog.Info("Deleting interfaces created by N3UE")
	RemoveIPsecInterfaces()
	logger.InitLog.Info("N3UE terminated")
}

func RemoveIPsecInterfaces() {
	n3ueSelf := context.N3UESelf()
	for _, iface := range n3ueSelf.CreatedIface {
		if err := netlink.LinkDel(*iface); err != nil {
			logger.AppLog.Errorf("Delete interface %s fail: %+v", (*iface).Attrs().Name, err)
		} else {
			logger.AppLog.Infof("Delete interface: %s", (*iface).Attrs().Name)
		}
	}
}

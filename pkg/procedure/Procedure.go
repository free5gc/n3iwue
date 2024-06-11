package procedure

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	nwucp_handler "github.com/free5gc/n3iwue/internal/nwucp/handler"
	nwucp_service "github.com/free5gc/n3iwue/internal/nwucp/service"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/ike/handler"
)

var (
	AppLog   *logrus.Entry
	n3ueSelf = context.N3UESelf()
)

func init() {
	// init logger
	AppLog = logger.AppLog
}

func StartProcedure() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			AppLog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	AppLog.Tracef("Start Registration")

	n3ueSelf.CurrentState = make(chan uint8)

	go func() {
		for {
			state := <-n3ueSelf.CurrentState
			switch state {
			case context.Registration_IKEINIT:
				handler.SendIKESAINIT()
			case context.Registration_IKEAUTH:
				handler.SendIKEAUTH()
			case context.Registration_CreateNWUCP:
				if err := nwucp_service.Run(); err != nil {
					AppLog.Fatalf("Start nuwcp service failed: %+v", err)
					return
				}
			case context.PduSessionEst:
				AppLog.Info("Start PduSession Establishment")
				done := false
				for !done {
					err := nwucp_handler.
						SendPduSessionEstablishmentRequest(n3ueSelf.RanUeContext,
							n3ueSelf.N3IWFRanUe.TCPConnection, n3ueSelf.PduSessionCount)
					if err != nil {
						AppLog.Errorf("Send PduSession Establishment Request failed: %+v", err)
					} else {
						done = true
					}
				}
			case context.PduSessionCreated:
				AppLog.Info("PduSession Created")
				if err := TestConnectivity("9.9.9.9"); err != nil {
					AppLog.Errorf("ping fail : %+v", err)
				}
				if err := TestConnectivity("1.1.1.1"); err != nil {
					AppLog.Errorf("ping fail : %+v", err)
				}
				if err := TestConnectivity("8.8.8.8"); err != nil {
					AppLog.Errorf("ping fail : %+v", err)
				} else {
					logger.NASLog.Infof("ULCount=%x, DLCount=%x",
						n3ueSelf.RanUeContext.ULCount.Get(),
						n3ueSelf.RanUeContext.DLCount.Get())
					AppLog.Info("Keep connection with N3IWF until receive SIGINT or SIGTERM")
				}
			}
		}
	}()
	n3ueSelf.CurrentState <- uint8(context.Registration_IKEINIT)
}

func TestConnectivity(addr string) error {
	// Ping remote
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return err
	}

	// Run with root
	pinger.SetPrivileged(true)

	pinger.OnRecv = func(pkt *ping.Packet) {
		AppLog.Infof("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		AppLog.Infof("\n--- %s ping statistics ---\n", stats.Addr)
		AppLog.Infof("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		AppLog.Infof("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	if n3ueSelf.N3ueInfo.DnIPAddr != "" {
		pinger.Source = n3ueSelf.N3ueInfo.DnIPAddr
	}

	time.Sleep(3 * time.Second)

	if err := pinger.Run(); err != nil {
		return fmt.Errorf("Running ping failed: %+v", err)
	}

	time.Sleep(1 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		return fmt.Errorf("Ping Failed")
	}

	return nil
}

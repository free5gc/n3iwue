package service

import (
	"errors"
	"net"
	"runtime/debug"
	"strings"

	n3iwfContext "github.com/free5gc/n3iwf/pkg/context"

	context "github.com/free5gc/n3iwue/pkg/context"

	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike"
	"github.com/sirupsen/logrus"
)

var ikeLog *logrus.Entry

func init() {
	// init logger
	ikeLog = logger.IKELog
}

func Run() error {
	bindAddr := factory.N3ueInfo.IPSecIfaceAddr + ":500"
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		ikeLog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.New("IKE service run failed")
	}

	// Listen and serve
	var errChan chan error
	errChan = make(chan error)

	go listenAndServe(udpAddr, errChan)
	if err, ok := <-errChan; ok {
		ikeLog.Errorln(err)
		return errors.New("IKE service run failed")
	}

	return nil
}

func listenAndServe(localAddr *net.UDPAddr, errChan chan<- error) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	udpListener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		ikeLog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	n3ueContext := context.N3UESelf()

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", factory.N3iwfInfo.IPSecIfaceAddr+":500")
	if err != nil {
		ikeLog.Errorf("Resolve UDP address %s fail: %+v", factory.N3iwfInfo.IPSecIfaceAddr+":500", err)
		return
	}

	n3ueUDPAddr, err := net.ResolveUDPAddr("udp", factory.N3ueInfo.IPSecIfaceAddr+":500")
	if err != nil {
		ikeLog.Errorf("Resolve UDP address %s fail: %+v", factory.N3ueInfo.IPSecIfaceAddr+":500", err)
		return
	}

	n3ueContext.N3IWFUe.IKEConnection = &n3iwfContext.UDPSocketInfo{
		Conn:      udpListener,
		N3IWFAddr: n3iwfUDPAddr,
		UEAddr:    n3ueUDPAddr,
	}

	close(errChan)

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := udpListener.ReadFromUDP(data)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				ikeLog.Errorf("ReadFromUDP failed: %+v", err)
				return
			}
			ikeLog.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		go ike.Dispatch(udpListener, localAddr, remoteAddr, forwardData)
	}
}

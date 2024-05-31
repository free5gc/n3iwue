package service

import (
	"encoding/hex"
	"errors"
	"net"
	"runtime/debug"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/nwucp"
	context "github.com/free5gc/n3iwue/pkg/context"
)

var nwucpLog *logrus.Entry

func init() {
	nwucpLog = logger.NWuCPLog
}

func Run() error {
	n3ueSelf := context.N3UESelf()

	errChan := make(chan error)

	go serveConn(n3ueSelf, errChan)
	if err, ok := <-errChan; ok {
		nwucpLog.Errorln(err)
		return errors.New("IKE service run failed")
	}
	nwucpLog.Tracef("Successfully Create CP  %+v", n3ueSelf.N3iwfNASAddr)

	return nil
}

func serveConn(n3ueSelf *context.N3UE, errChan chan<- error) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.NWuCPLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	localTCPAddr := &net.TCPAddr{
		IP: n3ueSelf.UEInnerAddr.IP,
	}
	tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3ueSelf.N3iwfNASAddr)
	if err != nil {
		nwucpLog.Error(err)
		errChan <- errors.New("nwup serveConn failed")
	}
	n3ueSelf.N3IWFRanUe.TCPConnection = tcpConnWithN3IWF

	close(errChan)

	defer func() {
		err := tcpConnWithN3IWF.Close()
		if err != nil {
			nwucpLog.Errorf("Error closing connection: %+v", err)
		}
	}()

	nasEnv := make([]byte, 65535)
	for {
		n, err := tcpConnWithN3IWF.Read(nasEnv)
		if err != nil {
			if err.Error() == "EOF" {
				nwucpLog.Warn("Connection close by peer")
				n3ueSelf.N3IWFRanUe.TCPConnection = nil
				return
			} else {
				nwucpLog.Errorf("Read TCP connection failed: %+v", err)
			}
		}
		nwucpLog.Tracef("Get NAS PDU from UE:\nNAS length: %d\nNAS content:\n%s", n, hex.Dump(nasEnv[:n]))

		forwardData := make([]byte, n)
		copy(forwardData, nasEnv[:n])

		go nwucp.Dispatch(tcpConnWithN3IWF, forwardData)
	}
}

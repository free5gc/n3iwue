package service

import (
	"net"
	"runtime/debug"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwue/internal/logger"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/handler"
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
	errChan := make(chan error)

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

	n3ueContext.N3IWFUe.IKEConnection = &context.UDPSocketInfo{
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

		ikeMsg, err := checkMessage(forwardData, udpListener, localAddr, remoteAddr)
		if err != nil {
			ikeLog.Errorf("checkMessage failed: %+v", err)
			continue
		}

		go handler.Dispatch(udpListener, localAddr, remoteAddr, ikeMsg)
	}
}

func checkMessage(msg []byte, udpConn *net.UDPConn,
	localAddr, remoteAddr *net.UDPAddr) (
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
		err = handler.SendIKEMessageToN3IWF(udpConn, localAddr, remoteAddr, responseIKEMessage, nil)
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
		n3ueCtx := context.N3UESelf()

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

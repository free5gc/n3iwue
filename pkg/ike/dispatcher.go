package ike

import (
	"net"
	"runtime/debug"

	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/pkg/ike/handler"
	"github.com/sirupsen/logrus"
)

var ikeLog *logrus.Entry

func init() {
	ikeLog = logger.IKELog
}

func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr, msg []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	ikeMessage := new(ike_message.IKEMessage)

	err := ikeMessage.Decode(msg)
	if err != nil {
		ikeLog.Error(err)
		return
	}

	if ikeMessage == nil {
		ikeLog.Error("IKE Message is nil")
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.INFORMATIONAL:
		handler.HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage)
	default:
		ikeLog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}

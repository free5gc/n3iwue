package handler

import (
	"net"
	"runtime/debug"

	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwue/internal/logger"
)

func init() {
	ikeLog = logger.IKELog
}

func Dispatch(udpConn *net.UDPConn, localAddr, remoteAddr *net.UDPAddr,
	ikeMessage *ike_message.IKEMessage,
) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.IKELog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.IKE_AUTH:
		HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage)
	case ike_message.INFORMATIONAL:
		HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage)
	default:
		ikeLog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}

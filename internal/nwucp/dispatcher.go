package nwucp

import (
	"net"
	"runtime/debug"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/nwucp/handler"
	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	n3ue_security "github.com/free5gc/n3iwue/internal/security"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/nas"
)

var naslog *logrus.Entry

func init() {
	naslog = logger.NASLog
}

func Dispatch(conn net.Conn, nasEnv []byte) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			naslog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	n3ueSelf := context.N3UESelf()

	// Decap Nas envelope
	nasEnv, _ = ngapPacket.DecapNasPduFromEnvelope(nasEnv[:])
	nasMsg, err := n3ue_security.NASDecode(
		n3ueSelf.RanUeContext,
		nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		nasEnv[:],
	)
	if err != nil {
		naslog.Errorf("NAS Decode Fail: %+v", err)
		return
	}

	spew.Config.Indent = "\t"
	nasStr := spew.Sdump(nasMsg)
	naslog.Tracef("Get NAS Message:\n %+v", nasStr)

	switch nasMsg.GmmMessage.GetMessageType() {
	case nas.MsgTypeRegistrationAccept:
		handler.HandleRegistrationAccept(n3ueSelf, nasMsg)
	case nas.MsgTypeDLNASTransport:
		handler.HandleDLNASTransport(n3ueSelf, nasMsg)
	}
}

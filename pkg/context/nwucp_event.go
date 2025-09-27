package context

import (
	"fmt"

	"github.com/free5gc/nas"
)

type NwucpEvt interface {
	GetEventType() NwucpEvtType
}

type NwucpEvtType int

const (
	StartNwucpConn NwucpEvtType = iota
	HandleRegistrationAccept
	HandleDLNASTransport
	StartPduSessionEstablishment
	SendDeregistration
)

var nwucpEvtTypeStr = []string{
	StartNwucpConn:               "StartNwucpConn",
	HandleRegistrationAccept:     "HandleRegistrationAccept",
	HandleDLNASTransport:         "HandleDLNASTransport",
	StartPduSessionEstablishment: "StartPduSessionEstablishment",
	SendDeregistration:           "SendDeregistration",
}

func (e NwucpEvtType) String() string {
	if int(e) < len(nwucpEvtTypeStr) {
		return nwucpEvtTypeStr[e]
	}
	return fmt.Sprintf("Unknown NwucpEvtType: %d", e)
}

type StartNwucpConnEvt struct{}

func (evt *StartNwucpConnEvt) GetEventType() NwucpEvtType {
	return StartNwucpConn
}

func NewStartNwucpConnEvt() *StartNwucpConnEvt {
	return &StartNwucpConnEvt{}
}

type HandleRegistrationAcceptEvt struct {
	NasMsg *nas.Message
}

func (evt *HandleRegistrationAcceptEvt) GetEventType() NwucpEvtType {
	return HandleRegistrationAccept
}

func NewHandleRegistrationAcceptEvt(nasMsg *nas.Message) *HandleRegistrationAcceptEvt {
	return &HandleRegistrationAcceptEvt{NasMsg: nasMsg}
}

type HandleDLNASTransportEvt struct {
	NasMsg *nas.Message
}

func (evt *HandleDLNASTransportEvt) GetEventType() NwucpEvtType {
	return HandleDLNASTransport
}

func NewHandleDLNASTransportEvt(nasMsg *nas.Message) *HandleDLNASTransportEvt {
	return &HandleDLNASTransportEvt{NasMsg: nasMsg}
}

type StartPduSessionEstablishmentEvt struct{}

func (evt *StartPduSessionEstablishmentEvt) GetEventType() NwucpEvtType {
	return StartPduSessionEstablishment
}

func NewStartPduSessionEstablishmentEvt() *StartPduSessionEstablishmentEvt {
	return &StartPduSessionEstablishmentEvt{}
}

type SendDeregistrationEvt struct{}

func (evt *SendDeregistrationEvt) GetEventType() NwucpEvtType {
	return SendDeregistration
}

func NewSendDeregistrationEvt() *SendDeregistrationEvt {
	return &SendDeregistrationEvt{}
}

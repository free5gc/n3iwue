package context

import (
	ike_message "github.com/free5gc/ike/message"
)

type IkeEventType int64

// IKE Event type
const (
	// For IKE message
	HandleIkeMsgSaInit IkeEventType = iota
	HandleIkeMsgAuth
	HandleIkeMsgCreateChildSa
	HandleIkeMsgInformational

	// For Procedure event
	StartIkeSaEstablishment

	// For retransmit event
	IkeRetransTimeout

	// For DPD event
	DpdCheck
)

var ikeEvtTypeStr = []string{
	// For IKE Message Event
	HandleIkeMsgSaInit:        "HandleIkeMsgSaInit",
	HandleIkeMsgAuth:          "HandleIkeMsgAuth",
	HandleIkeMsgCreateChildSa: "HandleIkeMsgCreateChildSa",
	HandleIkeMsgInformational: "HandleIkeMsgInformational",

	// For Procedure event
	StartIkeSaEstablishment: "StartIkeSaEstablishment",

	// For retransmit event
	IkeRetransTimeout: "IkeRetransTimeout",

	// For DPD event
	DpdCheck: "DpdCheck",
}

func (e IkeEventType) String() string {
	if int(e) < len(ikeEvtTypeStr) {
		return ikeEvtTypeStr[e]
	}
	return "UNKNOWN"
}

type IkeEvt interface {
	Type() IkeEventType
}

// For IKE Message Event

type HandleIkeMsgSaInitEvt struct {
	UdpConnInfo *UDPSocketInfo
	IkeMsg      *ike_message.IKEMessage
	Packet      []byte
}

func (evt *HandleIkeMsgSaInitEvt) Type() IkeEventType {
	return HandleIkeMsgSaInit
}

func NewHandleIkeMsgSaInitEvt(
	udpConnInfo *UDPSocketInfo,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) *HandleIkeMsgSaInitEvt {
	return &HandleIkeMsgSaInitEvt{
		UdpConnInfo: udpConnInfo,
		IkeMsg:      ikeMsg,
		Packet:      packet,
	}
}

type HandleIkeMsgAuthEvt struct {
	UdpConnInfo *UDPSocketInfo
	IkeMsg      *ike_message.IKEMessage
	Packet      []byte
}

func (evt *HandleIkeMsgAuthEvt) Type() IkeEventType {
	return HandleIkeMsgAuth
}

func NewHandleIkeMsgAuthEvt(
	udpConnInfo *UDPSocketInfo,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) *HandleIkeMsgAuthEvt {
	return &HandleIkeMsgAuthEvt{
		UdpConnInfo: udpConnInfo,
		IkeMsg:      ikeMsg,
		Packet:      packet,
	}
}

type HandleIkeMsgCreateChildSaEvt struct {
	UdpConnInfo *UDPSocketInfo
	IkeMsg      *ike_message.IKEMessage
	Packet      []byte
}

func (evt *HandleIkeMsgCreateChildSaEvt) Type() IkeEventType {
	return HandleIkeMsgCreateChildSa
}

func NewHandleIkeMsgCreateChildSaEvt(
	udpConnInfo *UDPSocketInfo,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) *HandleIkeMsgCreateChildSaEvt {
	return &HandleIkeMsgCreateChildSaEvt{
		UdpConnInfo: udpConnInfo,
		IkeMsg:      ikeMsg,
		Packet:      packet,
	}
}

type HandleIkeMsgInformationalEvt struct {
	UdpConnInfo *UDPSocketInfo
	IkeMsg      *ike_message.IKEMessage
	Packet      []byte
}

func (evt *HandleIkeMsgInformationalEvt) Type() IkeEventType {
	return HandleIkeMsgInformational
}

func NewHandleIkeMsgInformationalEvt(
	udpConnInfo *UDPSocketInfo,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) *HandleIkeMsgInformationalEvt {
	return &HandleIkeMsgInformationalEvt{
		UdpConnInfo: udpConnInfo,
		IkeMsg:      ikeMsg,
		Packet:      packet,
	}
}

// For Procedure event

type StartIkeSaEstablishmentEvt struct{}

func (evt *StartIkeSaEstablishmentEvt) Type() IkeEventType {
	return StartIkeSaEstablishment
}

func NewStartIkeSaEstablishmentEvt() *StartIkeSaEstablishmentEvt {
	return &StartIkeSaEstablishmentEvt{}
}

// For Retransmit event

type IkeRetransTimeoutEvt struct{}

func (evt *IkeRetransTimeoutEvt) Type() IkeEventType {
	return IkeRetransTimeout
}

func NewIkeRetransTimeoutEvt() *IkeRetransTimeoutEvt {
	return &IkeRetransTimeoutEvt{}
}

// For DPD event

type DpdCheckEvt struct{}

func (evt *DpdCheckEvt) Type() IkeEventType {
	return DpdCheck
}

func NewDpdCheckEvt() *DpdCheckEvt {
	return &DpdCheckEvt{}
}

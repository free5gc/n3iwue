package context

import (
	"math/big"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike/message"
	"github.com/free5gc/n3iwue/internal/qos"
	"github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas/nasType"
)

var n3ueContext = N3UE{}

// N3UE state
const (
	Registration_IKEINIT = iota
	Registration_IKEAUTH
	Registration_CreateNWUCP
	PduSessionEst
	PduSessionCreated
)

type N3UE struct {
	N3IWFUe              *context.N3IWFIkeUe
	N3IWFRanUe           *context.N3IWFRanUe
	N3ueInfo             factory.N3UEInfo
	N3iwfInfo            factory.N3IWFInfo
	RanUeContext         *security.RanUeContext
	MobileIdentity5GS    nasType.MobileIdentity5GS
	IkeInitiatorSPI      uint64
	Secert               *big.Int
	Factor               *big.Int
	Proposal             *message.Proposal
	LocalNonce           []byte
	SecurityAssociation  *message.SecurityAssociation
	AttributeType        uint16
	KeyLength            uint16
	UESecurityCapability *nasType.UESecurityCapability
	UEInnerAddr          *net.IPNet
	N3iwfNASAddr         *net.TCPAddr
	PduSessionCount      uint8
	CreatedIface         []*netlink.Link
	CurrentState         chan uint8
	Kn3iwf               []uint8

	// Temporary data , used to create GreTunnel
	TemporaryXfrmiName string
	TemporaryUPIPAddr  net.IP
	TemporaryQosInfo   *qos.PDUQoSInfo
}

func N3UESelf() *N3UE {
	return &n3ueContext
}

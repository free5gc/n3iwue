package context

import (
	"fmt"
	"math/big"
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/n3iwue/internal/qos"
	"github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
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
	N3IWFUe              *N3IWFIkeUe
	N3IWFRanUe           *N3IWFRanUe
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
	GUTI                 *nasType.GUTI5G
	IKEConnection        map[int]*UDPSocketInfo

	// Temporary data , used to create GreTunnel
	TemporaryXfrmiName string
	TemporaryUPIPAddr  net.IP
	TemporaryQosInfo   *qos.PDUQoSInfo
}

func N3UESelf() *N3UE {
	return &n3ueContext
}

type N3IWFIkeUe struct {
	/* UE identity */
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr *net.IPAddr // Used to send UP packets to UE

	/* IKE Security Association */
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key

	/* Temporary Mapping of two SPIs */
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key

	/* Security */
	Kn3iwf []uint8 // 32 bytes (256 bits), value is from NGAP IE "Security Key"

	/* NAS IKE Connection */
	IKEConnection *UDPSocketInfo

	// Length of PDU Session List
	PduSessionListLen int
}

type N3IWFRanUe struct {
	/* UE identity */
	RanUeNgapId  int64
	AmfUeNgapId  int64
	IPAddrv4     string
	IPAddrv6     string
	PortNumber   int32
	MaskedIMEISV *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti         string

	// UE send CREATE_CHILD_SA response
	TemporaryCachedNASMessage []byte

	/* NAS TCP Connection Established */
	IsNASTCPConnEstablished         bool
	IsNASTCPConnEstablishedComplete bool

	/* NAS TCP Connection */
	TCPConnection net.Conn

	/* Others */
	Guami                            *ngapType.GUAMI
	IndexToRfsp                      int64
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	AllowedNssai                     *ngapType.AllowedNSSAI
	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                int32
	RRCEstablishmentCause            int16
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes
}

type IKESecurityAssociation struct {
	*ike_security.IKESAKey
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Authentication data
	ResponderSignedOctets []byte
	InitiatorSignedOctets []byte

	// Used for key generating
	NonceInitiator []byte
	NonceResponder []byte

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	IKEAuthResponseSA *message.SecurityAssociation

	// NAT detection
	UEIsBehindNAT    bool
	N3IWFIsBehindNAT bool
}

func (ikeSA *IKESecurityAssociation) String() string {
	return "====== IKE Security Association Info =====" +
		"\nInitiator's SPI: " + fmt.Sprintf("%016x", ikeSA.LocalSPI) +
		"\nResponder's SPI: " + fmt.Sprintf("%016x", ikeSA.RemoteSPI) +
		"\nIKESAKey: " + ikeSA.IKESAKey.String()
}

type ChildSecurityAssociation struct {
	*ike_security.ChildSAKey

	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	XfrmStateList  []netlink.XfrmState
	XfrmPolicyList []netlink.XfrmPolicy

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Encapsulate
	EnableEncapsulate bool
	N3IWFPort         int
	NATPort           int

	// Used for key generating
	NonceInitiator []byte
	NonceResponder []byte
}

type UDPSocketInfo struct {
	Conn      *net.UDPConn
	N3IWFAddr *net.UDPAddr
	UEAddr    *net.UDPAddr
}

// When N3IWF send CREATE_CHILD_SA request to N3UE, the inbound SPI of childSA will be only stored first until
// receive response and call CompleteChildSAWithProposal to fill the all data of childSA
func (ikeUe *N3IWFIkeUe) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := new(ChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	// Map Exchange Message ID and Child SA data until get paired response
	ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ikeUe *N3IWFIkeUe) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *message.SecurityAssociation,
) (*ChildSecurityAssociation, error) {
	childSA, ok := ikeUe.TemporaryExchangeMsgIDChildSAMapping[msgID]

	if !ok {
		return nil, errors.Errorf("CompleteChildSA(): There's not a half child SA created by the exchange with message ID %d.", msgID)
	}

	// Remove mapping of exchange msg ID and child SA
	delete(ikeUe.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, errors.Errorf("CompleteChildSA(): chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, errors.Errorf("CompleteChildSA(): No proposal")
	}

	childSA.OutboundSPI = outboundSPI

	var err error
	childSA.ChildSAKey, err = ike_security.NewChildSAKeyByProposal(chosenSecurityAssociation.Proposals[0])
	if err != nil {
		return nil, errors.Wrapf(err, "CompleteChildSA")
	}

	// Record to UE context with inbound SPI as key
	ikeUe.N3IWFChildSecurityAssociation[childSA.InboundSPI] = childSA

	return childSA, nil
}

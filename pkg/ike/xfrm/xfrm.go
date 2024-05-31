package xfrm

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	n3iwf_context "github.com/free5gc/n3iwf/pkg/context"
	"github.com/free5gc/n3iwf/pkg/ike/xfrm"
	context "github.com/free5gc/n3iwue/pkg/context"
)

// Log

func init() {
}

func ApplyXFRMRule(
	ue_is_initiator bool,
	ifId uint32,
	childSecurityAssociation *n3iwf_context.ChildSecurityAssociation,
) error {
	// Build XFRM information data structure for incoming traffic.

	// Mark
	// mark := &netlink.XfrmMark{
	// 	Value: ifMark, // n3ueInfo.XfrmMark,
	// }

	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ue_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: xfrm.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: xfrm.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: xfrm.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: xfrm.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Ifid = int(ifId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.ESN

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	if childSecurityAssociation.SelectedIPProtocol == 0 {
		return errors.New("Protocol == 0")
	}

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(ifId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	// Direction: UE -> N3IWF
	// State
	if ue_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	return nil
}

func SetupIPsecXfrmi(
	xfrmIfaceName, parentIfaceName string,
	xfrmIfaceId uint32,
	xfrmIfaceAddr *net.IPNet,
) (netlink.Link, error) {
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	link := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         1478,
			Name:        xfrmIfaceName,
			ParentIndex: parent.Attrs().Index,
		},
		Ifid: xfrmIfaceId,
	}

	// ip link add
	if err = netlink.LinkAdd(link); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		return nil, err
	}

	// ip addr add
	linkIPSecAddr := &netlink.Addr{
		IPNet: xfrmIfaceAddr,
	}

	if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil {
		return nil, err
	}

	// ip link set ... up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	n3ueSelf := context.N3UESelf()
	n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &xfrmi)

	return xfrmi, nil
}

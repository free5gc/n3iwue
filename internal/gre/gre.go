package gre

import (
	"fmt"
	"net"
	"strconv"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/logger"
	Qos "github.com/free5gc/n3iwue/internal/qos"
	"github.com/free5gc/n3iwue/pkg/context"
)

func SetupGreTunnels(
	greIfaceName, parentIfaceName string,
	ueTunnelAddr, n3iwfTunnelAddr, pduAddr net.IP,
	qoSInfo *Qos.PDUQoSInfo,
) (map[uint8]*netlink.Link, error) {
	parent, err := netlink.LinkByName(parentIfaceName)
	if err != nil {
		return nil, fmt.Errorf("netlink.LinkByName: [%+v] %+v", parentIfaceName, err)
	}

	if qoSInfo == nil {
		linkGre, err := SetupGreTunnel(greIfaceName, parent, ueTunnelAddr, n3iwfTunnelAddr, pduAddr, 0)
		return map[uint8]*netlink.Link{
			1: &linkGre,
		}, err
	}

	n3ueSelf := context.N3UESelf()
	netlinks := map[uint8]*netlink.Link{}

	for _, qfi := range qoSInfo.QfiList {
		linkGRE, err := SetupGreTunnel(greIfaceName, parent, ueTunnelAddr, n3iwfTunnelAddr, pduAddr, qfi)
		if err != nil {
			return nil, fmt.Errorf("SetupGreTunnel(): [%s]", err)
		}

		n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &linkGRE)
		netlinks[qfi] = &linkGRE
	}
	return netlinks, nil
}

func SetupGreTunnel(
	greIfaceName string,
	parent netlink.Link,
	ueTunnelAddr, n3iwfTunnelAddr, pduAddr net.IP,
	qfi uint8,
) (netlink.Link, error) {
	var (
		greKeyField uint32
		err         error
	)

	greKeyField = (uint32(qfi) & 0x3F) << 24
	newGreIfaceName := greIfaceName + "-" + strconv.Itoa(int(qfi))

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: newGreIfaceName,
			MTU:  1438, // remain for endpoint IP header(most 40 bytes if IPv6) and ESP header (22 bytes)
		},
		Link:   uint32(parent.Attrs().Index), // PHYS_DEV in iproute2; IFLA_GRE_LINK in linux kernel
		Local:  ueTunnelAddr,
		Remote: n3iwfTunnelAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
	}
	logger.AppLog.Infof("New GRE Tunnel, Key Field: [0x%x], IfaceName: [%+v]", greKeyField, newGreIfaceName)

	if err = netlink.LinkAdd(newGRETunnel); err != nil {
		return nil, fmt.Errorf("netlink.LinkAdd: [%+v] %+v", newGreIfaceName, err)
	}

	// Get link info
	linkGRE, err := netlink.LinkByName(newGreIfaceName)
	if err != nil {
		return nil, fmt.Errorf("no link named: [%s]", newGreIfaceName)
	}

	linkGREAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   pduAddr,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
		return nil, err
	}

	// Set GRE interface up
	if err := netlink.LinkSetUp(linkGRE); err != nil {
		return nil, err
	}

	return linkGRE, nil
}

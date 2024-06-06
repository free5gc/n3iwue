package gre

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/logger"
	Qos "github.com/free5gc/n3iwue/internal/qos"
	"github.com/free5gc/n3iwue/pkg/context"
)

func SetupGreTunnel(greIfaceName, parentIfaceName string, ueTunnelAddr, n3iwfTunnelAddr,
	pduAddr net.IP, qoSInfo *Qos.PDUQoSInfo,
) (netlink.Link, error) {
	var (
		parent      netlink.Link
		greKeyField uint32
		err         error
	)

	if qoSInfo != nil {
		greKeyField |= (uint32(qoSInfo.MaxQFI()) & 0x3F) << 24
	}

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: greIfaceName,
			MTU:  1438, // remain for endpoint IP header(most 40 bytes if IPv6) and ESP header (22 bytes)
		},
		Link:   uint32(parent.Attrs().Index), // PHYS_DEV in iproute2; IFLA_GRE_LINK in linux kernel
		Local:  ueTunnelAddr,
		Remote: n3iwfTunnelAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
	}

	logger.AppLog.Infof("GRE Key Field: 0x%x", greKeyField)

	if err = netlink.LinkAdd(newGRETunnel); err != nil {
		return nil, err
	}

	// Get link info
	linkGRE, err := netlink.LinkByName(greIfaceName)
	if err != nil {
		return nil, fmt.Errorf("No link named %s", greIfaceName)
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

	n3ueSelf := context.N3UESelf()
	n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &parent)

	return linkGRE, nil
}

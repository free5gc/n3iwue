package vrf

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/pkg/context"
)

func CreateOrGetVRF(vrfName string, tableID int) (netlink.Link, error) {
	// Try to get VRF
	link, err := netlink.LinkByName(vrfName)
	if err == nil {
		// Found, check if it is a VRF
		if vrf, ok := link.(*netlink.Vrf); ok {
			if vrf.Table == uint32(tableID) {
				return vrf, nil // VRF exists and is correct
			}
			return nil, fmt.Errorf("VRF %s exists but Table ID mismatch (need %d, actual %d)", vrfName, tableID, vrf.Table)
		}
		return nil, fmt.Errorf("Device %s exists but is not a VRF", vrfName)
	}

	// Create VRF (l3mdev) device
	vrfLink := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: vrfName},
		Table:     uint32(tableID),
	}

	if err := netlink.LinkAdd(vrfLink); err != nil {
		return nil, fmt.Errorf("netlink.LinkAdd VRF %s failed: %v", vrfName, err)
	}

	// Enable VRF device
	if err := netlink.LinkSetUp(vrfLink); err != nil {
		return nil, fmt.Errorf("netlink.LinkSetUp VRF %s failed: %v", vrfName, err)
	}

	// Add to CreatedIface for auto cleanup
	n3ueSelf := context.N3UESelf()
	var createdLink netlink.Link = vrfLink
	n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &createdLink)

	return vrfLink, nil
}

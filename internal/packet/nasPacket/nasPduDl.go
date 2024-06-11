package nasPacket

import (
	"fmt"
	"net"

	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	n3ue_security "github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func DecodePDUSessionEstablishmentAccept(
	ue *n3ue_security.RanUeContext,
	length int,
	buffer []byte,
) (*nas.Message, error) {
	if length == 0 {
		return nil, fmt.Errorf("Empty buffer")
	}

	nasEnv, n := ngapPacket.DecapNasPduFromEnvelope(buffer[:length])
	nasMsg, err := n3ue_security.NASDecode(
		ue,
		nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		nasEnv[:n],
	)
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	// Retrieve GSM from GmmMessage.DLNASTransport.PayloadContainer and decode
	payloadContainer := nasMsg.GmmMessage.DLNASTransport.PayloadContainer
	byteArray := payloadContainer.Buffer[:payloadContainer.Len]
	if err := nasMsg.GsmMessageDecode(&byteArray); err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	return nasMsg, nil
}

func GetPDUAddress(accept *nasMessage.PDUSessionEstablishmentAccept) (net.IP, error) {
	if addr := accept.PDUAddress; addr != nil {
		PDUSessionTypeValue := addr.GetPDUSessionTypeValue()
		if PDUSessionTypeValue == nasMessage.PDUSessionTypeIPv4 {
			ip := net.IP(addr.Octet[1:5])
			return ip, nil
		}
	}

	return nil, fmt.Errorf("PDUAddress is nil")
}

func GetQFItoTargetMap(
	accept *nasMessage.PDUSessionEstablishmentAccept,
) (
	map[uint8]nasType.PacketFilterIPv4RemoteAddress, error,
) {
	qfiMap := map[uint8]nasType.PacketFilterIPv4RemoteAddress{}

	var rules nasType.QoSRules
	if err := rules.UnmarshalBinary(accept.AuthorizedQosRules.Buffer); err != nil {
		return nil, fmt.Errorf("rules UnmarshalBinary: %+v", err)
	}

	for _, rule := range rules {
		for _, pfList := range rule.PacketFilterList {
			for _, component := range pfList.Components {
				if component.Type() == nasType.PacketFilterComponentTypeIPv4RemoteAddress {
					var b []byte
					var err error
					if b, err = component.MarshalBinary(); err != nil {
						return nil, fmt.Errorf("MarshalBinary err: %+v", err)
					}
					var addr nasType.PacketFilterIPv4RemoteAddress
					if err = addr.UnmarshalBinary(b); err != nil {
						return nil, fmt.Errorf("UnmarshalBinary err: %+v", err)
					}
					qfiMap[rule.QFI] = addr
				}
			}
		}
	}
	return qfiMap, nil
}

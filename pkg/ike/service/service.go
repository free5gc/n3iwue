package service

import (
	"bytes"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/n3iwue/internal/logger"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/handler"
)

var ikeLog *logrus.Entry

const (
	DEFAULT_IKE_PORT  = 500
	DEFAULT_NATT_PORT = 4500
)

type EspHandler func(srcIP, dstIP *net.UDPAddr, espPkt []byte) error

func init() {
	// init logger
	ikeLog = logger.IKELog
}

func Run() error {
	ip := factory.N3ueInfo.IPSecIfaceAddr
	ikeAddrPort, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, DEFAULT_IKE_PORT))
	if err != nil {
		ikeLog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.Wrapf(err, "ResolveUDPAddr (%s:500)", ip)
	}

	nattAddrPort, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, DEFAULT_NATT_PORT))
	if err != nil {
		ikeLog.Errorf("Resolve UDP address failed: %+v", err)
		return errors.Wrapf(err, "ResolveUDPAddr (%s:4500)", ip)
	}

	// Listen and serve
	errChan := make(chan error)

	go listenAndServe(ikeAddrPort, errChan)
	if err, ok := <-errChan; ok {
		ikeLog.Errorln(err)
		return errors.New("IKE service 500 port run failed")
	}

	errChan = make(chan error)

	go listenAndServe(nattAddrPort, errChan)
	if err, ok := <-errChan; ok {
		ikeLog.Errorln(err)
		return errors.New("IKE service 4500 port run failed")
	}

	return nil
}

func listenAndServe(localAddr *net.UDPAddr, errChan chan<- error) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	udpListener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		ikeLog.Errorf("Listen UDP failed: %+v", err)
		errChan <- errors.New("listenAndServe failed")
		return
	}

	n3ueContext := context.N3UESelf()
	port := localAddr.Port

	n3iwfUDPAddr, err := net.ResolveUDPAddr("udp", factory.N3iwfInfo.IPSecIfaceAddr+":"+strconv.Itoa(port))
	if err != nil {
		ikeLog.Errorf("Resolve UDP address %s fail: %+v", factory.N3iwfInfo.IPSecIfaceAddr+":"+strconv.Itoa(port), err)
		return
	}

	n3ueUDPAddr, err := net.ResolveUDPAddr("udp", factory.N3ueInfo.IPSecIfaceAddr+":"+strconv.Itoa(port))
	if err != nil {
		ikeLog.Errorf("Resolve UDP address %s fail: %+v", factory.N3ueInfo.IPSecIfaceAddr+":"+strconv.Itoa(port), err)
		return
	}

	n3ueContext.IKEConnection[port] = &context.UDPSocketInfo{
		Conn:      udpListener,
		N3IWFAddr: n3iwfUDPAddr,
		UEAddr:    n3ueUDPAddr,
	}

	close(errChan)

	data := make([]byte, 65535)

	for {
		n, remoteAddr, err := udpListener.ReadFromUDP(data)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				ikeLog.Errorf("ReadFromUDP failed: %+v", err)
				return
			}
			ikeLog.Errorf("ReadFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		if port == DEFAULT_NATT_PORT {
			forwardData, err = handleNattMsg(forwardData, remoteAddr, localAddr, handleESPPacket)
			if err != nil {
				ikeLog.Errorf("Handle NATT msg: %v", err)
				continue
			}
			if forwardData == nil {
				continue
			}
		}

		ikeMsg, err := checkMessage(forwardData, udpListener, localAddr, remoteAddr)
		if err != nil {
			ikeLog.Errorf("checkMessage failed: %+v", err)
			continue
		}

		go handler.Dispatch(udpListener, localAddr, remoteAddr, ikeMsg)
	}
}

func checkMessage(msg []byte, udpConn *net.UDPConn,
	localAddr, remoteAddr *net.UDPAddr) (
	*ike_message.IKEMessage, error,
) {
	var ikeHeader *ike_message.IKEHeader
	var ikeMessage *ike_message.IKEMessage
	var err error

	// parse IKE header and setup IKE context
	ikeHeader, err = ike_message.ParseHeader(msg)
	if err != nil {
		return nil, errors.Wrapf(err, "IKE msg decode header")
	}

	// check major version
	if ikeHeader.MajorVersion > 2 {
		// send INFORMATIONAL type message with INVALID_MAJOR_VERSION Notify payload
		// For response or needed data
		payload := new(ike_message.IKEPayloadContainer)
		payload.BuildNotification(ike_message.TypeNone,
			ike_message.INVALID_MAJOR_VERSION, nil, nil)
		responseIKEMessage := ike_message.NewMessage(ikeHeader.InitiatorSPI, ikeHeader.ResponderSPI,
			ike_message.INFORMATIONAL, true, true, ikeHeader.MessageID, *payload)
		err = handler.SendIKEMessageToN3IWF(udpConn, localAddr, remoteAddr, responseIKEMessage, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "Received an IKE message with higher major version")
		}
		return nil, errors.Errorf("Received an IKE message with higher major version")
	}

	if ikeHeader.ExchangeType == ike_message.IKE_SA_INIT {
		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			nil, ike_message.Role_Initiator)
		if err != nil {
			return nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	} else {
		n3ueCtx := context.N3UESelf()

		if ikeHeader.InitiatorSPI != n3ueCtx.IkeInitiatorSPI {
			return nil, errors.Errorf("Drop this IKE message due to wrong InitiatorSPI: 0x%016x",
				ikeHeader.InitiatorSPI)
		}
		ikeMessage, err = ike.DecodeDecrypt(msg, ikeHeader,
			n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation.IKESAKey,
			ike_message.Role_Initiator)
		if err != nil {
			return nil, errors.Wrapf(err, "Decrypt IkeMsg error")
		}
	}

	return ikeMessage, nil
}

func handleNattMsg(
	msgBuf []byte,
	rAddr, lAddr *net.UDPAddr,
	espHandler EspHandler,
) ([]byte, error) {
	if len(msgBuf) == 1 && msgBuf[0] == 0xff {
		// skip NAT-T Keepalive
		return nil, nil
	}

	nonEspMarker := []byte{0, 0, 0, 0} // Non-ESP Marker
	nonEspMarkerLen := len(nonEspMarker)
	if len(msgBuf) < nonEspMarkerLen {
		return nil, errors.Errorf("Received msg is too short")
	}
	if !bytes.Equal(msgBuf[:nonEspMarkerLen], nonEspMarker) {
		// ESP packet
		if espHandler != nil {
			err := espHandler(rAddr, lAddr, msgBuf)
			if err != nil {
				return nil, errors.Wrapf(err, "Handle ESP")
			}
		}
		return nil, nil
	}

	// IKE message: skip Non-ESP Marker
	msgBuf = msgBuf[nonEspMarkerLen:]
	return msgBuf, nil
}

func constructPacketWithESP(srcIP, dstIP *net.UDPAddr, espPacket []byte) ([]byte, error) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP.IP,
		DstIP:    dstIP.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolESP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer,
		options,
		ipLayer,
		gopacket.Payload(espPacket),
	)
	if err != nil {
		return nil, errors.Errorf("Error serializing layers: %v", err)
	}

	packetData := buffer.Bytes()
	return packetData, nil
}

func handleESPPacket(srcIP, dstIP *net.UDPAddr, espPacket []byte) error {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle ESPPacket")

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return errors.Errorf("socket error: %v", err)
	}

	defer func() {
		if err = syscall.Close(fd); err != nil {
			ikeLog.Errorf("Close fd error : %v", err)
		}
	}()

	ipPacket, err := constructPacketWithESP(srcIP, dstIP, espPacket)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{
		Addr: [4]byte(dstIP.IP),
		Port: dstIP.Port,
	}

	err = syscall.Sendto(fd, ipPacket, 0, &addr)
	if err != nil {
		return errors.Errorf("sendto error: %v", err)
	}

	return nil
}

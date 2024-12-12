package handler

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	"github.com/free5gc/n3iwue/internal/qos"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/xfrm"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/util/ueauth"
)

var (
	n3ueSelf = context.N3UESelf()
	ikeLog   *logrus.Entry
	nasLog   *logrus.Entry
)

func init() {
	ikeLog = logger.IKELog
	nasLog = logger.NASLog
}

// IKE_AUTH state
const (
	IKEAUTH_Request = iota
	EAP_RegistrationRequest
	EAP_Authentication
	EAP_NASSecurityComplete
	IKEAUTH_Authentication
)

func HandleIKESAINIT(
	udpConn *net.UDPConn,
	ueAddr, n3iwfAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
) {
	ikeLog.Infoln("Handle IKESA INIT")

	var sharedKeyExchangeData []byte
	var remoteNonce []byte
	var notifications []*ike_message.Notification
	// For NAT-T
	var ueIsBehindNAT, n3iwfIsBehindNAT bool
	var err error

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			ikeLog.Info("Get SA payload")
		case ike_message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*ike_message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(
				big.Int,
			).Exp(remotePublicKeyExchangeValueBig, n3ueSelf.Secert, n3ueSelf.Factor).
				Bytes()
		case ike_message.TypeNiNr:
			remoteNonce = ikePayload.(*ike_message.Nonce).NonceData
		case ike_message.TypeN:
			notifications = append(notifications, ikePayload.(*ike_message.Notification))
		}
	}

	if len(notifications) != 0 {
		ueIsBehindNAT, n3iwfIsBehindNAT, err = HandleNATDetect(
			message.InitiatorSPI, message.ResponderSPI,
			notifications, ueAddr, n3iwfAddr)
		if err != nil {
			ikeLog.Errorf("Handle IKE_SA_INIT: %v", err)
			return
		}
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:           n3ueSelf.IkeInitiatorSPI,
		RemoteSPI:          message.ResponderSPI,
		InitiatorMessageID: 0,
		ResponderMessageID: 0,
		IKESAKey: &ike_security.IKESAKey{
			EncrInfo:  encr.DecodeTransform(n3ueSelf.Proposal.EncryptionAlgorithm[0]),
			IntegInfo: integ.DecodeTransform(n3ueSelf.Proposal.IntegrityAlgorithm[0]),
			PrfInfo:   prf.DecodeTransform(n3ueSelf.Proposal.PseudorandomFunction[0]),
			DhInfo:    dh.DecodeTransform(n3ueSelf.Proposal.DiffieHellmanGroup[0]),
		},
		NonceInitiator: n3ueSelf.LocalNonce,
		NonceResponder: remoteNonce,
		ResponderSignedOctets: append(n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation.
			ResponderSignedOctets, remoteNonce...),
		UEIsBehindNAT:    ueIsBehindNAT,
		N3IWFIsBehindNAT: n3iwfIsBehindNAT,
	}
	ConcatenatedNonce := append(ikeSecurityAssociation.NonceInitiator, ikeSecurityAssociation.NonceResponder...)

	err = ikeSecurityAssociation.IKESAKey.GenerateKeyForIKESA(ConcatenatedNonce,
		sharedKeyExchangeData, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)
	if err != nil {
		ikeLog.Errorf("Generate key for IKE SA failed: %+v", err)
		return
	}

	ikeLog.Tracef("%v", ikeSecurityAssociation.String())
	n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation
	n3ueSelf.CurrentState <- uint8(context.Registration_IKEAUTH)
}

func HandleIKEAUTH(
	udpConn *net.UDPConn,
	ueAddr, n3iwfAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
) {
	ikeLog.Infoln("Handle IKE AUTH")

	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	ue := n3ueSelf.RanUeContext

	var ikePayload ike_message.IKEPayloadContainer

	// var eapIdentifier uint8
	var eapReq *ike_message.EAP

	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var responseConfiguration *ike_message.Configuration
	var err error
	var ok bool
	n3ueSelf.N3iwfNASAddr = new(net.TCPAddr)

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeIDr:
			ikeLog.Info("Get IDr")
		case ike_message.TypeAUTH:
			ikeLog.Info("Get AUTH")
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeCERT:
			ikeLog.Info("Get CERT")
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				n3ueSelf.N3iwfNASAddr.IP = net.IPv4(
					notification.NotificationData[0],
					notification.NotificationData[1],
					notification.NotificationData[2],
					notification.NotificationData[3],
				)
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				n3ueSelf.N3iwfNASAddr.Port = int(
					binary.BigEndian.Uint16(notification.NotificationData),
				)
			}
		case ike_message.TypeCP:
			responseConfiguration = ikePayload.(*ike_message.Configuration)
			if responseConfiguration.ConfigurationType == ike_message.CFG_REPLY {
				n3ueSelf.UEInnerAddr = new(net.IPNet)
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == ike_message.INTERNAL_IP4_ADDRESS {
						n3ueSelf.UEInnerAddr.IP = configAttr.Value
					}
					if configAttr.Type == ike_message.INTERNAL_IP4_NETMASK {
						n3ueSelf.UEInnerAddr.Mask = configAttr.Value
					}
				}
			}
		case ike_message.TypeEAP:
			ikeLog.Info("Get EAP")
			eapReq = ikePayload.(*ike_message.EAP)
		}
	}

	switch ikeSecurityAssociation.State {
	case IKEAUTH_Request:
		eapIdentifier := eapReq.Identifier

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 2)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// AN Parameters
		anParameters := BuildEAP5GANParameters()
		anParametersLength := make([]byte, 2)
		binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
		eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
		eapVendorTypeData = append(eapVendorTypeData, anParameters...)

		// NAS
		n3ueSelf.UESecurityCapability = n3ueSelf.RanUeContext.GetUESecurityCapability()
		registrationRequest := nasPacket.GetRegistrationRequest(
			nasMessage.RegistrationType5GSInitialRegistration,
			n3ueSelf.MobileIdentity5GS,
			nil,
			n3ueSelf.UESecurityCapability,
			nil,
			nil,
			nil,
		)

		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

		eap := ikePayload.BuildEAP(ike_message.EAPCodeResponse, eapIdentifier)
		eap.EAPTypeData.BuildEAPExpanded(
			ike_message.VendorID3GPP,
			ike_message.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = SendIKEMessageToN3IWF(
			n3ueSelf.N3IWFUe.IKEConnection.Conn,
			n3ueSelf.N3IWFUe.IKEConnection.UEAddr,
			n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr,
			ikeMessage,
			ikeSecurityAssociation.IKESAKey,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() IKEAUTH_Request: %v", err)
			return
		}

		// TS 33.102
		// Sync the SQN for security in config
		if err = factory.SyncConfigSQN(1); err != nil {
			ikeLog.Errorf("syncConfigSQN: %+v", err)
			return
		}
		ikeSecurityAssociation.State++

	case EAP_RegistrationRequest:
		var eapExpanded *ike_message.EAPExpanded
		eapExpanded, ok = eapReq.EAPTypeData[0].(*ike_message.EAPExpanded)
		if !ok {
			ikeLog.Error("The EAP data is not an EAP expended.")
			return
		}

		var decodedNAS *nas.Message

		// Decode NAS - Authentication Request
		nasData := eapExpanded.VendorData[4:]
		decodedNAS = new(nas.Message)
		if err = decodedNAS.PlainNasDecode(&nasData); err != nil {
			ikeLog.Errorf("Decode plain NAS fail: %+v", err)
			return
		}

		// Calculate for RES*
		if decodedNAS == nil || decodedNAS.GmmMessage == nil {
			nasLog.Error("decodedNAS is nil")
			return
		}

		switch decodedNAS.GmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationRequest:
			nasLog.Info("Received Authentication Request")
		default:
			nasLog.Errorf("Received unexpected message type: %d",
				decodedNAS.GmmMessage.GetMessageType())
		}

		rand := decodedNAS.AuthenticationRequest.GetRANDValue()

		snn := n3ueSelf.N3ueInfo.GetSNN()
		nasLog.Infof("SNN: %+v", snn)
		resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], snn)

		nasLog.Infof("KnasEnc: %0x", ue.KnasEnc)
		nasLog.Infof("KnasInt: %0x", ue.KnasInt)
		nasLog.Infof("Kamf: %0x", ue.Kamf)
		nasLog.Infof("AnType: %s", ue.AnType)
		nasLog.Infof("SUPI: %s", ue.Supi)

		// send NAS Authentication Response
		pdu := nasPacket.GetAuthenticationResponse(resStat, "")

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 4)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eap := ikePayload.BuildEAP(ike_message.EAPCodeResponse, eapReq.Identifier)
		eap.EAPTypeData.BuildEAPExpanded(
			ike_message.VendorID3GPP,
			ike_message.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = SendIKEMessageToN3IWF(
			n3ueSelf.N3IWFUe.IKEConnection.Conn,
			n3ueSelf.N3IWFUe.IKEConnection.UEAddr,
			n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr,
			ikeMessage,
			ikeSecurityAssociation.IKESAKey,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_RegistrationRequest: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_Authentication:
		_, ok = eapReq.EAPTypeData[0].(*ike_message.EAPExpanded)
		if !ok {
			ikeLog.Error("The EAP data is not an EAP expended.")
			return
		}
		// nasData := eapExpanded.VendorData[4:]

		// Send NAS Security Mode Complete Msg
		registrationRequestWith5GMM := nasPacket.GetRegistrationRequest(
			nasMessage.RegistrationType5GSInitialRegistration,
			n3ueSelf.MobileIdentity5GS,
			nil,
			n3ueSelf.UESecurityCapability,
			ue.Get5GMMCapability(),
			nil,
			nil,
		)
		pdu := nasPacket.GetSecurityModeComplete(registrationRequestWith5GMM)
		if pdu, err = ngapPacket.EncodeNasPduWithSecurity(ue,
			pdu,
			nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext,
			true,
			true); err != nil {
			nasLog.Errorf("EncodeNasPduWithSecurity: %+v", err)
			return
		}

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 4)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eap := ikePayload.BuildEAP(ike_message.EAPCodeResponse, eapReq.Identifier)
		eap.EAPTypeData.BuildEAPExpanded(
			ike_message.VendorID3GPP,
			ike_message.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = SendIKEMessageToN3IWF(
			n3ueSelf.N3IWFUe.IKEConnection.Conn,
			n3ueSelf.N3IWFUe.IKEConnection.UEAddr,
			n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr,
			ikeMessage,
			ikeSecurityAssociation.IKESAKey,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_Authentication: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_NASSecurityComplete:
		if eapReq.Code != ike_message.EAPCodeSuccess {
			ikeLog.Error("Not Success")
			return
		}

		// IKE_AUTH - Authentication
		ikeSecurityAssociation.InitiatorMessageID++

		// Authentication
		// Derive Kn3iwf
		P0 := make([]byte, 4)
		binary.BigEndian.PutUint32(P0, ue.ULCount.Get()-1)
		L0 := ueauth.KDFLen(P0)
		P1 := []byte{security.AccessTypeNon3GPP}
		L1 := ueauth.KDFLen(P1)

		n3ueSelf.Kn3iwf, err = ueauth.GetKDFValue(
			ue.Kamf,
			ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION,
			P0,
			L0,
			P1,
			L1,
		)
		if err != nil {
			ikeLog.Error("GetKn3iwf error: :", err)
		}

		var idPayload ike_message.IKEPayloadContainer
		idPayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, []byte("UE"))
		idPayloadData, err := idPayload.Encode()
		if err != nil {
			ikeLog.Errorln(err)
			ikeLog.Error("Encode IKE payload failed.")
			return
		}
		if _, err = ikeSecurityAssociation.Prf_i.Write(idPayloadData[4:]); err != nil {
			ikeLog.Errorf("Pseudorandom function write error: %+v", err)
			return
		}
		ikeSecurityAssociation.ResponderSignedOctets = append(
			ikeSecurityAssociation.ResponderSignedOctets,
			ikeSecurityAssociation.Prf_i.Sum(nil)...)

		pseudorandomFunction := ikeSecurityAssociation.PrfInfo.Init(n3ueSelf.Kn3iwf)
		if _, err = pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
			ikeLog.Errorf("Pseudorandom function write error: %+v", err)
			return
		}
		secret := pseudorandomFunction.Sum(nil)
		pseudorandomFunction = ikeSecurityAssociation.PrfInfo.Init(secret)
		pseudorandomFunction.Reset()
		if _, err = pseudorandomFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
			ikeLog.Errorf("Pseudorandom function write error: %+v", err)
			return
		}
		ikePayload.BuildAuthentication(
			ike_message.SharedKeyMesageIntegrityCode,
			pseudorandomFunction.Sum(nil),
		)

		// Configuration Request
		configurationRequest := ikePayload.BuildConfiguration(ike_message.CFG_REQUEST)
		configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(
			ike_message.INTERNAL_IP4_ADDRESS,
			nil,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = SendIKEMessageToN3IWF(
			n3ueSelf.N3IWFUe.IKEConnection.Conn,
			n3ueSelf.N3IWFUe.IKEConnection.UEAddr,
			n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr,
			ikeMessage,
			ikeSecurityAssociation.IKESAKey,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_NASSecurityComplete: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case IKEAUTH_Authentication:
		// Get outbound SPI from proposal provided by N3IWF
		OutboundSPI := binary.BigEndian.Uint32(
			ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI,
		)
		childSecurityAssociationContext, err := n3ueSelf.N3IWFUe.CompleteChildSA(
			0x01, OutboundSPI, ikeSecurityAssociation.IKEAuthResponseSA)
		if err != nil {
			ikeLog.Errorf("Create child security association context failed: %+v", err)
			return
		}
		err = ParseIPAddressInformationToChildSecurityAssociation(
			childSecurityAssociationContext,
			responseTrafficSelectorInitiator.TrafficSelectors[0],
			responseTrafficSelectorResponder.TrafficSelectors[0])
		if err != nil {
			ikeLog.Errorf("Parse IP address to child security association failed: %+v", err)
			return
		}
		// Select TCP traffic
		childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP
		childSecurityAssociationContext.NonceInitiator = ikeSecurityAssociation.NonceInitiator
		childSecurityAssociationContext.NonceResponder = ikeSecurityAssociation.NonceResponder
		concatenatedNonce := append(childSecurityAssociationContext.NonceInitiator,
			childSecurityAssociationContext.NonceResponder...)

		err = childSecurityAssociationContext.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
			concatenatedNonce)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH Generate key for child SA failed: %+v", err)
			return
		}

		// ====== Inbound ======
		ikeLog.Debugln("====== IPSec/Child SA for 3GPP CP Inbound =====")
		ikeLog.Debugf(
			"[UE:%+v] <- [N3IWF:%+v]",
			childSecurityAssociationContext.LocalPublicIPAddr,
			childSecurityAssociationContext.PeerPublicIPAddr,
		)
		ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContext.InboundSPI)
		ikeLog.Debugf(
			"IPSec Encryption Algorithm: %d",
			childSecurityAssociationContext.EncrKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Encryption Key: 0x%x",
			childSecurityAssociationContext.ResponderToInitiatorEncryptionKey,
		)
		ikeLog.Debugf(
			"IPSec Integrity  Algorithm: %d",
			childSecurityAssociationContext.IntegKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Integrity  Key: 0x%x",
			childSecurityAssociationContext.ResponderToInitiatorIntegrityKey,
		)
		// ====== Outbound ======
		ikeLog.Debugln("====== IPSec/Child SA for 3GPP CP Outbound =====")
		ikeLog.Debugf(
			"[UE:%+v] -> [N3IWF:%+v]",
			childSecurityAssociationContext.LocalPublicIPAddr,
			childSecurityAssociationContext.PeerPublicIPAddr,
		)
		ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContext.OutboundSPI)
		ikeLog.Debugf(
			"IPSec Encryption Algorithm: %d",
			childSecurityAssociationContext.EncrKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Encryption Key: 0x%x",
			childSecurityAssociationContext.InitiatorToResponderEncryptionKey,
		)
		ikeLog.Debugf(
			"IPSec Integrity  Algorithm: %d",
			childSecurityAssociationContext.IntegKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Integrity  Key: 0x%x",
			childSecurityAssociationContext.InitiatorToResponderIntegrityKey,
		)

		// NAT-T concern
		if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
			childSecurityAssociationContext.EnableEncapsulate = true
			childSecurityAssociationContext.N3IWFPort = n3iwfAddr.Port
			childSecurityAssociationContext.NATPort = ueAddr.Port
		}

		// Setup interface for ipsec
		newXfrmiName := fmt.Sprintf("%s-%d", n3ueSelf.N3ueInfo.XfrmiName, n3ueSelf.N3ueInfo.XfrmiId)
		if _, err = xfrm.SetupIPsecXfrmi(newXfrmiName,
			n3ueSelf.N3ueInfo.IPSecIfaceName,
			n3ueSelf.N3ueInfo.XfrmiId,
			n3ueSelf.UEInnerAddr); err != nil {
			ikeLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
			return
		}

		// Aplly XFRM rules
		if err = xfrm.ApplyXFRMRule(true, n3ueSelf.N3ueInfo.XfrmiId, childSecurityAssociationContext); err != nil {
			ikeLog.Errorf("Applying XFRM rules failed: %+v", err)
			return
		}

		n3ueSelf.CurrentState <- uint8(context.Registration_CreateNWUCP)
	}
}

func HandleCREATECHILDSA(
	udpConn *net.UDPConn,
	ueAddr, n3iwfAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
) {
	ikeLog.Tracef("Handle CreateChildSA")

	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation

	var ikePayload ike_message.IKEPayloadContainer

	var QoSInfo *qos.PDUQoSInfo
	var OutboundSPI uint32
	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var err error
	var nonce []byte

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			OutboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyType5G_QOS_INFO {
				ikeLog.Info("Received Qos Flow settings")
				var info *qos.PDUQoSInfo
				if info, err = qos.Parse5GQoSInfoNotify(notification); err == nil {
					QoSInfo = info
					ikeLog.Infof("NotificationData:%+v", notification.NotificationData)
					if QoSInfo.IsDSCPSpecified {
						ikeLog.Infof("DSCP is specified but test not support")
					}
				} else {
					ikeLog.Infof("%+v", err)
				}
				n3ueSelf.TemporaryQosInfo = QoSInfo
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				n3ueSelf.TemporaryUPIPAddr = notification.NotificationData[:4]
				ikeLog.Infof("UP IP Address: %+v\n", n3ueSelf.TemporaryUPIPAddr)
			}
		case ike_message.TypeNiNr:
			responseNonce := ikePayload.(*ike_message.Nonce)
			nonce = responseNonce.NonceData
		}
	}

	// SA
	inboundSPI, err := GenerateSPI(n3ueSelf.N3IWFUe)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
	}
	ikeLog.Tracef("inboundspi : %+v", inboundSPI)
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
		return
	}
	localNonce := localNonceBigInt.Bytes()
	ikePayload.BuildNonce(localNonce)

	ikeMessage := ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.CREATE_CHILD_SA,
		true, true,
		ikeSecurityAssociation.InitiatorMessageID,
		ikePayload,
	)

	err = SendIKEMessageToN3IWF(
		n3ueSelf.N3IWFUe.IKEConnection.Conn,
		n3ueSelf.N3IWFUe.IKEConnection.UEAddr,
		n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr,
		ikeMessage,
		ikeSecurityAssociation.IKESAKey,
	)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
		return
	}

	n3ueSelf.N3IWFUe.CreateHalfChildSA(
		ikeSecurityAssociation.ResponderMessageID,
		binary.BigEndian.Uint32(inboundSPI),
		-1,
	)
	childSecurityAssociationContextUserPlane, err := n3ueSelf.N3IWFUe.CompleteChildSA(
		ikeSecurityAssociation.ResponderMessageID, OutboundSPI, responseSecurityAssociation)
	if err != nil {
		ikeLog.Errorf("Create child security association context failed: %+v", err)
		return
	}

	err = ParseIPAddressInformationToChildSecurityAssociation(
		childSecurityAssociationContextUserPlane,
		responseTrafficSelectorResponder.TrafficSelectors[0],
		responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		ikeLog.Errorf("Parse IP address to child security association failed: %+v", err)
		return
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE
	childSecurityAssociationContextUserPlane.NonceInitiator = nonce
	childSecurityAssociationContextUserPlane.NonceResponder = localNonce
	concatenatedNonce := append(childSecurityAssociationContextUserPlane.NonceInitiator,
		childSecurityAssociationContextUserPlane.NonceResponder...)

	err = childSecurityAssociationContextUserPlane.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
		concatenatedNonce)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA() Generate key for child SA failed: %+v", err)
		return
	}

	// NAT-T concern
	if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
		childSecurityAssociationContextUserPlane.EnableEncapsulate = true
		childSecurityAssociationContextUserPlane.N3IWFPort = n3iwfAddr.Port
		childSecurityAssociationContextUserPlane.NATPort = ueAddr.Port
	}

	n3ueSelf.N3ueInfo.XfrmiId++
	// Aplly XFRM rules
	if err = xfrm.ApplyXFRMRule(false, n3ueSelf.N3ueInfo.XfrmiId, childSecurityAssociationContextUserPlane); err != nil {
		ikeLog.Errorf("Applying XFRM rules failed: %+v", err)
		return
	}

	// ====== Inbound ======
	ikeLog.Debugln("====== IPSec/Child SA for 3GPP UP Inbound =====")
	ikeLog.Debugf(
		"[UE:%+v] <- [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr,
		childSecurityAssociationContextUserPlane.PeerPublicIPAddr,
	)
	ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.InboundSPI)
	ikeLog.Debugf(
		"IPSec Encryption Algorithm: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Encryption Key: 0x%x",
		childSecurityAssociationContextUserPlane.InitiatorToResponderEncryptionKey,
	)
	ikeLog.Debugf(
		"IPSec Integrity  Algorithm: %d",
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Integrity  Key: 0x%x",
		childSecurityAssociationContextUserPlane.InitiatorToResponderIntegrityKey,
	)
	// ====== Outbound ======
	ikeLog.Debugln("====== IPSec/Child SA for 3GPP UP Outbound =====")
	ikeLog.Debugf(
		"[UE:%+v] -> [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr,
		childSecurityAssociationContextUserPlane.PeerPublicIPAddr,
	)
	ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.OutboundSPI)
	ikeLog.Debugf(
		"IPSec Encryption Algorithm: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Encryption Key: 0x%x",
		childSecurityAssociationContextUserPlane.ResponderToInitiatorEncryptionKey,
	)
	ikeLog.Debugf(
		"IPSec Integrity  Algorithm: %d",
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Integrity  Key: 0x%x",
		childSecurityAssociationContextUserPlane.ResponderToInitiatorIntegrityKey,
	)
	ikeLog.Debugf(
		"State function: encr: %d, auth: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)

	// Setup interface for ipsec
	n3ueSelf.TemporaryXfrmiName = fmt.Sprintf(
		"%s-%d",
		n3ueSelf.N3ueInfo.XfrmiName,
		n3ueSelf.N3ueInfo.XfrmiId,
	)
	if _, err = xfrm.SetupIPsecXfrmi(n3ueSelf.TemporaryXfrmiName, n3ueSelf.N3ueInfo.IPSecIfaceName,
		n3ueSelf.N3ueInfo.XfrmiId, n3ueSelf.UEInnerAddr); err != nil {
		ikeLog.Errorf("Setup XFRMi interface %s fail: %+v", n3ueSelf.TemporaryXfrmiName, err)
	}
	ikeLog.Infof("Setup XFRM interface %s successfully", n3ueSelf.TemporaryXfrmiName)
}

func HandleInformational(
	udpConn *net.UDPConn,
	ueAddr, n3iwfAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
) {
	ikeLog.Infoln("Handle Informational")

	n3ueSelf = context.N3UESelf()

	if len(message.Payloads) == 0 && !message.IsResponse() {
		ikeLog.Tracef("Receive DPD message")
		SendN3IWFInformationExchange(n3ueSelf, nil, true, true, message.MessageID)
	} else {
		ikeLog.Warnf("Unimplemented informational message")
	}
}

func HandleNATDetect(
	initiatorSPI, responderSPI uint64,
	notifications []*ike_message.Notification,
	ueAddr, n3iwfAddr *net.UDPAddr,
) (bool, bool, error) {
	ueBehindNAT := false
	n3iwfBehindNAT := false

	srcNatDData, err := GenerateNATDetectHash(initiatorSPI, responderSPI, n3iwfAddr)
	if err != nil {
		return false, false, errors.Wrapf(err, "handle NATD")
	}

	dstNatDData, err := GenerateNATDetectHash(initiatorSPI, responderSPI, ueAddr)
	if err != nil {
		return false, false, errors.Wrapf(err, "handle NATD")
	}

	for _, notification := range notifications {
		switch notification.NotifyMessageType {
		case ike_message.NAT_DETECTION_SOURCE_IP:
			ikeLog.Tracef("Received IKE Notify: NAT_DETECTION_SOURCE_IP")
			if !bytes.Equal(notification.NotificationData, srcNatDData) {
				ikeLog.Tracef("N3IWF is behind NAT")
				n3iwfBehindNAT = true
			}
		case ike_message.NAT_DETECTION_DESTINATION_IP:
			ikeLog.Tracef("Received IKE Notify: NAT_DETECTION_DESTINATION_IP")
			if !bytes.Equal(notification.NotificationData, dstNatDData) {
				ikeLog.Tracef("UE(SPI: %016x) is behind NAT", responderSPI)
				ueBehindNAT = true
			}
		default:
		}
	}
	return ueBehindNAT, n3iwfBehindNAT, nil
}

func BuildNATDetectNotifPayload(
	localSPI uint64, remoteSPI uint64,
	payload *ike_message.IKEPayloadContainer,
	ueAddr, n3iwfAddr *net.UDPAddr,
) error {
	srcNatDHash, err := GenerateNATDetectHash(localSPI, remoteSPI, ueAddr)
	if err != nil {
		return errors.Wrapf(err, "build NATD")
	}
	// Build and append notify payload for NAT_DETECTION_SOURCE_IP
	payload.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_SOURCE_IP, nil, srcNatDHash)

	dstNatDHash, err := GenerateNATDetectHash(localSPI, remoteSPI, n3iwfAddr)
	if err != nil {
		return errors.Wrapf(err, "build NATD")
	}
	// Build and append notify payload for NAT_DETECTION_DESTINATION_IP
	payload.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_DESTINATION_IP, nil, dstNatDHash)

	return nil
}

func GenerateNATDetectHash(
	initiatorSPI, responderSPI uint64,
	addr *net.UDPAddr,
) ([]byte, error) {
	// Calculate NAT_DETECTION hash for NAT-T
	// : sha1(ispi | rspi | ip | port)
	natdData := make([]byte, 22)
	binary.BigEndian.PutUint64(natdData[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(natdData[8:16], responderSPI)
	copy(natdData[16:20], addr.IP.To4())
	binary.BigEndian.PutUint16(natdData[20:22], uint16(addr.Port)) // #nosec G115

	sha1HashFunction := sha1.New() // #nosec G401
	_, err := sha1HashFunction.Write(natdData)
	if err != nil {
		return nil, errors.Wrapf(err, "generate NATD Hash")
	}
	return sha1HashFunction.Sum(nil), nil
}

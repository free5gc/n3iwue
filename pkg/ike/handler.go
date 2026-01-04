package ike

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	ike_eap "github.com/free5gc/ike/eap"
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
	"github.com/free5gc/n3iwue/internal/util"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/xfrm"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/util/ueauth"
)

var nasLog *logrus.Entry

func init() {
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

func (s *Server) handleEvent(ikeEvt context.IkeEvt) {
	switch t := ikeEvt.(type) {
	case *context.HandleIkeMsgSaInitEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleIKESAINIT(t)
		}
	case *context.HandleIkeMsgAuthEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleIKEAUTH(t)
		}
	case *context.HandleIkeMsgCreateChildSaEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleCREATECHILDSA(t)
		}
	case *context.HandleIkeMsgInformationalEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleInformational(t)
		}
	case *context.IkeRetransTimeoutEvt:
		s.handleIkeRetransTimeout()
	case *context.DpdCheckEvt:
		s.handleDpdCheck()

	// For Procedure event
	case *context.StartIkeSaEstablishmentEvt:
		s.handleStartIkeSaEstablishment()
	case *context.IkeReConnectEvt:
		s.handleIkeReconnect()
	default:
		logger.IKELog.Errorf("Unknown IKE event: %+v", ikeEvt.Type())
	}
}

func (s *Server) handleStartIkeSaEstablishment() {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle Start IKE SA Establishment")
	n3ueContext := s.Context()

	// Stop any existing continuous timer
	s.stopContinuousIkeSaInit()

	// Send initial IKE_SA_INIT
	s.SendIkeSaInit()

	// Set up continuous timer for IKE_SA_INIT retransmission
	retransCfg := factory.N3ueInfo.IkeRetransmit
	interval := time.Duration(retransCfg.Base) * retransCfg.ExpireTime

	n3ueContext.ContinuousIkeSaInitTimer = time.AfterFunc(interval, func() {
		s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
	})
}

// stopContinuousIkeSaInit stops the continuous IKE_SA_INIT timer
func (s *Server) stopContinuousIkeSaInit() {
	n3ueContext := s.Context()
	if n3ueContext.ContinuousIkeSaInitTimer != nil {
		n3ueContext.ContinuousIkeSaInitTimer.Stop()
		n3ueContext.ContinuousIkeSaInitTimer = nil
	}
}

func (s *Server) handleIKESAINIT(
	evt *context.HandleIkeMsgSaInitEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle IKESA INIT")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg
	// packet := evt.Packet

	n3ueSelf := s.Context()
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
			var i int
			for remotePublicKeyExchangeValue[i] == 0 {
				i++
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
		UEIsBehindNAT:     ueIsBehindNAT,
		N3IWFIsBehindNAT:  n3iwfIsBehindNAT,
		ReqRetransmitInfo: &context.ReqRetransmitInfo{},
		RspRetransmitInfo: &context.RspRetransmitInfo{},
	}
	ConcatenatedNonce := append(ikeSecurityAssociation.NonceInitiator, ikeSecurityAssociation.NonceResponder...)

	err = ikeSecurityAssociation.GenerateKeyForIKESA(ConcatenatedNonce,
		sharedKeyExchangeData, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)
	if err != nil {
		ikeLog.Errorf("Generate key for IKE SA failed: %+v", err)
		return
	}

	ikeLog.Tracef("%v", ikeSecurityAssociation.String())
	n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	// Stop continuous IKE_SA_INIT timer as IKE SA is now established
	s.stopContinuousIkeSaInit()

	s.SendIkeAuth()
}

func (s *Server) handleIKEAUTH(
	evt *context.HandleIkeMsgAuthEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle IKE AUTH")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	ue := n3ueSelf.RanUeContext

	var ikePayload ike_message.IKEPayloadContainer

	// var eapIdentifier uint8
	var eapReq *ike_message.PayloadEap

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
			eapReq = ikePayload.(*ike_message.PayloadEap)
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
		anParameters := s.BuildEAP5GANParameters()
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

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapIdentifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
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

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() IKEAUTH_Request: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_RegistrationRequest:
		var eapExpanded *ike_eap.EapExpanded
		eapExpanded, ok = eapReq.EapTypeData.(*ike_eap.EapExpanded)
		if !ok {
			ikeLog.Error("The EAP data is not an EAP expended.")
			return
		}

		// Decode NAS - Authentication Request
		nasData := eapExpanded.VendorData[4:]
		pdu, keepAuth := s.HandleNas(nasData)
		if pdu == nil {
			ikeLog.Error("HandleNas() failed")
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

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapReq.Identifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
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

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_RegistrationRequest: %v", err)
			return
		}

		if !keepAuth {
			// keep authentication, and keep the ike state until the authentication is successful
			ikeSecurityAssociation.State++
		}
	case EAP_Authentication:
		_, ok = eapReq.EapTypeData.(*ike_eap.EapExpanded)
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

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapReq.Identifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
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

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_Authentication: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_NASSecurityComplete:
		if eapReq.Code != ike_eap.EapCodeSuccess {
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

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
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

		s.StartInboundMessageTimer(ikeSecurityAssociation)

		s.SendProcedureEvt(context.NewNwucpChildSaCreatedEvt())
	}
}

func (s *Server) handleCREATECHILDSA(
	evt *context.HandleIkeMsgCreateChildSaEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle CreateChildSA")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	ikeSecurityAssociation.ResponderMessageID = message.MessageID

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
		ikeSecurityAssociation.ResponderMessageID,
		ikePayload,
	)

	err = s.SendIkeMsgToN3iwf(
		n3ueSelf.N3IWFUe.IKEConnection,
		ikeMessage,
		ikeSecurityAssociation,
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

func (s *Server) handleInformational(
	evt *context.HandleIkeMsgInformationalEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle Informational")

	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSA := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation

	var deletePayload *ike_message.Delete

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeD:
			deletePayload = ikePayload.(*ike_message.Delete)
		default:
			ikeLog.Warnf("Unhandled Ike payload type[%s] informational message", ikePayload.Type().String())
		}
	}

	if !message.IsResponse() {
		ikeSA.ResponderMessageID = message.MessageID
		if deletePayload != nil {
			// TODO: Handle delete payload
			ikeLog.Infof("Received delete payload, sending deregistration complete event")
			s.SendProcedureEvt(context.NewDeregistrationCompleteEvt())
		} else {
			ikeLog.Tracef("Receive DPD message request")
		}
		s.SendN3iwfInformationExchange(n3ueSelf, nil, true, true, message.MessageID)
	}
}

func HandleNATDetect(
	initiatorSPI, responderSPI uint64,
	notifications []*ike_message.Notification,
	ueAddr, n3iwfAddr *net.UDPAddr,
) (bool, bool, error) {
	ikeLog := logger.IKELog
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

// Retransmit message types
const (
	RETRANSMIT_PACKET = iota
	NEW_PACKET
	INVALID_PACKET
)

// processRetransmitCtx processes retransmission context with Message ID checking
func (s *Server) processRetransmitCtx(
	ikeSA *context.IKESecurityAssociation,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) bool {
	if ikeSA == nil {
		return true
	}
	ikeLog := logger.IKELog

	// Reset inbound message timer if DPD is enabled
	if ikeSA.IsUseDPD {
		s.ResetInboundMessageTimer(ikeSA)

		// Update inbound message timestamp
		ikeSA.UpdateInboundMessageTimestamp()
	}

	// Process retransmit message
	needMoreProcess, err := s.processRetransmitMsg(ikeSA, ikeMsg.IKEHeader, packet)
	if err != nil {
		ikeLog.Errorf("processRetransmitCtx(): %v", err)
		return false
	}
	if !needMoreProcess {
		return false
	}

	// Stop request message's retransmit timer send from n3iwue
	if ikeMsg.IsResponse() && ikeSA.GetReqRetransTimer() != nil {
		ikeSA.StopReqRetransTimer()
	}

	// Store request message's hash send from N3IWF
	if !ikeMsg.IsResponse() {
		ikeSA.StoreRspRetransPrevReqHash(packet)
	}
	return true
}

// processRetransmitMsg determines if the message should be processed further
func (s *Server) processRetransmitMsg(
	ikeSA *context.IKESecurityAssociation,
	ikeHeader *ike_message.IKEHeader, packet []byte,
) (bool, error) {
	if ikeSA == nil {
		return false, errors.New("processRetransmitMsg(): ikeSA is nil")
	}
	ikeLog := logger.IKELog
	ikeLog.Tracef("Process retransmit message")

	if !ikeHeader.IsResponse() {
		// For requests from N3IWF, check retransmit status
		status, err := s.isRetransmit(ikeSA, ikeHeader, packet)
		switch status {
		case RETRANSMIT_PACKET:
			ikeLog.Warnf("Received IKE request message retransmission with message ID: %d", ikeHeader.MessageID)
			// Send cached response
			err = SendIkeRawMsg(ikeSA.GetRspRetransPrevRsp(), ikeSA.GetRspRetransUdpConnInfo())
			if err != nil {
				return false, errors.Wrapf(err, "processRetransmitMsg()")
			}
			return false, nil
		case NEW_PACKET:
			return true, nil
		case INVALID_PACKET:
			return false, err
		default:
			return false, errors.New("processRetransmitMsg(): invalid retransmit status")
		}
	} else {
		if ikeHeader.MessageID == ikeSA.InitiatorMessageID {
			return true, nil
		} else {
			return false, fmt.Errorf("processRetransmitMsg(): Response expected message ID: %d but received message ID: %d",
				ikeSA.InitiatorMessageID, ikeHeader.MessageID)
		}
	}
}

// isRetransmit checks if the packet is a retransmission using Message ID and SHA1 hash comparison
func (s *Server) isRetransmit(
	ikeSA *context.IKESecurityAssociation,
	ikeHeader *ike_message.IKEHeader, packet []byte,
) (int, error) {
	if ikeSA == nil {
		return INVALID_PACKET, errors.New("isRetransmit(): ikeSA is nil")
	}

	if ikeHeader.MessageID == ikeSA.ResponderMessageID+1 {
		return NEW_PACKET, nil
	}

	if ikeHeader.MessageID != ikeSA.ResponderMessageID {
		return INVALID_PACKET,
			fmt.Errorf("isRetransmit(): Expected message ID: %d or %d but received message ID: %d",
				ikeSA.ResponderMessageID, ikeSA.ResponderMessageID+1, ikeHeader.MessageID)
	}

	// Check if we have a cached response (indicating we processed this request before)
	if ikeSA.GetRspRetransPrevRsp() == nil {
		logger.IKELog.Warnf("isRetransmit(): Received potential retransmit but no cached response, processing as new")
		return NEW_PACKET, nil
	}

	// Compare SHA1 hashes to determine if it's truly a retransmit
	hash := sha1.Sum(packet) // #nosec G401
	prevHash := ikeSA.GetRspRetransPrevReqHash()

	// Compare the incoming request message with the previous request message (same msgID)
	if bytes.Equal(hash[:], prevHash[:]) {
		return RETRANSMIT_PACKET, nil
	}
	return INVALID_PACKET, errors.New("isRetransmit(): message is not retransmit")
}

// handleIkeRetransTimeoutEvt handles IKE retransmission timeout events
func (s *Server) handleIkeRetransTimeout() {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle IKE retransmission timeout")

	n3ueCtx := s.Context()
	if n3ueCtx.N3IWFUe == nil || n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		ikeLog.Warn("No IKE SA found for retransmission")
		return
	}

	ikeSA := n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation

	// Get retransmit information
	timer := ikeSA.GetReqRetransTimer()
	prevReq := ikeSA.GetReqRetransPrevReq()
	udpConnInfo := ikeSA.GetReqRetransUdpConnInfo()

	if timer == nil || prevReq == nil || udpConnInfo == nil {
		ikeLog.Warn("Incomplete retransmit information, cannot retransmit")
		ikeSA.StopReqRetransTimer()
		return
	}

	// Check if we have retries left
	if timer.GetRetryCount() == 0 {
		ikeLog.Warnf("Maximum retransmission attempts reached, triggering reconnection")

		if s.Config().Configuration.N3UEInfo.AutoReRegistration {
			// Trigger IKE reconnection if re-registration is allowed
			s.handleIkeReconnect()
		} else {
			// Trigger graceful shutdown if re-registration is not allowed
			s.TriggerGracefulShutdown("maximum IKE retransmission attempts reached")
		}

		return
	}

	// Increment retry count and retransmit the packet
	timer.DecrementRetryCount()
	ikeLog.Tracef("Retransmitting IKE packet (retry %d/%d)",
		timer.GetRetryCount(), timer.MaxRetryTimes)

	// Send the retransmitted packet
	err := SendIkeRawMsg(prevReq, udpConnInfo)
	if err != nil {
		ikeLog.Errorf("Failed to retransmit IKE packet: %v", err)
		ikeSA.StopReqRetransTimer()
		return
	}

	delayTime := timer.GetNextDelay()
	timer.Timer = time.AfterFunc(delayTime, func() {
		s.SendIkeEvt(context.NewIkeRetransTimeoutEvt())
	})
}

// shouldProcessRetransmit checks if message should be processed for retransmit
func (s *Server) shouldProcessRetransmit(ikeMsg *ike_message.IKEMessage, packet []byte) bool {
	n3ueCtx := s.Context()
	if n3ueCtx.N3IWFUe == nil || n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		return false // No IKE SA, continue normal processing
	}

	ikeSA := n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation
	return s.processRetransmitCtx(ikeSA, ikeMsg, packet)
}

// StartInboundMessageTimer starts the inbound message timer for DPD
func (s *Server) StartInboundMessageTimer(ikeSA *context.IKESecurityAssociation) {
	ikeLog := logger.IKELog
	if ikeSA == nil {
		return
	}

	dpdInterval := factory.N3ueConfig.Configuration.N3UEInfo.DpdInterval
	if dpdInterval == 0 {
		return
	}

	ikeLog.Tracef("Starting inbound message timer for DPD with interval: %v", dpdInterval)

	ikeSA.InboundMessageTimer = time.AfterFunc(dpdInterval, func() {
		ikeLog.Tracef("Inbound message timer timeout, triggering DPD check")
		s.SendIkeEvt(context.NewDpdCheckEvt())
	})
}

// ResetInboundMessageTimer resets the inbound message timer
func (s *Server) ResetInboundMessageTimer(ikeSA *context.IKESecurityAssociation) {
	if ikeSA == nil {
		return
	}

	// Stop existing timer
	ikeSA.StopInboundMessageTimer()
	// Start new timer
	s.StartInboundMessageTimer(ikeSA)
}

// handleDpdCheck handles DPD check events
func (s *Server) handleDpdCheck() {
	ikeLog := logger.IKELog
	n3ue := s.Context()

	if n3ue.N3IWFUe == nil || n3ue.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		ikeLog.Warn("No IKE SA found for DPD check")
		return
	}

	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation
	ikeLog.Tracef("Handle DPD check event")

	dpdInterval := factory.N3ueConfig.Configuration.N3UEInfo.DpdInterval
	if dpdInterval == 0 {
		ikeLog.Tracef("DPD is disabled, skip DPD check")
		return
	}

	var sendDpd bool

	// Check if we need to send DPD based on inbound message timestamp
	if ikeSA.GetReqRetransTimer() == nil { // No ongoing retransmissions
		now := time.Now()
		lastInboundTime := time.Unix(ikeSA.InboundMessageTimestamp, 0)

		ikeLog.Tracef("Last inbound message time: %v, now: %v", lastInboundTime, now)

		// If no inbound message for DPD interval, send DPD
		if now.Sub(lastInboundTime) > dpdInterval {
			ikeLog.Tracef("Sending DPD message")
			ikeSA.InitiatorMessageID++
			s.SendN3iwfInformationExchange(n3ue, nil, true, false, ikeSA.InitiatorMessageID)
			sendDpd = true
		}
	}

	// Reset the timer for next check
	s.ResetInboundMessageTimer(ikeSA)

	if !sendDpd {
		ikeLog.Tracef("DPD check completed, no message needed")
	}
}

// handleIkeReconnect handles IKE connection failure events for reconnection
func (s *Server) handleIkeReconnect() {
	ikeLog := logger.IKELog
	ikeLog.Warnf("Handle IKE connection failed - initiating reconnection")

	n3ue := s.Context()
	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation

	ikeSA.StopReqRetransTimer()
	ikeSA.StopInboundMessageTimer()

	if err := s.CleanChildSAXfrm(); err != nil {
		ikeLog.Errorf("CleanChildSAXfrm error: %v", err)
	}

	// Cleanup XFRM interfaces
	n3ue.CleanupXfrmIf()

	// Reset all IKE context to prepare for reconnection
	ikeConn := n3ue.IKEConnection
	if err := factory.Initialize(); err != nil {
		ikeLog.Errorf("handleIkeConnectionFailed(): %v", err)
	}

	util.InitN3UEContext()
	n3ue.IKEConnection = ikeConn

	// Trigger procedure restart via RestartRegistration event
	s.SendProcedureEvt(context.NewRestartRegistrationEvt())
}

// return (nasPdu, keepAuthentication)
func (s *Server) HandleNas(nasData []byte) ([]byte, bool) {
	nasLog := logger.NASLog

	n3ueSelf := s.Context()
	ue := n3ueSelf.RanUeContext
	decodedNAS := new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		nasLog.Errorf("HandleNas(): Decode plain NAS fail: %+v", err)
		return nil, false
	}

	// Calculate for RES*
	if decodedNAS.GmmMessage == nil {
		nasLog.Error("HandleNas(): decodedNAS is nil")
		return nil, false
	}

	var pdu []byte
	switch decodedNAS.GmmMessage.GetMessageType() {
	case nas.MsgTypeAuthenticationRequest:
		nasLog.Info("Received Authentication Request")

		// Extract RAND and AUTN parameters
		rand := decodedNAS.GetRANDValue()

		// Check if AUTN is present
		if decodedNAS.AuthenticationParameterAUTN == nil {
			nasLog.Error("AUTN parameter missing in Authentication Request")
			return nil, false
		}
		autn := decodedNAS.GetAUTN()

		nasLog.Infof("RAND: %x", rand)
		nasLog.Infof("AUTN: %x", autn)

		// Perform AUTN verification and SQN synchronization
		authResult, err := ue.VerifyAUTN(autn[:], rand[:])
		if err != nil {
			nasLog.Errorf("AUTN verification failed: %v", err)
		}

		var resStat []byte

		switch authResult {
		case 0: // AUTH_SUCCESS
			nasLog.Info("AUTN verification successful, SQN is fresh")
			// Update SQN and derive RES*
			snn := n3ueSelf.N3ueInfo.GetSNN()
			resStat = ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], snn, autn[:])

		case 1: // AUTH_SQN_FAILURE
			nasLog.Warn("SQN failure detected, generating AUTS for re-synchronization")
			auts, err := ue.GenerateAUTS(rand[:])
			if err != nil {
				nasLog.Errorf("AUTS generation failed: %v", err)
				return nil, false
			}

			nasLog.Infof("Generated AUTS: %x", auts)
			// Send Authentication Failure with AUTS
			pdu = nasPacket.GetAuthenticationFailure(0x15, auts) // EMM cause 0x15 = Synch failure
			return pdu, true

		case 2: // AUTH_MAC_FAILURE
			nasLog.Error("MAC verification failed - possible attack or corruption")
			// Send Authentication Failure without AUTS
			pdu = nasPacket.GetAuthenticationFailure(0x14, nil) // EMM cause 0x14 = MAC failure
			return pdu, false

		default:
			nasLog.Errorf("Unknown authentication result: %d", authResult)
			return nil, false
		}

		nasLog.Infof("KnasEnc: %0x", ue.KnasEnc)
		nasLog.Infof("KnasInt: %0x", ue.KnasInt)
		nasLog.Infof("Kamf: %0x", ue.Kamf)
		nasLog.Infof("AnType: %s", ue.AnType)
		nasLog.Infof("SUPI: %s", ue.Supi)

		// send NAS Authentication Response
		pdu = nasPacket.GetAuthenticationResponse(resStat, "")

	default:
		nasLog.Errorf("Received unexpected message type: %d",
			decodedNAS.GmmMessage.GetMessageType())
		return nil, false
	}

	return pdu, false
}

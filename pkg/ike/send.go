package ike

import (
	"encoding/binary"
	"math/big"
	"time"

	"github.com/pkg/errors"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/n3iwue/internal/logger"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

func (s *Server) SendIkeSaInit() {
	ikeLog := logger.IKELog
	ikeLog.Tracef("start IKE_SA_INIT message")
	var err error

	n3ueContext := s.Context()

	n3ueContext.IkeInitiatorSPI = factory.N3ueInfo.IkeSaSPI
	payload := new(ike_message.IKEPayloadContainer)

	// Security Association
	n3ueContext.SecurityAssociation = payload.BuildSecurityAssociation()
	// Proposal 1
	n3ueContext.Proposal = n3ueContext.SecurityAssociation.Proposals.BuildProposal(1, ike_message.TypeIKE, nil)
	// ENCR
	n3ueContext.AttributeType = ike_message.AttributeTypeKeyLength
	n3ueContext.KeyLength = 256
	n3ueContext.Proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_AES_CBC,
		&n3ueContext.AttributeType, &n3ueContext.KeyLength, nil)
	// INTEG
	n3ueContext.Proposal.IntegrityAlgorithm.BuildTransform(
		ike_message.TypeIntegrityAlgorithm,
		ike_message.AUTH_HMAC_SHA1_96,
		nil,
		nil,
		nil,
	)
	// PRF
	n3ueContext.Proposal.PseudorandomFunction.BuildTransform(
		ike_message.TypePseudorandomFunction,
		ike_message.PRF_HMAC_SHA1,
		nil,
		nil,
		nil,
	)
	// DH
	n3ueContext.Proposal.DiffieHellmanGroup.BuildTransform(
		ike_message.TypeDiffieHellmanGroup,
		ike_message.DH_2048_BIT_MODP,
		nil,
		nil,
		nil,
	)

	// Key exchange data
	generator := new(big.Int).SetUint64(dh.Group14Generator)
	factor, ok := new(big.Int).SetString(dh.Group14PrimeString, 16)
	if !ok {
		ikeLog.Error("Generate key exchange data failed")
		return
	}
	n3ueContext.Factor = factor

	n3ueContext.Secert, err = ike_security.GenerateRandomNumber()
	if err != nil {
		ikeLog.Errorf("SendIKESAINIT() Secert : %v", err)
		return
	}

	localPublicKeyExchangeValue := new(big.Int).Exp(generator, n3ueContext.Secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	payload.BuildKeyExchange(ike_message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		ikeLog.Errorf("SendIKESAINIT() localNonce : %v", err)
		return
	}
	n3ueContext.LocalNonce = localNonceBigInt.Bytes()
	payload.BuildNonce(n3ueContext.LocalNonce)

	ikeMessage := ike_message.NewMessage(n3ueContext.IkeInitiatorSPI, 0,
		ike_message.IKE_SA_INIT, false, true, 0, *payload)

	n3ueContext.N3IWFUe.IKEConnection = n3ueContext.IKEConnection[500]

	err = BuildNATDetectNotifPayload(n3ueContext.IkeInitiatorSPI, 0, &ikeMessage.Payloads,
		n3ueContext.N3IWFUe.IKEConnection.UEAddr,
		n3ueContext.N3IWFUe.IKEConnection.N3IWFAddr)
	if err != nil {
		ikeLog.Errorf("SendIKESAINIT(): %v", err)
		return
	}

	// Send to n3iwf
	err = s.SendIkeMsgToN3iwf(
		n3ueContext.N3IWFUe.IKEConnection,
		ikeMessage,
		nil,
	)
	if err != nil {
		ikeLog.Errorf("SendIKESAINIT(): %v", err)
		return
	}

	var realMessage1 []byte
	if realMessage1, err = ikeMessage.Encode(); err != nil {
		ikeLog.Errorf("Write config file: %+v", err)
		return
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		ResponderSignedOctets: realMessage1,
	}
	n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation
}

func (s *Server) SendIkeAuth() {
	ikeLog := logger.IKELog
	ikeLog.Tracef("IKE_AUTH message")

	n3ueContext := s.Context()
	ikeSA := n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation

	ikeSA.InitiatorMessageID++

	var ikePayload ike_message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, []byte("UE"))

	// Security Association
	n3ueContext.SecurityAssociation = ikePayload.BuildSecurityAssociation()
	// Proposal 1
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, factory.N3ueInfo.IPSecSaCpSPI)
	n3ueContext.Proposal = n3ueContext.SecurityAssociation.Proposals.BuildProposal(1, ike_message.TypeESP, spi)
	// ENCR
	n3ueContext.Proposal.EncryptionAlgorithm.BuildTransform(ike_message.TypeEncryptionAlgorithm, ike_message.ENCR_AES_CBC,
		&n3ueContext.AttributeType, &n3ueContext.KeyLength, nil)
	// INTEG
	n3ueContext.Proposal.IntegrityAlgorithm.BuildTransform(
		ike_message.TypeIntegrityAlgorithm,
		ike_message.AUTH_HMAC_SHA1_96,
		nil,
		nil,
		nil,
	)
	// ESN
	n3ueContext.Proposal.ExtendedSequenceNumbers.BuildTransform(
		ike_message.TypeExtendedSequenceNumbers,
		ike_message.ESN_DISABLE,
		nil,
		nil,
		nil,
	)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(
		ike_message.TS_IPV4_ADDR_RANGE,
		0,
		0,
		65535,
		[]byte{0, 0, 0, 0},
		[]byte{255, 255, 255, 255},
	)
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(
		ike_message.TS_IPV4_ADDR_RANGE,
		0,
		0,
		65535,
		[]byte{0, 0, 0, 0},
		[]byte{255, 255, 255, 255},
	)

	ikeMessage := ike_message.NewMessage(
		ikeSA.LocalSPI, ikeSA.RemoteSPI,
		ike_message.IKE_AUTH, false, true,
		ikeSA.InitiatorMessageID,
		ikePayload,
	)

	if ikeSA.UEIsBehindNAT || ikeSA.N3IWFIsBehindNAT {
		n3ueContext.N3IWFUe.IKEConnection = n3ueContext.IKEConnection[4500]
	}

	err := s.SendIkeMsgToN3iwf(
		n3ueContext.N3IWFUe.IKEConnection,
		ikeMessage,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation)
	if err != nil {
		ikeLog.Errorf("SendIKEAUTH(): %d", err)
		return
	}

	n3ueContext.N3IWFUe.CreateHalfChildSA(
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID,
		factory.N3ueInfo.IPSecSaCpSPI,
		-1,
	)
}

func SendIkeRawMsg(pkt []byte,
	udpConnInfo *context.UDPSocketInfo,
) error {
	ikeLog := logger.IKELog
	ikeLog.Trace("Sending...")
	_, err := udpConnInfo.Conn.WriteToUDP(pkt, udpConnInfo.N3IWFAddr)
	if err != nil {
		return errors.Wrapf(err, "SendIkeRawMsg()")
	}
	return nil
}

func (s *Server) SendIkeMsgToN3iwf(
	udpConnInfo *context.UDPSocketInfo,
	message *ike_message.IKEMessage,
	ikeSA *context.IKESecurityAssociation,
) error {
	ikeLog := logger.IKELog
	ikeLog.Trace("Send IKE message to N3IWF")
	ikeLog.Trace("Encoding...")

	var ikeSAKey *ike_security.IKESAKey
	if ikeSA != nil {
		ikeSAKey = ikeSA.IKESAKey
	}
	pkt, err := ike.EncodeEncrypt(message, ikeSAKey, ike_message.Role_Initiator)
	if err != nil {
		return errors.Wrapf(err, "SendIkeMsgToN3iwf")
	}

	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if udpConnInfo.UEAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	err = SendIkeRawMsg(pkt, udpConnInfo)
	if err != nil {
		return errors.Wrapf(err, "SendIkeMsgToN3iwf")
	}

	// Set retransmit context if this is a request message and we have an IKE SA
	if ikeSA != nil {
		s.SetRetransmitCtx(ikeSA, pkt, udpConnInfo, message.IsResponse())
	}

	return nil
}

func (s *Server) SendN3iwfInformationExchange(
	n3ue *context.N3UE,
	payload *ike_message.IKEPayloadContainer, initiator bool,
	response bool, messageID uint32,
) {
	ikeLog := logger.IKELog
	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation

	// Build IKE message
	responseIKEMessage := ike_message.NewMessage(ikeSA.LocalSPI, ikeSA.RemoteSPI,
		ike_message.INFORMATIONAL, response, initiator, messageID, nil)

	if payload != nil && len(*payload) > 0 {
		responseIKEMessage.Payloads = append(responseIKEMessage.Payloads, *payload...)
	}

	err := s.SendIkeMsgToN3iwf(
		n3ue.N3IWFUe.IKEConnection,
		responseIKEMessage,
		ikeSA)
	if err != nil {
		ikeLog.Errorf("SendUEInformationExchange err: %+v", err)
		return
	}
}

// ===== IKE Retransmit Methods =====

// SetRetransmitCtx sets up retransmit context for IKE messages
func (s *Server) SetRetransmitCtx(
	ikeSA *context.IKESecurityAssociation,
	pkt []byte,
	udpConnInfo *context.UDPSocketInfo,
	isResponse bool,
) {
	if ikeSA == nil {
		return
	}

	if isResponse {
		// Store response retransmit info
		ikeSA.StoreRspRetransPrevRsp(pkt)
		ikeSA.StoreRspRetransUdpConnInfo(udpConnInfo)
	} else {
		// Store request retransmit info and set timer for requests only
		ikeSA.StoreReqRetransPrevReq(pkt)
		ikeSA.StoreReqRetransUdpConnInfo(udpConnInfo)
		s.SetRetransmitTimer(ikeSA)
	}
}

// SetRetransmitTimer sets up retransmit timer for IKE requests
func (s *Server) SetRetransmitTimer(ikeSA *context.IKESecurityAssociation) {
	retransCfg := factory.N3ueInfo.IkeRetransmit
	timer := &context.RetransmitTimer{
		ExponentialTimerValue: *factory.N3ueInfo.IkeRetransmit,
	}
	if retransCfg.Enable {
		timer.Base = retransCfg.Base
	} else {
		timer.Base = 1
		timer.MaxRetryTimes = 0
	}
	timer.RemainingRetries = retransCfg.MaxRetryTimes

	// Start the timer
	delayTime := timer.GetNextDelay()
	timer.Timer = time.AfterFunc(delayTime, func() {
		s.SendIkeEvt(context.NewIkeRetransTimeoutEvt())
	})

	ikeSA.StoreReqRetransTimer(timer)
}

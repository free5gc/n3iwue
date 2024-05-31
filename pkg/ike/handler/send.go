package handler

import (
	"encoding/binary"
	"math/big"
	"net"

	n3iwfContext "github.com/free5gc/n3iwf/pkg/context"
	n3iwf_handler "github.com/free5gc/n3iwf/pkg/ike/handler"
	"github.com/free5gc/n3iwf/pkg/ike/message"
	ike_message "github.com/free5gc/n3iwf/pkg/ike/message"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

func SendIKESAINIT() {
	ikeLog.Tracef("start IKE_SA_INIT message")

	n3ueContext := context.N3UESelf()

	n3ueContext.IkeInitiatorSPI = factory.N3ueInfo.IkeSaSPI
	ikeMessage := new(message.IKEMessage)
	ikeMessage.BuildIKEHeader(n3ueContext.IkeInitiatorSPI, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	// Security Association
	n3ueContext.SecurityAssociation = ikeMessage.Payloads.BuildSecurityAssociation()
	// Proposal 1
	n3ueContext.Proposal = n3ueContext.SecurityAssociation.Proposals.BuildProposal(1, message.TypeIKE, nil)
	// ENCR
	n3ueContext.AttributeType = message.AttributeTypeKeyLength
	n3ueContext.KeyLength = 256
	n3ueContext.Proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC,
		&n3ueContext.AttributeType, &n3ueContext.KeyLength, nil)
	// INTEG
	n3ueContext.Proposal.IntegrityAlgorithm.BuildTransform(
		message.TypeIntegrityAlgorithm,
		message.AUTH_HMAC_SHA1_96,
		nil,
		nil,
		nil,
	)
	// PRF
	n3ueContext.Proposal.PseudorandomFunction.BuildTransform(
		message.TypePseudorandomFunction,
		message.PRF_HMAC_SHA1,
		nil,
		nil,
		nil,
	)
	// DH
	n3ueContext.Proposal.DiffieHellmanGroup.BuildTransform(
		message.TypeDiffieHellmanGroup,
		message.DH_2048_BIT_MODP,
		nil,
		nil,
		nil,
	)

	// Key exchange data
	generator := new(big.Int).SetUint64(n3iwf_handler.Group14Generator)
	factor, ok := new(big.Int).SetString(n3iwf_handler.Group14PrimeString, 16)
	if !ok {
		ikeLog.Error("Generate key exchange data failed")
		return
	}
	n3ueContext.Factor = factor

	n3ueContext.Secert = n3iwf_handler.GenerateRandomNumber()
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, n3ueContext.Secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	n3ueContext.LocalNonce = n3iwf_handler.GenerateRandomNumber().Bytes()
	ikeMessage.Payloads.BuildNonce(n3ueContext.LocalNonce)

	// Send to n3iwf
	n3iwf_handler.SendIKEMessageToUE(n3ueContext.N3IWFUe.IKEConnection.Conn, n3ueContext.N3IWFUe.IKEConnection.UEAddr,
		n3ueContext.N3IWFUe.IKEConnection.N3IWFAddr, ikeMessage)

	var realMessage1 []byte
	var err error
	if realMessage1, err = ikeMessage.Encode(); err != nil {
		ikeLog.Errorf("Write config file: %+v", err)
		return
	}

	ikeSecurityAssociation := &n3iwfContext.IKESecurityAssociation{
		ResponderSignedOctets: realMessage1,
	}
	n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation
}

func SendIKEAUTH() {
	ikeLog.Tracef("IKE_AUTH message")

	n3ueContext := context.N3UESelf()

	ikeMessage := new(message.IKEMessage)
	ikeMessage.Payloads.Reset()
	n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.LocalSPI,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH,
		message.InitiatorBitCheck,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID,
	)

	var ikePayload message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_KEY_ID, []byte("UE"))

	// Security Association
	n3ueContext.SecurityAssociation = ikePayload.BuildSecurityAssociation()
	// Proposal 1
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, factory.N3ueInfo.IPSecSaCpSPI)
	n3ueContext.Proposal = n3ueContext.SecurityAssociation.Proposals.BuildProposal(1, message.TypeESP, spi)
	// ENCR
	n3ueContext.Proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC,
		&n3ueContext.AttributeType, &n3ueContext.KeyLength, nil)
	// INTEG
	n3ueContext.Proposal.IntegrityAlgorithm.BuildTransform(
		message.TypeIntegrityAlgorithm,
		message.AUTH_HMAC_SHA1_96,
		nil,
		nil,
		nil,
	)
	// ESN
	n3ueContext.Proposal.ExtendedSequenceNumbers.BuildTransform(
		message.TypeExtendedSequenceNumbers,
		message.ESN_NO,
		nil,
		nil,
		nil,
	)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE,
		0,
		0,
		65535,
		[]byte{0, 0, 0, 0},
		[]byte{255, 255, 255, 255},
	)
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE,
		0,
		0,
		65535,
		[]byte{0, 0, 0, 0},
		[]byte{255, 255, 255, 255},
	)

	if err := EncryptProcedure(n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation, ikePayload, ikeMessage); err != nil {
		ikeLog.Errorf("Encrypting IKE message failed: %+v", err)
		return
	}

	SendIKEMessageToN3IWF(n3ueContext.N3IWFUe.IKEConnection.Conn, n3ueContext.N3IWFUe.IKEConnection.UEAddr,
		n3ueContext.N3IWFUe.IKEConnection.N3IWFAddr, ikeMessage)

	n3ueContext.N3IWFUe.CreateHalfChildSA(
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID,
		factory.N3ueInfo.IPSecSaCpSPI,
		-1,
	)
}

func SendIKEMessageToN3IWF(udpConn *net.UDPConn, srcAddr, dstAddr *net.UDPAddr, message *ike_message.IKEMessage) {
	ikeLog.Trace("Send IKE message to N3IWF")
	ikeLog.Trace("Encoding...")
	pkt, err := message.Encode()
	if err != nil {
		ikeLog.Errorln(err)
		return
	}

	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	ikeLog.Trace("Sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		ikeLog.Error(err)
		return
	}
	if n != len(pkt) {
		ikeLog.Errorf("Not all of the data is sent. Total length: %d. Sent: %d.", len(pkt), n)
		return
	}
}

func SendN3IWFInformationExchange(
	n3ue *context.N3UE, payload ike_message.IKEPayloadContainer, ike_flag uint8,
) {
	ikeSecurityAssociation := n3ue.N3IWFUe.N3IWFIKESecurityAssociation
	responseIKEMessage := new(ike_message.IKEMessage)

	// Build IKE message
	responseIKEMessage.BuildIKEHeader(ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI, ike_message.INFORMATIONAL, ike_flag,
		ikeSecurityAssociation.ResponderMessageID)
	if err := EncryptProcedure(ikeSecurityAssociation, payload, responseIKEMessage); err != nil {
		ikeLog.Errorf("Encrypting IKE message failed: %+v", err)
		return
	}

	SendIKEMessageToN3IWF(n3ue.N3IWFUe.IKEConnection.Conn, n3ue.N3IWFUe.IKEConnection.UEAddr,
		n3ue.N3IWFUe.IKEConnection.N3IWFAddr, responseIKEMessage)
}

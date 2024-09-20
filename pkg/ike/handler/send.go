package handler

import (
	"encoding/binary"
	"math/big"
	"net"

	"github.com/pkg/errors"

	"github.com/free5gc/ike"
	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

func SendIKESAINIT() {
	ikeLog.Tracef("start IKE_SA_INIT message")
	var err error

	n3ueContext := context.N3UESelf()

	n3ueContext.IkeInitiatorSPI = factory.N3ueInfo.IkeSaSPI
	ikeMessage := new(ike_message.IKEMessage)
	ikeMessage.BuildIKEHeader(n3ueContext.IkeInitiatorSPI, 0, ike_message.IKE_SA_INIT, ike_message.InitiatorBitCheck, 0)

	// Security Association
	n3ueContext.SecurityAssociation = ikeMessage.Payloads.BuildSecurityAssociation()
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
	ikeMessage.Payloads.BUildKeyExchange(ike_message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		ikeLog.Errorf("SendIKESAINIT() localNonce : %v", err)
		return
	}
	n3ueContext.LocalNonce = localNonceBigInt.Bytes()
	ikeMessage.Payloads.BuildNonce(n3ueContext.LocalNonce)

	// Send to n3iwf
	err = SendIKEMessageToN3IWF(n3ueContext.N3IWFUe.IKEConnection.Conn,
		n3ueContext.N3IWFUe.IKEConnection.UEAddr,
		n3ueContext.N3IWFUe.IKEConnection.N3IWFAddr, ikeMessage, nil)
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

func SendIKEAUTH() {
	ikeLog.Tracef("IKE_AUTH message")

	n3ueContext := context.N3UESelf()

	ikeMessage := new(ike_message.IKEMessage)
	ikeMessage.Payloads.Reset()
	n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.LocalSPI,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		ike_message.InitiatorBitCheck,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.InitiatorMessageID,
	)

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

	ikeMessage.Payloads = append(ikeMessage.Payloads, ikePayload...)
	err := SendIKEMessageToN3IWF(n3ueContext.N3IWFUe.IKEConnection.Conn, n3ueContext.N3IWFUe.IKEConnection.UEAddr,
		n3ueContext.N3IWFUe.IKEConnection.N3IWFAddr, ikeMessage,
		n3ueContext.N3IWFUe.N3IWFIKESecurityAssociation.IKESAKey)
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

func SendIKEMessageToN3IWF(
	udpConn *net.UDPConn,
	srcAddr, dstAddr *net.UDPAddr,
	message *ike_message.IKEMessage,
	ikeSAKey *security.IKESAKey,
) error {
	ikeLog.Trace("Send IKE message to UE")
	ikeLog.Trace("Encoding...")

	pkt, err := ike.EncodeEncrypt(message, ikeSAKey, ike_message.Role_Initiator)
	if err != nil {
		return errors.Wrapf(err, "SendIKEMessageToUE")
	}

	// As specified in RFC 7296 section 3.1, the IKE message send from/to UDP port 4500
	// should prepend a 4 bytes zero
	if srcAddr.Port == 4500 {
		prependZero := make([]byte, 4)
		pkt = append(prependZero, pkt...)
	}

	ikeLog.Trace("Sending...")
	n, err := udpConn.WriteToUDP(pkt, dstAddr)
	if err != nil {
		return errors.Wrapf(err, "SendIKEMessageToUE")
	}

	if n != len(pkt) {
		return errors.Errorf("SendIKEMessageToUE Not all of the data is sent. Total length: %d. Sent: %d.",
			len(pkt), n)
	}
	return nil
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

	responseIKEMessage.Payloads = append(responseIKEMessage.Payloads, payload...)
	err := SendIKEMessageToN3IWF(n3ue.N3IWFUe.IKEConnection.Conn,
		n3ue.N3IWFUe.IKEConnection.UEAddr,
		n3ue.N3IWFUe.IKEConnection.N3IWFAddr, responseIKEMessage,
		n3ue.N3IWFUe.N3IWFIKESecurityAssociation.IKESAKey)
	if err != nil {
		ikeLog.Errorf("SendN3IWFInformationExchange() : %v", err)
	}
}

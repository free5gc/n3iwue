package util

import (
	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	n3ue_security "github.com/free5gc/n3iwue/internal/security"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
)

var contextLog *logrus.Entry

func InitN3UEContext() {
	contextLog = logger.ContextLog

	n3ueContext := context.N3UESelf()

	n3ueContext.N3ueInfo = factory.N3ueConfig.Configuration.N3UEInfo
	n3ueContext.N3iwfInfo = factory.N3ueConfig.Configuration.N3IWFInfo
	n3ueContext.N3IWFRanUe = new(context.N3IWFRanUe)
	n3ueContext.N3IWFUe = new(context.N3IWFIkeUe)
	n3ueContext.N3IWFUe.N3IWFChildSecurityAssociation = make(map[uint32]*context.ChildSecurityAssociation)
	n3ueContext.N3IWFUe.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*context.ChildSecurityAssociation)
	n3ueContext.PduSessionCount = 1

	supi := n3ueContext.N3ueInfo.GetSUPI()
	contextLog.Infof("SUPI: %+v", supi)
	n3ueContext.RanUeContext = n3ue_security.NewRanUeContext(
		supi,
		1,
		security.AlgCiphering128NEA0,
		security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS,
	)
	n3ueContext.RanUeContext.AmfUeNgapId = 1
	n3ueContext.RanUeContext.AuthenticationSubs = getAuthSubscription()

	suci := buildSUCI(
		n3ueContext.N3ueInfo.BuildPLMN(),
		[]byte{0xf0, 0xff},
		0x00,
		0x00,
		n3ueContext.N3ueInfo.BuildMSIN(),
	)
	n3ueContext.MobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    uint16(len(suci)),
		Buffer: suci,
	}
	n3ueContext.IKEConnection = make(map[int]*context.UDPSocketInfo)
}

func getAuthSubscription() (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: factory.N3ueInfo.Security.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: factory.N3ueInfo.Security.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: factory.N3ueInfo.Security.OP,
		},
	}
	authSubs.AuthenticationManagementField = factory.N3ueInfo.Security.AMF

	authSubs.SequenceNumber = factory.N3ueInfo.Security.SQN
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}

func buildSUCI(
	plmn []byte,
	routingIndicator []byte,
	protectionSchemeId byte,
	HomeNetworkPublickeyId byte,
	msin []byte,
) []byte {
	var suci []byte
	suci = append(suci, 0x01) // SUCI type
	suci = append(suci, plmn...)
	suci = append(suci, routingIndicator...)
	suci = append(suci, protectionSchemeId)
	suci = append(suci, HomeNetworkPublickeyId)
	suci = append(suci, msin...)

	return suci
}

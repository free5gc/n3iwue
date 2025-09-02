package ike

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
)

var dpdLog *logrus.Entry

func init() {
	dpdLog = logger.IKELog
}

func (s *Server) StartDPD() {
	dpdLog.Tracef("Start DPD")

	n3ue := s.Context()
	dpdInterval := factory.N3ueConfig.Configuration.N3UEInfo.DpdInterval
	if dpdInterval == 0 {
		dpdLog.Tracef("DPD is disabled")
		return
	}

	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation
	if ikeSA.IKESAClosedCh != nil {
		dpdLog.Warn("DPD already started")
		return
	}

	ikeSA.IKESAClosedCh = make(chan struct{})
	ikeSA.IsUseDPD = true

	go s.dpdRoutine(n3ue, ikeSA, dpdInterval)
}

func (s *Server) StopDPD() {
	dpdLog.Tracef("Stop DPD")

	n3ue := s.Context()
	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation

	if ikeSA.IsUseDPD && ikeSA.IKESAClosedCh != nil {
		select {
		case ikeSA.IKESAClosedCh <- struct{}{}:
		default:
		}
		ikeSA.IsUseDPD = false
	}
}

func (s *Server) dpdRoutine(
	n3ue *context.N3UE,
	ikeSA *context.IKESecurityAssociation,
	interval time.Duration,
) {
	timer := time.NewTicker(interval)
	defer timer.Stop()

	for {
		select {
		case <-ikeSA.IKESAClosedCh:
			dpdLog.Tracef("DPD routine stopped")
			close(ikeSA.IKESAClosedCh)
			ikeSA.IKESAClosedCh = nil
			return
		case <-timer.C:
			dpdLog.Tracef("DPD is triggered")
			ikeSA.InitiatorMessageID++
			s.SendN3iwfInformationExchange(n3ue, nil, true, false, ikeSA.InitiatorMessageID)
		}
	}
}

package ike

import (
	"runtime/debug"
	"sync"

	"github.com/free5gc/n3iwue/internal/logger"
)

// dispatcher processes IKE events from the event channel
func (s *Server) dispatcher(wg *sync.WaitGroup) {
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			ikeLog.Fatalf("panic in dispatcher: %v\n%s", p, string(debug.Stack()))
		}
		ikeLog.Infof("IKE dispatcher stopped")
		s.serverWg.Done()
		wg.Done()
	}()

	for {
		select {
		case evt := <-s.evtCh:
			if evt == nil {
				continue
			}
			s.handleEvent(evt)
		case <-s.serverCtx.Done():
			ikeLog.Infof("IKE dispatcher stopped by server context")
			return
		}
	}
}

package main

import (
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/service"
)

func main() {
	if err := factory.Initialize(); err != nil {
		logger.CfgLog.Fatalf("%+v", err)
	}
	service.Start()
}

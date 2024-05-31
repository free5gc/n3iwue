package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var log *logrus.Logger

var (
	AppLog     *logrus.Entry
	InitLog    *logrus.Entry
	CfgLog     *logrus.Entry
	IKELog     *logrus.Entry
	NASLog     *logrus.Entry
	ContextLog *logrus.Entry
	NWuCPLog   *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	AppLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "APP"})
	InitLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "CFG"})
	ContextLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "Context"})
	IKELog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "IKE"})
	NASLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "NAS"})
	NWuCPLog = log.WithFields(logrus.Fields{"component": "N3UE", "category": "NWuCP"})
	if err := LogFileHook("n3ue.log"); err != nil {
		log.Fatalf("Hook Log File Fail:%+v", err)
	}
}

func LogFileHook(filename string) error {
	if selfLogHook, err := logger_util.NewFileHook("./"+filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666); err == nil {
		log.Hooks.Add(selfLogHook)
	} else {
		return err
	}

	return nil
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(enable bool) {
	log.SetReportCaller(enable)
}

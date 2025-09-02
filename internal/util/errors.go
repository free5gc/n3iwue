package util

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func IsConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "EOF" || strings.Contains(err.Error(), "use of closed network connection")
}

func SafeCloseConn(conn net.Conn, logger *logrus.Entry, context string) {
	if conn != nil {
		if err := conn.Close(); err != nil {
			logger.Errorf("%s: Error closing connection: %+v", context, err)
		}
	}
}

func LogAndWrapError(err error, logger *logrus.Entry, message string) error {
	if err == nil {
		return nil
	}
	logger.Errorf("%s: %+v", message, err)
	return errors.Wrap(err, message)
}

func WrapServiceError(serviceName string, err error) error {
	return errors.Wrapf(err, "%s service run failed", serviceName)
}

func ResolveUDPAddrWithLog(address string, logger *logrus.Entry) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logger.Errorf("Resolve UDP address %s failed: %+v", address, err)
		return nil, errors.Wrapf(err, "ResolveUDPAddr (%s)", address)
	}
	return addr, nil
}

func IsConnectionClosedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

package qos

import (
	"errors"

	"github.com/free5gc/ike/message"
)

type PDUQoSInfo struct {
	PduSessionID    uint8
	QfiList         []uint8
	IsDefault       bool
	IsDSCPSpecified bool
	DSCP            uint8
}

func Parse5GQoSInfoNotify(n *message.Notification) (info *PDUQoSInfo, err error) {
	info = new(PDUQoSInfo)
	var offset int = 0
	data := n.NotificationData
	dataLen := int(data[0])
	info.PduSessionID = data[1]
	qfiListLen := int(data[2])
	offset += (3 + qfiListLen)

	if offset > dataLen {
		return nil, errors.New("parse5GQoSInfoNotify err: Length and content of 5G-QoS-Info-Notify mismatch")
	}

	info.QfiList = make([]byte, qfiListLen)
	copy(info.QfiList, data[3:3+qfiListLen])

	info.IsDefault = (data[offset] & message.NotifyType5G_QOS_INFOBitDCSICheck) > 0
	info.IsDSCPSpecified = (data[offset] & message.NotifyType5G_QOS_INFOBitDSCPICheck) > 0

	return
}

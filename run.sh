#!/usr/bin/env bash

sudo -v

PID_LIST=()

function terminate()
{
    sleep 1
    sudo ip xfrm policy flush
    sudo ip xfrm state flush

    # Remove all GRE interfaces
    GREs=$(ip link show type gre | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
    for GRE in ${GREs}; do
        sudo ip link del ${GRE}
    done

    # Remove all XFRM interfaces
    XFRMIs=$(ip link show type xfrm | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
    for XFRMI in ${XFRMIs}; do
        sudo ip link del ${XFRMI}
    done

    sudo kill -SIGTERM ${PID_LIST[@]}
}

function dump()
{
    LOG_PATH=log
    mkdir -p ${LOG_PATH}
    N3UE_IPSec_iface_addr=10.0.1.2
    N3IWF_IPsec_inner_addr=10.0.0.1
    UE_DN_addr=10.60.0.1

    TCPDUMP_QUERY=" host $N3UE_IPSec_iface_addr or \
                    host $N3IWF_IPsec_inner_addr or \
                    host $UE_DN_addr"
    sudo -E tcpdump -U -i any $TCPDUMP_QUERY -w $LOG_PATH/n3ue.pcap &
    SUDO_TCPDUMP_PID=$!
    sleep 0.1
    TCPDUMP_PID=$(pgrep -P ${SUDO_TCPDUMP_PID})
    PID_LIST+=($SUDO_TCPDUMP_PID $TCPDUMP_PID)
}

dump
sleep 1

# Run N3UE
sudo ./n3iwue &
SUDO_N3UE_PID=$!
sleep 0.1
echo $N3UE_PID
N3UE_PID=$(pgrep -P ${N3UE_PID})
PID_LIST+=($SUDO_N3UE_PID $N3UE_PID)

trap terminate SIGINT
wait ${PID_LIST}
exit 0
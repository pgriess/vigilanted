# An awk(1) file to display statistics for a packet trace based on
# tshark(1) output.
#
# Expected usage is:
#
#   % tshark -V | awk -f draino.awk
#
# Output is a single line per packet seen, of the form, where the
# <timestamp> is in the native tshark format (e.g. "Jan  5, 2010
# 22:27:33.999993000"), and so goes at the end of the line to (slightly)
# ease parsing.
#
#   <src MAC>/<src IP>:<src port> <dst MAC>/<dst IP>:<dst port> <pkt sz> <tcpSeq> <tcpAck> <tcpLen> <timestamp>

# Frame 1 (1514 bytes on wire, 1514 bytes captured)
/^Frame [[:digit:]]+/ {
    # If we have a valid record, print it out
    if (time != "" &&
        srcMac != "" && srcIp != "" && srcPort != "" &&
        dstMac != "" && dstIp != "" && dstPort != "")
        printf("%s/%s:%s %s/%s:%s %d %d %d %d %s\n", srcMac, srcIp, srcPort, dstMac, dstIp, dstPort, pktLen, tcpSeq, tcpAck, tcpLen, time)
        fflush()

    pktLen = substr($3, 2, length($3) - 1)
    srcMac = srcIp = srcPort = ""
    dstMac = dstIp = dstPort = ""
    tcpSeq = tcpAck = tcpLen = ""
}

/^    Arrival Time: / {
    time = substr($0, 19, length($0) - 18)
}

# Internet Protocol, Src: 84.75.218.87 (84.75.218.87), Dst: 172.26.1.192 (172.26.1.192)
/^Internet Protocol, Src: / {
    srcIp = $4
    dstIp = $7
}

# Ethernet II, Src: HewlettP_3e:af:93 (00:08:02:3e:af:93), Dst: Apple_03:44:53 (00:26:bb:03:44:53)
/^Ethernet II, Src: / {
    srcMac = substr($5, 2, length($5) - 3)
    dstMac = substr($8, 2, length($8) - 2)
}

# Transmission Control Protocol, Src Port: http (80), Dst Port: 60823 (60823), Seq: 1, Ack: 1, Len: 1448
/^Transmission Control Protocol, Src Port: / {
    srcPort = substr($7, 2, length($7) - 3)
    dstPort = substr($11, 2, length($11) - 3)
    tcpSeq = substr($13, 1, length($13) - 1)
    tcpAck = substr($15, 1, length($15) - 1)
    tcpLen = $17
}

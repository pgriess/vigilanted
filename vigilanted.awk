# An gawk(1) file to display statistics for a packet trace based on
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
#   <src MAC>/<src IP>:<src port> <dst MAC>/<dst IP>:<dst port> <pkt sz> <timestamp>
#
# The basic flow of this script is to note interesting fields by line
# signature (e.g. 'Source port') and make sure it's in the right section
# (the most recent line without any indentation). We accumulate values in
# variables, and print them out when we see a new frame.

/^Frame [[:digit:]]+/ {
    # If we have a valid record, print it out
    if (time != "" &&
        srcMac != "" && srcIp != "" && srcPort != "" &&
        dstMac != "" && dstIp != "" && dstPort != "")
        printf("%s/%s:%s %s/%s:%s %d %s\n", srcMac, srcIp, srcPort, dstMac, dstIp, dstPort, pktLen, time)

    srcMac = srcIp = srcPort = ""
    dstMac = dstIp = dstPort = ""
}

# Match the section name of any given packet. Use this to disambiguate
# between fields which may exist in multiple sections.
/^[[:alnum:]]+ / {
    sectionName = $1
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

# Frame Length: 125123
/^    Frame Length: / {
    pktLen = $3
}

# Source port: http (80)
/^    Source port: / {
    if (sectionName != "Transmission")
        next

    srcPort = substr($4, 2, length($4) - 2)
}

# Destination port: http (80)
/^    Destination port: / {
    if (sectionName != "Transmission")
        next

    dstPort = substr($4, 2, length($4) - 2)
}

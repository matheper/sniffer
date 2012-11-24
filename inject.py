import pycap.constants, pycap.protocol, pycap.inject
data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ethernet = pycap.protocol.ethernet(type=pycap.constants.ethernet.ETHERTYPE_IP,
                                    source='00:03:93:44:a9:92',
                                    destination='00:50:ba:8f:c4:5f')
ip = pycap.protocol.ip(version=4,
                        length=pycap.constants.ip.HEADER_LENGTH + pycap.constants.icmp.ECHO_HEADER_LENGTH + len(data),
                        id=1,
                        offset=0,
                        ttl=100,
                        protocol=pycap.constants.ip.IPPROTO_ICMP,
                        checksum=0,
                        source="192.168.1.106",
                        destination="192.168.1.104")
icmp = pycap.protocol.icmpEchoRequest(0, 0, 1, 0)
packet = (ethernet, ip, icmp, data)
print packet
pycap.inject.inject().inject(packet)

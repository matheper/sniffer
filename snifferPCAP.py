# -*- coding: utf8 -*-
import pcapy
import dpkt
import impacket.ImpactDecoder

class Sniffer( ):
    """Sniffer class."""

    def __init__(self):

        self.capture_list = []

        self.extension_header = {
            0:"Hop-By-Hop Options Extension Header (note that this value was “Reserved” in IPv4)",
            1:"ICMPv4",
            2:"IGMPv4",
            4:"IP in IP Encapsulation",
            6:"TCP",
            8:"EGP",
            17:"UDP",
            41:"IPv6",
            43:"Routing Extension Header",
            44:"Fragmentation Extension Header",
            46:"Resource Reservation Protocol (RSVP)",
            50:"Encrypted Security Payload (ESP) Extension Header",
            51:"Authentication Header (AH) Extension Header",
            58:"ICMPv6",
            59:"No Next Header",
            60:"Destination Options Extension Header"
        }

        self.traffic_dict = {
            0 : "Nenhum tráfego específico",
            1 : "Dados de segundo plano",
            2 : "Tráfego de dados não atendido",
            3 : "Reservado",
            4 : "Tráfego de dados pesado atendido",
            5 : "Reservado",
            6 : "Tráfego interativo",
            7 : "Tráfego de controle",
        }


    def ip_addr(self, addr):
        """Format ipv6 address."""
        import ipdb;ipdb.set_trace()
        ip_address = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]))
        return ip_address


    def next_header_type(self, nxt):
        """Retuns label for next header code."""
        if self.extension_header.has_key(nxt):
            return (nxt,self.extension_header[nxt])
        return (nxt,'')


    def traffic_class_type(self, t_class):
        """Returns label for traffic class code."""
        if t_class >= 0 and t_class <= 7:
            return (t_class, "Tráfego controlado por congestionamento", self.traffic_dict[t_class])
        elif t_class <= 15:
            return (t_class, "Tráfego não controlado por congestionamento", "")
        return False;


    def recv_packets(self, header, data):
        """Decodes packet."""
        packet = impacket.ImpactDecoder.EthDecoder().decode(data)
        eth = dpkt.ethernet.Ethernet(data)
        ip = eth.data
        dst = self.ip_addr(ip.dst)
        src = self.ip_addr(ip.src)
        next_header = self.next_header_type(ip.nxt)
        hop_limit = ip.hlim
        traffic_class = self.traffic_class_type(ip.fc)
#        print packet
#        print dst, src, next_header, hop_limit, traffic_class, "\n\n"
        self.capture_list.append((src, dst, next_header[0], next_header[1], hop_limit,
                                  traffic_class[0], traffic_class[1], traffic_class[2]))
        print self.capture_list, "\n\n\n"


    def configure_device(self):
        pcapy.findalldevs()
        dev = pcapy.findalldevs()[1]
        self.cap = pcapy.open_live(dev , 65536 , 1 , 0)
        self.cap.setfilter('ip6')


    def get_next_packet(self):
        (header, data) = self.cap.next()
        self.recv_packets(header, data)


    def capture(self):
        self.configure_device()
        while 1:
            (header, data) = self.cap.next()
            self.recv_packets(header, data)

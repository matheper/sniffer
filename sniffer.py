# -*- coding: utf8 -*-
from scapy import all
import netaddr


class Sniffer():
    """Sniffer class."""

    def __init__(self):
        self.capture_list = []
        self.capture_dict = []
        
        self.extension_header = {
            0:"Hop-By-Hop Options Extension Header",
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
            47:"GRE",
            50:"Encrypted Security Payload (ESP) Extension Header",
            51:"Authentication Header (AH) Extension Header",
            58:"ICMPv6",
            59:"No Next Header",
            60:"Destination Options Extension Header",
            135:"Mobility Header"
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
        return False


    def analyze(self, packet):
        pack_dict = {}
        pack_dict['mac_src'] = packet.src
        pack_dict['mac_dst'] = packet.dst
        ip = packet.payload
        pack_dict['ip_src'] = ip.src
        pack_dict['ip_src_type'] = netaddr.IPAddress(ip.src).info['IPv6'][0]['allocation']
        pack_dict['ip_dst'] = ip.dst
        pack_dict['ip_dst_type'] = netaddr.IPAddress(ip.dst).info['IPv6'][0]['allocation']
        pack_dict['ip_dst'] = ip.dst
        pack_dict['hop_limit'] = ip.hlim
        pack_dict['traffic_class'] = self.traffic_class_type(ip.tc)
        pack_dict['flowlabel'] = ip.fl
        pack_dict['version'] = ip.version

        current = ip
        next_header_list = []
        while hasattr(current, 'nh'):
            next_header_list.append(self.next_header_type(current.nh))
            current = current.payload
        pack_dict['next_header'] = next_header_list

        self.capture_dict.append(pack_dict)

        pack_tuple  = ( pack_dict['ip_src'], pack_dict['ip_src_type'], pack_dict['ip_dst'],
                        pack_dict['ip_dst_type'], pack_dict['next_header'],
                        pack_dict['hop_limit'], pack_dict['traffic_class'][0],
                        pack_dict['traffic_class'][1], pack_dict['traffic_class'][2],
                        pack_dict['flowlabel'], pack_dict['version']
                      )

        self.capture_list.append(pack_tuple)


    def get_packet(self, sniff_filter = 'ip6'):
        capture = all.sniff(filter = sniff_filter, count = 1)
        packet = capture[0]
        self.analyze(packet)


    def read_file(self, filename):
        capture = all.rdpcap(filename)
        for packet in capture:
            self.analyze(packet)


    def get_flow_packets(self, flowlabel):
        flow_packets = []
        flow_packets[:] = filter(lambda x: x[9] == flowlabel, self.capture_list)
        return flow_packets


    def parse_filter(src = '', operador = ''):
        filtered_list = []
        if src and dst:
            ip_src = netaddr.IPAddress(src)
            ip_dst = netaddr.IPAddress(dst)
            filtered_list[:] = filter(lambda x: x[])


#    def get_capture_list(self):
#        return ( pack_dict['mac_src'], pack_dict['mac_dst'], pack_dict['ip_src'],
#                 pack_dict['ip_dst'], pack_dict['next_header'], pack_dict['hop_limit'],
#                 pack_dict['traffic_class'], pack_dict['flowlabel'], pack_dict['version']
#               )


    def filter(self, sniff_filter):
        pass

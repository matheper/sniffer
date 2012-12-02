# -*- coding: utf8 -*-
from scapy import all
import netaddr


INDEX = 0
VALUE = ''

class Sniffer():
    """Sniffer class."""

    def __init__(self):
        """ Defini dicionarios para proximo cabecalho e classe de trafego."""
        self.capture_list = []
        self.filtered_list = []
        self.capture_dict = []
        self.flowlabel_dict = {}
        self.mean_next_header = 0
        self.icmpv6_number = 0

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
        """ Faz a analise do pacote e insere as informacoes
            no dict capture_dict e na lista capture_list."""
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
        """ Captura e analisa 1 pacote."""
        capture = all.sniff(filter = sniff_filter, count = 1)
        packet = capture[0]
        self.analyze(packet)


    def read_file(self, filename):
        """ Le arquivo compativel com wireshark (.cap) e faz analise dos pacote"""
        capture = all.rdpcap(filename)
        for packet in capture:
            self.analyze(packet)


    def list_filter(self, side, oper, value):
        """ Side pode ser 'origem', 'destino' ou 'flowlabel'.
            Prepara filtered_list utilizada na funcao capture_filter."""
        VALUE = value
        if side.lower() == 'origem':
            INDEX = 0
        elif side.lower() == 'destino':
            INDEX = 2
        elif side.lower() == 'flowlabel':
            INDEX = 9
            self.filtered_list[:] = filter(lambda x: x[INDEX] == int(VALUE), self.filtered_list)
            return True
        else:
            return False
        if oper == '<':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) < netaddr.IPAddress(VALUE), self.filtered_list)
        elif oper == '<=':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) <= netaddr.IPAddress(VALUE), self.filtered_list)
        elif oper == '>':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) > netaddr.IPAddress(VALUE), self.filtered_list)
        elif oper == '>=':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) >= netaddr.IPAddress(VALUE), self.filtered_list)
        elif oper == '==':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) == netaddr.IPAddress(VALUE), self.filtered_list)
        elif oper == '!=':
            self.filtered_list[:] = filter(lambda x: netaddr.IPAddress(x[INDEX]) != netaddr.IPAddress(VALUE), self.filtered_list)
        return True

    def capture_filter(self, expression):
        """ Recebe uma lista de expressoes separadas por virgula,
            Faz split e executa filtro com 'E' logico.
            Returna lista filtrada."""
        self.filtered_list = self.capture_list[:]
        expression = expression.split('; ')
        for operation in expression:
            opers = operation.split(' ')
            if len(opers) == 3:
                self.list_filter(opers[0], opers[1], opers[2])
        return self.filtered_list

    def set_flowlabel_list(self):
        """ Cria dicionario com pacotes do mesmo fluxo para
            o mesmo ip destino e ip origem."""
        for packet in self.capture_dict:
            src = packet['ip_src']
            dst = packet['ip_dst']
            flowlabel = packet['flowlabel']
            self.flowlabel_dict[(src, dst, flowlabel)] = []
        for packet in self.capture_dict:
            src = packet['ip_src']
            dst = packet['ip_dst']
            flowlabel = packet['flowlabel']
            self.flowlabel_dict[(src, dst, flowlabel)].append(packet)

    def set_mean_next_header(self):
        """ Cria media do numero de pacotes de proximo cabecalho."""
        total = 0.0
        for packet in self.capture_dict:
            total += len(packet['next_header'])
        self.mean_next_header = total / len(self.capture_dict)


    def counts_icmpv6(self):
        """Contabiliza numero de pacotes ICMPv6 da captura."""
        import ipdb;ipdb.set_trace()
        self.icmpv6_number = 0
        for packet in self.capture_dict:
            if (58,'ICMPv6') in packet['next_header']:
                self.icmpv6_number += 1

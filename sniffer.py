# -*- coding: utf8 -*-
import pcapy
import dpkt
import impacket.ImpactDecoder


def ip_addr(addr):
    ip_address = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]) , ord(addr[1]) , ord(addr[2]), ord(addr[3]), ord(addr[4]) , ord(addr[5]))
    return ip_address


def next_header_type(nxt):
    extension_header = {
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
    return (nxt,extension_header[nxt])


def traffic_class_type(t_class):
    traffic_dict = {
        0 : "Nenhum tráfego específico",
        1 : "Dados de segundo plano",
        2 : "Tráfego de dados não atendido",
        3 : "Reservado",
        4 : "Tráfego de dados pesado atendido",
        5 : "Reservado",
        6 : "Tráfego interativo",
        7 : "Tráfego de controle",
    }
    if t_class >= 0 and t_class <= 7:
        return (t_class, "Tráfego controlado por congestionamento", traffic_dict[t_class])
    elif t_class <= 15:
        return (t_class, "Tráfego não controlado por congestionamento", "")
    return False;


def recv_packets(header, data):
    packet = impacket.ImpactDecoder.EthDecoder().decode(data)
    print packet
    eth = dpkt.ethernet.Ethernet(data)
    ip = eth.data
    dst = ip_addr(ip.dst)
    src = ip_addr(ip.src)
    next_header = next_header_type(ip.nxt)
    hop_limit = ip.hlim
    traffic_class = traffic_class_type(ip.fc)
    print dst, src, next_header, hop_limit, traffic_class, "\n\n"

pcapy.findalldevs()
br0 = pcapy.findalldevs()[1]
 
max_bytes = 1024
promiscous = False
read_timeout = 100 # millisecond
pc = pcapy.open_live(br0,max_bytes,promiscous,read_timeout)
cap = pcapy.open_live(br0 , 65536 , 1 , 0)
cap.setfilter('ip6')

pc.setfilter('ip6')
max_packets = -1 # -1 means no limit

while 1:
    (header, data) = cap.next()
    recv_packets(header, data)
#pc.loop(-1, recv_packets)

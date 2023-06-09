import socket
import struct
import textwrap
import time
import binascii

'''
Ethernet frame
DA [Destination MAC Address] : 6 bytes
SA [Source MAC Address] : 6 bytes
Type [0x8870 (Ethertype)] : 2 bytes
'''
class Ethernet:
    def __init__(self, r_data):
        dest, src, proto = struct.unpack('!6s6sH', r_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = proto
        self.data = r_data[14:]


class ARP:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! H H B B H 6s L 6s L", r_data[:28])
        self.hardware_type = tmp[0]
        self.protocol_type = tmp[1]
        self.hardware_addr_len = tmp[2]
        self.protocol_addr_len = tmp[3]
        self.opcode = tmp[4]
        self.sender_hardware_address = get_mac_addr(tmp[5])
        self.sender_protocol_addr = socket.inet_ntoa(struct.pack(">I", tmp[6]))
        self.target_hardware_address = get_mac_addr(tmp[7])
        self.target_protocol_addr = socket.inet_ntoa(struct.pack(">I", tmp[8]))
        self.data = r_data[28:]


class ICMP:
    #identifier & sequence number
    def __init__(self, r_data):
        self.icmp_type, self.code, self.checksum, self.id, self.sequence = struct.unpack('! B B H H H', r_data[:8])
        self.data = r_data[8:]


class IPv4:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! B B H H H B B H L L", r_data[:20])
        version_header_length = tmp[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.tos = tmp[1]  # type of service
        self.total_length = tmp[2]
        self.ID = tmp[3]
        ff = tmp[4]
        self.Rb = (ff & 0x8000) >> 15
        self.MF = (ff & 0x3FFF) >> 13
        self.DF = (ff & 0x7FFF) >> 14
        self.fragment_Offset = (ff & 0x1FFF)
        self.ttl = tmp[5]
        self.protocol = tmp[6]
        self.header_checksum = tmp[7]

        self.source_address = socket.inet_ntoa(struct.pack(">I", tmp[8]))
        self.destination_address = socket.inet_ntoa(struct.pack(">I", tmp[9]))
        self.options = []
        if self.header_length > 20:
            self.options = r_data[20:self.header_length]
        self.data = r_data[self.header_length:]


class IPv6:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! L 2s s s", r_data[:8])
        version_traffic_flow = tmp[0]
        self.flow_label = version_traffic_flow & 0xFFFFF
        version_traffic = version_traffic_flow >> 20
        self.version = version_traffic >> 8
        self.traffic_class = version_traffic & 0xFF
        self.payload_length = tmp[1]
        self.next_header = tmp[2]
        self.hop_limit = tmp[3]

        self.source_address = socket.inet_ntop(socket.AF_INET6,r_data[8:24])
        self.destination_address = socket.inet_ntop(socket.AF_INET6,r_data[24:40])
        self.data = r_data[40:]


class TCP:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack('! H H L L H H H H', r_data[:20])
        self.src_port = tmp[0]
        self.dest_port = tmp[1]
        self.sequence = tmp[2]
        self.acknowledgment = tmp[3]
        offset_reserved_flag = tmp[4]
        self.window = tmp[5]
        self.checksum = tmp[6]
        self.urgent = tmp[7]
        self.offset = (offset_reserved_flag >> 12) * 4  # offset is header_length = row count * 32 / 8
        self.Reserved = (offset_reserved_flag & 0xE00) >> 9
        self.NS = (offset_reserved_flag & 256) >> 8
        self.CWR = (offset_reserved_flag & 128) >> 7
        self.ECE = (offset_reserved_flag & 64) >> 6
        self.URG = (offset_reserved_flag & 32) >> 5
        self.ACK = (offset_reserved_flag & 16) >> 4
        self.PSH = (offset_reserved_flag & 8) >> 3
        self.RST = (offset_reserved_flag & 4) >> 2
        self.SYN = (offset_reserved_flag & 2) >> 1
        self.FIN = (offset_reserved_flag & 1)
        self.options = []
        if self.offset > 20:
            self.options = r_data[20:self.offset]
        self.data = r_data[self.offset:]


class UDP:
    def __init__(self, r_data):
        self.src_port, self.dest_port, self.length, self.checksum = struct.unpack('! H H H H', r_data[:8])
        self.data = r_data[8:]

class HTTP:
    def __init__(self, r_data):
        try:
            self.data = r_data.decode('utf-8')
        except:
            self.data = r_data


class DNS:
    def __init__(self, r_data):
        self.id, flags_codes, self.question_count, self.answer_count, self.name_server_count, self.additional_record_count = struct.unpack(
            "! 6H", r_data[:12])
        self.Rcode = flags_codes & 15
        flags_codes = flags_codes >> 4
        self.CD = (flags_codes & 1)
        self.AD = (flags_codes & 2) >> 1
        self.Z = (flags_codes & 4) >> 2
        self.RA = (flags_codes & 8) >> 3
        self.RD = (flags_codes & 16) >> 4
        self.TC = (flags_codes & 32) >> 5
        self.AA = (flags_codes & 64) >> 6
        flags_codes = flags_codes >> 7
        self.opcode = flags_codes & 15
        self.QR = flags_codes >> 4

        self.data = r_data[12:]


    #DNS details
    def dns_details(self):
        data = self.data
        self.Queries = []
        try:
            if self.question_count > 0:
                    for i in range(self.question_count):
                        st = ""
                        while True:
                            n = struct.unpack('!B', data[:1])
                            data = data[1:]
                            if n[0] == 0:
                                break
                            p = struct.unpack('!' + str(n[0]) + 's', data[:n[0]])
                            tmp = struct.unpack('!' + str(n[0]) + 'B', p[0])
                            st += ''.join([chr(i) for i in tmp]) + '.'
                            data = data[n[0]:]

                        name = st[:-1]
                        type, clas = struct.unpack('!HH', data[:4])
                        data = data[4:]

                        dic = {}
                        dic['Name'] = name
                        dic['Type'] = type
                        dic['Class'] = clas
                        self.Queries.append(dic)
        except:
            self.Queries = data[4:]


        self.Answers = []
        try:
            if self.answer_count > 0:

                for i in range(self.answer_count):
                    name = data[:2]
                    type, clas, ttl, datalength = struct.unpack('! H H L H', data[2:12])
                    data = data[12:]
                    Cname = data[:datalength]
                    data = data[datalength:]

                    dic = {}
                    dic['Name'] = name
                    dic['Type'] = type
                    dic['Class'] = clas
                    dic['TTL'] = ttl
                    dic['Data length'] = datalength

                    if type == 1:  # IPv4
                        dic['Type'] = 'A (Host Address) (1)'
                        dic['Address'] = socket.inet_ntoa(Cname)

                    elif type == 28:  # IPv6
                        dic['Type'] = 'AAAA (IPv6 Address) (28)'
                        dic['Address'] = socket.inet_ntop(socket.AF_INET6,Cname)

                    elif type == 5:  # CNAME
                        dic['Type'] = 'CNAME (5)'

                        cn = ""
                        while True:
                            n = struct.unpack('!B', Cname[:1])
                            Cname = Cname[1:]
                            if n[0] > len(Cname):
                                break
                            if n[0] == 0:
                                break
                            p = struct.unpack('!' + str(n[0]) + 's', Cname[:n[0]])
                            tmp = struct.unpack('!' + str(n[0]) + 'B', p[0])
                            cn += ''.join([chr(i) for i in tmp]) + '.'
                            Cname = Cname[n[0]:]

                        dic['CNAME'] = cn[:-1]
                    else:  # Other types
                        dic['Type'] = type

                        cn = ""
                        while True:
                            n = struct.unpack('!B', Cname[:1])
                            Cname = Cname[1:]
                            if n[0] > len(Cname):
                                break
                            if n[0] == 0:
                                break
                            p = struct.unpack('!' + str(n[0]) + 's', Cname[:n[0]])
                            tmp = struct.unpack('!' + str(n[0]) + 'B', p[0])
                            cn += ''.join([chr(i) for i in tmp]) + '.'
                            Cname = Cname[n[0]:]

                        dic['CNAME'] = cn[:-1]

                    self.Answers.append(dic)
        except:
            self.Answers = data


        self.Authoritative = []
        try:
            if self.name_server_count > 0:

                for i in range(self.name_server_count):

                    name = data[:2]
                    type, clas, ttl, datalength = struct.unpack('! H H L H', data[2:12])
                    data = data[12:]
                    info = data[: datalength]
                    data = data[datalength:]

                    primary_responsible = info[:-20]
                    info2 = info[-20:]

                    primary = ""
                    while True:
                        n = struct.unpack('!B', primary_responsible[:1])
                        primary_responsible = primary_responsible[1:]
                        if n[0] > len(primary_responsible):
                            break
                        if n[0] == 0:
                            break
                        p = struct.unpack('!' + str(n[0]) + 's', primary_responsible[:n[0]])
                        tmp = struct.unpack('!' + str(n[0]) + 'B', p[0])
                        primary += ''.join([chr(i) for i in tmp]) + '.'
                        primary_responsible = primary_responsible[n[0]:]

                    responsible = ""

                    while len(primary_responsible) > 0:
                        n = struct.unpack('!B', primary_responsible[:1])
                        primary_responsible = primary_responsible[1:]

                        if n[0] > len(primary_responsible):
                            break
                        p = struct.unpack('!' + str(n[0]) + 's', primary_responsible[:n[0]])
                        tmp = struct.unpack('!' + str(n[0]) + 'B', p[0])
                        responsible += ''.join([chr(i) for i in tmp]) + '.'
                        primary_responsible = primary_responsible[n[0]:]

                    Serialnumber, Refreshinterval, Retryinterval, Expirelimit, MinimumTTL = struct.unpack('!5L', info2[:20])

                    dic = {}
                    dic['Name'] = name
                    dic['Type'] = type
                    dic['Class'] = clas
                    dic['TTL'] = ttl
                    dic['Data length'] = datalength
                    dic['Primary name server'] = ''
                    dic['Responsible authoritys mailbox'] = ''
                    dic['Serial number'] = Serialnumber
                    dic['Refresh interval'] = Refreshinterval
                    dic['Retry interval'] = Retryinterval
                    dic['Expire limit'] = Expirelimit
                    dic['Minimum TTL'] = MinimumTTL

                    self.Authoritative.append(dic)
        except:
            self.Authoritative = data


        self.Additinal = []
        try:
            if self.additional_record_count > 0:

                for i in range(self.additional_record_count):
                    name, type, payload, higher, version, Z, datalength = struct.unpack('!B H H B B H H', data)

                    dic = {}
                    dic['Name'] = name
                    dic['Type'] = type
                    dic['UDP payload size'] = payload
                    dic['Higher bits in extended RCODE'] = higher
                    dic['Version'] = version
                    dic['Z'] = Z
                    dic['Data length'] = datalength
                    data = data[11:]
                    self.Additinal.append(dic)
                    #end of DNS details
        except:
            self.additional_record_count = data[11:]

    # print DNS details
    def print_details(self):
        print()
        try:
            if self.question_count > 0:

                print("\t\t - Queries:")

                for i in range(self.question_count):
                    print('\t\t\t - ' + 'Name: {}, Type: {}, Class: {}'.format(self.Queries[i]['Name'], self.Queries[i]['Type'],
                                                                               self.Queries[i]['Class']))
        except:
            print(self.Queries)

        try:
            if self.answer_count > 0:

                print("\t\t - Answers:")

                for i in range(self.answer_count):
                    if self.Answers[i]['Type'] == 'A (Host Address) (1)' or self.Answers[i]['Type'] == 'AAAA (IPv6 Address) (28)':
                        print(
                            '\t\t\t - ' + 'Name: {}, Type: {}, Class: {}, Time tp live: {}, Data length: {}, Address: {}'.format(
                                self.Answers[i]['Name'], self.Answers[i]['Type'],
                                self.Answers[i]['Class'], self.Answers[i]['TTL'], self.Answers[i]['Data length'],
                                self.Answers[i]['Address']))

                    elif self.Answers[i]['Type'] == 'CNAME (5)':
                        print(
                            '\t\t\t - ' + 'Name: {}, Type: {}, Class: {}, Time tp live: {}, Data length: {}, CNAME: {}'.format(
                                self.Answers[i]['Name'], self.Answers[i]['Type'],
                                self.Answers[i]['Class'], self.Answers[i]['TTL'], self.Answers[i]['Data length'],
                                self.Answers[i]['CNAME']))
                    else:
                        print(
                            '\t\t\t - ' + 'Name: {}, Type: {}, Class: {}, Time tp live: {}, Data length: {}, CNAME: {}'.format(
                                self.Answers['Name'], self.Answers[i]['Type'],
                                self.Answers['Class'], self.Answers[i]['TTL'], self.Answers[i]['Data length'],
                                self.Answers['CNAME']))
        except:
            print(self.Answers)

        try:
            if self.name_server_count > 0:

                print("\t\t - Authoritative nameservers:")
                auth = self.Authoritative
                for i in range(self.name_server_count):
                    print('\t\t\t - ' + 'Name: {}, Type: {}, Class: {}'.format(auth[i]['Name'], auth[i]['Type'],
                                                                               auth[i]['Class']))
                    print('\t\t\t - ' + 'Time to live: {}, Data length: {}'.format(auth[i]['TTL'],
                                                                                   auth[i]['Data length']))
                    print('\t\t\t - ' + 'Primary name server: {}'.format(auth[i]['Primary name server']))
                    print('\t\t\t - ' + 'Responsible authoritys mailbox: {}'.format(
                        auth[i]['Responsible authoritys mailbox']))

                    print('\t\t\t - ' + 'Serial number: {}'.format(auth[i]['Serial number']))
                    print('\t\t\t - ' + 'Refresh interval: {}'.format(auth[i]['Refresh interval']))
                    print('\t\t\t - ' + 'Retry interval: {}'.format(auth[i]['Retry interval']))
                    print('\t\t\t - ' + 'Expire limit: {}'.format(auth[i]['Expire limit']))
                    print('\t\t\t - ' + 'Minimum TTL: {}'.format(auth[i]['Minimum TTL']))
        except:
            print(self.Authoritative)

        try:
            if self.additional_record_count > 0:

                print("\t\t - Additional records:")

                for i in range(self.additional_record_count):
                    print('\t\t\t - ' + 'Name: {}, Type: {}, UDP payload size: {}'.format(self.Additinal[i]['Name'],
                                                                                          self.Additinal[i]['Type'],
                                                                                          self.Additinal[i]['UDP payload size']))
                    print('\t\t\t - ' + 'Higher bits in extended RCODE: {}, Version: {}'.format(
                        self.Additinal[i]['Higher bits in extended RCODE'], self.Additinal[i]['Version']))
                    print('\t\t\t - ' + 'Z: {}, Data length: {}'.format(self.Additinal[i]['Z'], self.Additinal[i]['Data length']))
        except:
            print(self.Additinal)


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str)
    return mac_addr


def print_data(tab, string):
    size = 80 - len(tab)
    string = ''.join(r'\x{:02x}'.format(byte) for byte in string)

    return '\n'.join([tab + line for line in textwrap.wrap(string, size)])


# Pcap_header_format = '@ I H H i I I I '
# Global Header Values
PCAP_MAGICAL_NUMBER = 0xa1b2c3d4
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

class Pcap:

    def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER,
                                         PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))


    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


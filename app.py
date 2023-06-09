from Headers import *

#====================================== main ===================================
if __name__=='__main__':

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        s = input('URL : ')
        pcap = Pcap(s)
        while True:

            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)
            eth = Ethernet(raw_data)

            print('\n\n' + "="*100 + '\n')

            print(f' Ethernet Frame: \t\t\t\t\t\t {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}')

            if (eth.proto == 0x0806):
                ether_type = 'ARP (0x0806)'
            elif (eth.proto == 0x800):
                ether_type = 'IPv4 (0x0800)'
            elif (eth.proto == 0x86DD):
                ether_type = 'IPv6 (0x086DD)'
            else:
                ether_type = hex(eth.proto)

            print('\t - ' + 'Destination: {}, Source: {}, Type: {}'.format(eth.dest_mac, eth.src_mac, ether_type))

            if eth.proto == 0x800:  # IP/IPV4
                proto = 'Other'
                ipv4 = IPv4(eth.data)
                if ipv4.protocol == 1:
                    proto = 'ICMP'
                if ipv4.protocol == 6:
                    proto = 'TCP'
                if ipv4.protocol == 17:
                    proto = 'UDP'

                print('\t - ' + "Internet Protocol Version 4:")
                h_len = str(ipv4.header_length) + ' bytes (' + str(int(ipv4.header_length / 4)) + ')'
                print('\t\t - ' + 'Version: {}, Header Length: {}, Type Of Service: {}, Total Lenght: {}'.format(
                    ipv4.version, h_len, ipv4.tos, ipv4.total_length))
                print('\t\t - ' + 'Identification: {} ({})'.format(hex(ipv4.ID), ipv4.ID))
                print('\t\t - ' + 'Flags:')
                print('\t\t\t - ' + 'Reserved bit: {}, Dont Fragment: {}, More Fragment: {}'.format(
                    ipv4.Rb, ipv4.DF, ipv4.MF))
                print('\t\t - '+'Fragment Offset: {}', ipv4.fragment_Offset)
                print('\t\t - ' + 'Time to live: {}, Protocol: {} ({}), Header checksum: {}'.format(ipv4.ttl, proto,
                                                                                                    ipv4.protocol,
                                                                                                    ipv4.header_checksum))
                print('\t\t - ' + 'Source address: {}'.format(ipv4.source_address))
                print('\t\t - ' + 'Destination address: {}'.format(ipv4.destination_address))

                print('\t\t - ' + 'Options: {}'.format(ipv4.options))

                # ICMP
                if ipv4.protocol == 1:
                    icmp = ICMP(ipv4.data)

                    print('\t - ' + 'Intenet Control Message Protocol:')
                    print('\t\t - ' + 'Type: {}, Code: {}, Checksum: {}'.format(icmp.icmp_type, icmp.code, icmp.checksum))
                    print('\t\t - ' + 'Identifier: {}, Sequence number: {}'.format(icmp.id, icmp.sequence))
                    print('\t\t - ' + 'Data:')
                    print(print_data('\t\t\t   ', icmp.data))

                # TCP
                elif ipv4.protocol == 6:
                    tcp = TCP(ipv4.data)

                    print('\t - ' + 'Transmission Control Protocol:')
                    print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                    print('\t\t - ' + 'Sequence number: {}, Acknowledgment number: {}'.format(tcp.sequence,tcp.acknowledgment))
                    h_len = str(tcp.offset) + ' bytes (' + str(int(tcp.offset / 4)) + ')'
                    print('\t\t - ' + 'Header Length: {}'.format(h_len))
                    print('\t\t - ' + 'Flags:')
                    print('\t\t\t - ' + 'Reserved: {}, NS: {}, CWR: {}'.format(tcp.Reserved, tcp.NS, tcp.CWR))
                    print('\t\t\t - ' + 'ECE: {}, URG: {}, ACK: {}, PSH: {}'.format(tcp.ECE, tcp.URG, tcp.ACK, tcp.PSH))
                    print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN: {}'.format(tcp.RST, tcp.SYN, tcp.FIN))
                    print('\t\t - ' + 'Window sizr: {}, Checksum: {}'.format(tcp.window, tcp.checksum))
                    print('\t\t - ' + 'Urgent pointer: {}, Options: {}'.format(tcp.urgent, tcp.options))

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print('\t\t - ' + 'Hypertext Transfer Protocol:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print('\t\t\t   ' + str(line))
                        except:
                            print(print_data('\t\t\t   ', tcp.data))

                    # DNS
                    elif tcp.src_port == 53 or tcp.dest_port == 53:
                        try:
                            dns = DNS(tcp.data)
                            print('\t - ' + 'Domain Name System:')
                            print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                            print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                dns.AA, dns.TC, dns.RD, dns.RA))

                            print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA, dns.Z, dns.AD))
                            print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD, dns.Rcode))
                            print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                                dns.question_count, dns.answer_count, dns.name_server_count, dns.additional_record_count))
                            dns.dns_details()
                            dns.print_details()
                        except:
                            print(tcp.data)

                    else:
                        print('\t\t - ' + 'TCP Data:')
                        #print(print_data('\t\t\t   ', tcp.data))   # uncomment to print tcp data
                # UDP
                elif ipv4.protocol == 17:
                    udp = UDP(ipv4.data)

                    print('\t - ' + 'User Datagram Protocol:')
                    print('\t\t - ' + 'Source Port: {}, Destination Port: {}, Length: {},Checksum: {}'.format(udp.src_port,
                                                                                                              udp.dest_port,
                                                                                                              udp.length,
                                                                                                              udp.checksum))
                    # DNS
                    if udp.src_port == 53 or udp.dest_port == 53:
                        dns = DNS(udp.data)
                        print('\t - ' + 'Domain Name System:')
                        print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                        print('\t\t - ' + 'Flags:')
                        print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                        print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                dns.AA, dns.TC, dns.RD, dns.RA))

                        print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA,dns.Z,dns.AD))
                        print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD,dns.Rcode))
                        print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                                dns.question_count,dns.answer_count,dns.name_server_count,dns.additional_record_count))
                        dns.dns_details()
                        dns.print_details()

                    else:
                        print('\t\t - ' + 'UDP Data:')
                        #print(print_data('\t\t\t   ', udp.data))   # uncomment to print udp data

                else:
                    print('\t - ' + 'Other IPv4 Data:')
                    print(print_data('\t\t   ', ipv4.data))

            # IP/IPV6
            elif eth.proto == 0x86DD:
                ipv6 = IPv6(eth.data)

                print('\t - ' + "Internet Protocol Version 6:")
                print('\t\t - ' + 'Version: {}, Traffic Class: {}, Flow Label: {}'.format(ipv6.version,ipv6.traffic_class,
                                                                                                               ipv6.flow_label))
                print('\t\t - ' + 'Payload length: {}, Next header: {}, Hop limit: {}'.format(ipv6.payload_length,
                                                                                       ipv6.next_header,ipv6.hop_limit))
                print('\t\t - ' + 'Source address: {}, Destination address: {}'.format(ipv6.source_address,
                                                                                                      ipv6.destination_address))

                # ICMPv6
                if ipv6.next_header == 58:
                    icmp = ICMP(ipv6.data)

                    print('\t - ' + 'Intenet Control Message Protocol:')
                    print('\t\t - ' + 'Type: {}, Code: {}, Checksum: {}'.format(icmp.icmp_type, icmp.code, icmp.checksum))
                    print('\t\t - ' + 'Identifier: {}, Sequence number: {}'.format(icmp.id, icmp.sequence))
                    print('\t\t - ' + 'Data:')
                    print(print_data('\t\t\t   ', icmp.data))

                # TCP
                elif ipv6.next_header == 6:
                    tcp = TCP(ipv6.data)

                    print('\t - ' + 'Transmission Control Protocol:')
                    print('\t\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                    print('\t\t - ' + 'Sequence number: {}, Acknowledgment number: {}'.format(tcp.sequence,
                                                                                              tcp.acknowledgment))
                    h_len = str(tcp.offset) + ' bytes (' + str(int(tcp.offset / 4)) + ')'
                    print('\t\t - ' + 'Header Length: {}'.format(h_len))
                    print('\t\t - ' + 'Flags:')
                    print('\t\t\t - ' + 'Reserved: {}, NS: {}, CWR: {}'.format(tcp.Reserved, tcp.NS, tcp.CWR))
                    print('\t\t\t - ' + 'ECE: {}, URG: {}, ACK: {}, PSH: {}'.format(tcp.ECE, tcp.URG, tcp.ACK,tcp.PSH))
                    print('\t\t\t - ' + 'RST: {}, SYN: {}, FIN: {}'.format(tcp.RST, tcp.SYN, tcp.FIN))
                    print('\t\t - ' + 'Window sizr: {}, Checksum: {}'.format(tcp.window, tcp.checksum))
                    print('\t\t - ' + 'Urgent pointer: {}, Options: {}'.format(tcp.urgent, tcp.options))

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print('\t\t - ' + 'Hypertext Transfer Protocol:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:

                                print('\t\t\t   ' + str(line))
                        except:
                            print(print_data('\t\t\t   ', tcp.data))

                    # DNS
                    if tcp.src_port == 53 or tcp.dest_port == 53:
                        try:
                            dns = DNS(tcp.data)
                            print('\t - ' + 'Domain Name System:')
                            print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                            print('\t\t - ' + 'Flags:')
                            print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                            print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                dns.AA, dns.TC, dns.RD, dns.RA))

                            print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA, dns.Z, dns.AD))
                            print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD, dns.Rcode))

                            print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                                dns.question_count, dns.answer_count, dns.name_server_count, dns.additional_record_count))
                            dns.dns_details()
                            dns.print_details()
                        except:
                            print(tcp.data)

                    else:
                        print('\t\t - ' + 'TCP Data:')
                        #print(print_data('\t\t\t   ', tcp.data))
                # UDP
                elif ipv6.next_header == 17:
                    udp = UDP(ipv6.data)

                    print('\t - ' + 'User Datagram Protocol:')
                    print('\t\t - ' + 'Source Port: {}, Destination Port: {}, Length: {},Checksum: {}'.format(udp.src_port,
                                                                                                              udp.dest_port,
                                                                                                              udp.length,
                                                                                                              udp.checksum))
                    #   DNS
                    if udp.src_port == 53 or udp.dest_port == 53:
                        dns = DNS(udp.data)
                        print('\t - ' + 'Domain Name System:')
                        print('\t\t - ' + 'Identifier: {}'.format(hex(dns.id)))
                        print('\t\t - ' + 'Flags:')
                        print('\t\t\t - ' + 'Query/Response(QR): {}, Operation Code(Opcode): {}'.format(dns.QR, dns.opcode))
                        print('\t\t\t - ' + 'Authoritative Answer(AA): {}, Truncated(TC): {}, Recursion Desired(RD): {}'.format(
                                dns.AA, dns.TC, dns.RD, dns.RA))

                        print('\t\t\t - ' + 'Recursion Available(RA): {}, Z: {}, Authenticated data(AD): {}'.format(dns.AA, dns.Z, dns.AD))
                        print('\t\t\t - ' + 'Checking Disabled(CD): {}, Return code(Rcode)'.format(dns.CD, dns.Rcode))
                        print('\t\t - ' + 'Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(
                            dns.question_count, dns.answer_count, dns.name_server_count, dns.additional_record_count))
                        dns.dns_details()
                        dns.print_details()

                    else:
                        print('\t\t - ' + 'UDP Data:')
                        #print(print_data('\t\t\t   ', udp.data))

                else:
                    print('\t - ' + 'Other IPv6 Data:')
                    print(print_data('\t\t   ', ipv6.data))

            # ARP
            elif eth.proto == 0x0806:
                arp = ARP(eth.data)
                print('\t - ' + "Address Resolution Protocol:")
                h_type = arp.hardware_type
                if h_type == 1:
                    h_type = 'Ethernet (1)'

                print(
                    '\t\t - ' + 'Hardware type: {}, Protocol type: {}'.format(
                        h_type, hex(arp.protocol_type)))
                print(
                    '\t\t - ' + 'Hardware size: {}, Protocol size: {}, Opcode: {}'.format(arp.hardware_addr_len, arp.protocol_addr_len,
                                                                                          arp.opcode))
                print('\t\t - ' + 'Sender MAC address: {}, Sender IP address: {}'.format(arp.sender_hardware_address,
                                                                                         arp.sender_protocol_addr))
                print('\t\t - ' + 'Target MAC address: {}, Target IP address: {}'.format(
                    arp.target_hardware_address,
                    arp.target_protocol_addr))

            else:
                print(' Ethernet Data:')
                print(print_data('\t   ', eth.data))

    except KeyboardInterrupt:
        print('\033[32m' + '\n Packet capturing was stopped. Packets were saved in capture.pcap \n')
        pcap.close()
        
        
        
        
        
        
        
        
        
        
        
        
        

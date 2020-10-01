import socket, sys
from struct import *
import binascii


def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b


try:
	s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error,msg:
	print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()


while True:
	packet = s.recvfrom(65565)
	
	packet = packet[0]
	
	eth_length = 14
	
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])


	if eth_protocol == 8 :

		ip_header = packet[eth_length:20+eth_length]
		

		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8])
		d_addr = socket.inet_ntoa(iph[9])


        if protname != "nil":
            if protname == "tcp":
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                tcph = unpack('!HHLLBBHHH' , tcp_header)
                
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                
                if ipname != 0 and portname != 0:
                    if d_addr == ipname and source_port == portname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')

                elif ipname != 0:
                    if d_addr == ipname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')


                elif portname != 0:
                    if source_port == portname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')



            elif protname == "udp":
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                #now unpack them :)
                udph = unpack('!HHHH' , udp_header)
                
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                if ipname != 0 and portname != 0:
                    if d_addr == ipname and source_port == portname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')

                elif ipname != 0:
                    if d_addr == ipname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')


                elif portname != 0:
                    if source_port == portname:
                        print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                        
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        
                        data = packet[h_size:]

                        print('')
                
            
            elif protname == "http":
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]

                    tcph = unpack('!HHLLBBHHH' , tcp_header)
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4
                
                    if dest_port == 80:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                elif protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                    #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)
                    
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                
                    if dest_port == 80:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


            elif protname == "ftp":
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]

                    tcph = unpack('!HHLLBBHHH' , tcp_header)
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4
                
                    if dest_port == 20 or dest_port == 21:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')
                
                elif protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                    #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)
                    
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                
                    if dest_port == 20 or dest_port == 21:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

            elif protname == "telnet":
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]

                    tcph = unpack('!HHLLBBHHH' , tcp_header)
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4
                
                    if dest_port == 23:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')
                
                elif protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u+8]

                    #now unpack them :)
                    udph = unpack('!HHHH' , udp_header)
                    
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                
                    if dest_port == 23:
                        if ipname != 0 and portname != 0:
                            if d_addr == ipname and source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + s * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')

                        elif ipname != 0:
                            if d_addr == ipname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')


                        elif portname != 0:
                            if source_port == portname:
                                print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
                                print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
                                print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                                
                                h_size = eth_length + iph_length + tcph_length * 4
                                data_size = len(packet) - h_size
                                
                                data = packet[h_size:]

                                print('')
            
            



                
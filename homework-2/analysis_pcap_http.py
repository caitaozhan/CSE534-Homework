import dpkt
import sys

class Packet:
    '''Encapsulate TCP's header fields of a packet from pcap.
    
    Attributes:
        source_port (int):  source port number
        dest_port (int):    destination port number
        sequence_num (int): sequence number
        ack_num (int):      acknowledgement number
        head_len(int):      header length
        urg (int):          urgent flag
        ack (int):          acknowledgement flag
        psh (int):          psh flag
        rst (int):          reset flag
        syn (int):          synchronize flag
        fin (int):          finish flag
        receive_win (int):  receive window
        checksum (int):     checksum
        urgent (int):       urgent data pointer
        scale (int):        window scaling size
        size (int):         the size of the whole packet, including data and all headers
        payload (bytes):    TCP payload
        payload_len (int):  TCP payload length
    '''
    
    def __init__(self, packet):
        '''Init a packet
        
        Args:
            packet(tuple): an element from dpkt.pcap.Reader.readpkts()
        '''
        self.time_stamp = packet[0]
        self.byte_info  = packet[1]
        self.size = len(packet[1])

        
    def parse_byte_info(self):
        '''Convert the byte format information of a packet into human readable fields
        '''
        self.source_port  = int.from_bytes(self.byte_info[34:36], byteorder='big')
        self.dest_port    = int.from_bytes(self.byte_info[36:38], byteorder='big')
        self.sequence_num = int.from_bytes(self.byte_info[38:42], byteorder='big')
        self.ack_num      = int.from_bytes(self.byte_info[42:46], byteorder='big')
        head_len          = int.from_bytes(self.byte_info[46:47], byteorder='big')
        self.head_len     = 4*(head_len>>4)
        flags             = int.from_bytes(self.byte_info[47:48], byteorder='big')
        self.fin = flags&1
        flags = flags>>1
        self.syn = flags&1
        flags = flags>>1
        self.rst = flags&1
        flags = flags>>1
        self.psh = flags&1
        flags = flags>>1
        self.ack = flags&1
        flags = flags>>1
        self.urg = flags&1
        self.receive_win = int.from_bytes(self.byte_info[48:50], byteorder='big')
        self.checksum    = int.from_bytes(self.byte_info[50:52], byteorder='big')
        self.urgent      = int.from_bytes(self.byte_info[52:54], byteorder='big')
        self.payload     = self.byte_info[34+packet.head_len:]
        self.payload_len = len(self.payload)
        
        
    def parse_window_scale(self):
        '''shift window size is typically 14. so the scaling is 2^14 = 16384
        '''
        shift = int.from_bytes(self.byte_info[73:74], byteorder='big')
        self.scale = 1<<shift

        
    def __str__(self):
        string = 'Source Port #  = {}\n'.format(self.source_port)
        string = string + 'Dest Port #    = {}\n'.format(self.dest_port)
        string = string + 'Sequence #     = {}\n'.format(self.sequence_num)
        string = string + 'Ackownledge #  = {}\n'.format(self.ack_num)
        string = string + 'Header length  = {}\n'.format(self.head_len)
        string = string + 'URG({}) ACK({}) PSH({})\n'.format(self.urg, self.ack, self.psh)
        string = string + 'RST({}) SYN({}) FIN({})\n'.format(self.rst, self.syn, self.fin)
        string = string + 'Receive window = {}\n'.format(self.receive_win)
        string = string + 'Checksum       = {}\n'.format(self.checksum)
        string = string + 'Urgent         = {}\n'.format(self.urgent)
        string = string + 'Payload len    = {}\n'.format(self.payload_len)
        return string

class Flow:
    '''Encapsulate a flow of packets from one port of sender to another port of receiver
    
    Attributes:
        __ID  (int):  private class member identification
        ID    (int):  identification of a flow
        port1 (int):  a port number
        port2 (int):  a port number
        flow  (list): a list of Packet
        throughput_emp (float): empirical throughput
        rtt (float): round trip time
        counter (int): count the number of packets in this flow
        scale (int):   window scaling size
        tda (int):     number of triple duplicate ack occurs
        timeout (int): number of timeout occurs
    '''
    __ID = 100
    
    def __init__(self):
        self.ID    = Flow.__ID
        Flow.__ID += 1
        self.port1 = -1
        self.port2 = -1
        self.flow  = []
        self.throughput_emp = -1
        self.rtt     = -1
        self.counter = 0
        self.scale   = 1
        print('init a new flow {}'.format(self.ID))
        
    
    def __str__(self):
        return 'ID={}  port1={}  port2={}  # of packets={}'.format(self.ID, self.port1, self.port2, self.counter)
         
    
    def set_port(self, packet):
        self.port1 = packet.source_port
        self.port2 = packet.dest_port
        
    
    def get_packet(self, index):
        if index >= 0 and index < len(self.flow):
            return self.flow[index]
        else:
            return None
        
    
    def add_packet(self, packet):
        self.flow.append(packet)
        self.counter += 1
        

    def reassemble_http(self):
        '''Reassemble each unique HTTP Request/Response for http_1080.pcap 
           (the other two are encrypted, so you will not be able to reassemble easily). 
           The output of this part should be the Packet type (request or response) and the 
           unique <source, dest, seq, ack> TCP tuple for all the TCP segments that contain data for that request.
        '''
        get_packets = []
        for packet in self.flow:       # find all the get packets
            payload = getattr(packet, 'payload')
            if str(payload).find('GET') != -1:
                get_packets.append(packet)
        
        packet_dict = {}
        for packet in self.flow:
            seq = getattr(packet, 'sequence_num')
            packet_dict[seq] = packet  # the latter packets with the same seq number will replace the former one, which is okay.
            
        reassembles = []
        
        for get in get_packets:
            reassemble = ReassembleHTTP(get)
            next_seq = getattr(get, 'ack_num')     # start from the ack of GET request
            next_packet = packet_dict.get(next_seq)
            while next_packet:
                reassemble.add_tcp_segment(next_packet)
                payload_len = getattr(next_packet, 'payload_len')
                next_seq = next_seq + payload_len
                next_packet = packet_dict.get(next_seq)
                if getattr(next_packet, 'fin') == 1:
                    break
            reassembles.append(reassemble)
            
        for reassemble in reassembles:
            reassemble.print_reassembleHTTP()
            
    
    def data_from_server(self):
        '''Count amount of data (in bytes) send from server to client
           
        Return:
            (int) the amount of data send from server to client
        '''
        data_from_server = 0
        for packet in self.flow:
            source_port = getattr(packet, 'source_port')
            if source_port == self.port2:   # packet from server is from port2
                data_from_server += getattr(packet, 'payload_len')
        print('Flow {0}: {1:10.0f} byte of data has been send from server to client'.format(self.ID, data_from_server))
        return data_from_server
    
    
    def packet_from_server(self):
        '''Count number of packets send from server to client
        
        Return:
            (int) the number of packets
        '''
        packet_counter = 0
        for packet in self.flow:
            source_port = getattr(packet, 'source_port')
            if source_port == self.port2:
                packet_counter += 1
        return packet_counter
    
    
    def last_packet_time(self):
        '''Return the timestamps
        
        Return:
            (float, float) time stamp of the first packet and last effective time stamp
        '''
        packet_0 = self.flow[0]
        timestamp0 = getattr(packet_0, 'time_stamp')
        packet_1 = self.flow[0]
        for packet_2 in self.flow:
            timestamp1 = getattr(packet_1, 'time_stamp')
            timestamp2 = getattr(packet_2, 'time_stamp')
            if timestamp2 - timestamp1 > 2:
                break
            packet_1 = packet_2
            
        return (timestamp0, timestamp1)


class ReassembleHTTP:
    '''Reassemble the multiply packets of one HTTP Request/Response
    
    Attributes:
        request (str): what this HTTP request for
        response (str): version and status code
    '''
    def __init__(self, get_packet):   # use the request get to init, get only need one packet
        start = str(get_packet.payload).find('GET')
        end1 = str(get_packet.payload).find('HTTP')
        end2 = str(get_packet.payload).find('Connection')
        end  = end1 if end1 > end2 else end2
        self.request = str(get_packet.payload)[start:end]
        self.tcp_segment = []
        
        
    def add_tcp_segment(self, packet):
        source = getattr(packet, 'source_port')
        dest   = getattr(packet, 'dest_port')
        seq    = getattr(packet, 'sequence_num')
        ack    = getattr(packet, 'ack_num')
        self.tcp_segment.append((source, dest, seq, ack))
    
    
    def print_reassembleHTTP(self):
        print(self.request)
        print('The TCP segments are below:')
        for segment in self.tcp_segment:
            print(segment)
            

class FlowManager:
    '''Manage some flows
    
    Attributes:
        flow_list (list): an list(array) of Flow
        flow_info (dict): a dict { ID : (index, port1, port2) }
    '''
    
    def __init__(self):
        self.flow_list = []
        self.flow_info = {}
        
        
    def add_packet(self, packet):
        '''Add a packet to the flow it belongs to. 
           If the flow does not exit, then create a new one.
           
        Args:
            packet (Packet)
        '''
        index = self.where_is_packet(packet)
        if index == -1:  # this is a "new packet": the packet does not belong to any existed flow
            new_flow = Flow()
            new_flow.set_port(packet)
            new_flow.add_packet(packet)
            self.add_flow(new_flow)
        else:            # this packet belongs to an existed flow
            self.flow_list[index].add_packet(packet)
    
    
    def add_flow(self, flow):
        '''Add a new flow into FlowManager
        
        Args:
            flow (Flow): a new flow to be added to the flow manager
        '''
        index = len(self.flow_list)
        self.flow_list.append(flow)
        ID  = getattr(flow, 'ID')
        port1 = getattr(flow, 'port1')
        port2 = getattr(flow, 'port2')
        self.flow_info[ID] = (index, port1, port2)
        
    
    def where_is_packet(self, packet):
        '''Return the flow's index to which a packet belongs
        
        Args:
            packet (Packet): a packet
        
        Return:
            (int): index 
        '''
        source_port = getattr(packet, 'source_port')
        dest_port = getattr(packet, 'dest_port')
        for ID, info in self.flow_info.items():
            if (source_port == info[1] and dest_port == info[2]) or (source_port == info[2] and dest_port == info[1]):
                return info[0]
        else:
            return -1
        
    
    def size(self):
        return len(self.flow_list)
    
    
    def get_flow(self, ID):
        '''Get a flow according to its ID
        
        Args:
            flow (Flow): Identification number
        '''
        flow_info = self.flow_info.get(ID)
        if flow_info:
            index = flow_info[0]
            return self.flow_list[index]
        return None
    
    
    def partC_1(self):
        for flow in self.flow_list:
            flow.reassemble_http()
            print('\n\n')
            
    
    def partC_2(self):
        '''Identify which HTTP protocol is being used for each PCAP file. 
           Note that two of the sites are encrypted so you must use your knowledge of HTTP and TCP to 
           programmatically solve this question. Include the logic behind your code in the write-up.
        '''
        print()
        flow_server_data = []
        for flow in self.flow_list:
            flow_server_data.append(flow.data_from_server())
            
        secure_data = 3500     # typical amount of data for SSL key exchange
        flow_counter = 0       # number of flow that actually send website data, not merely SSL data
        total_data   = 0
        for data in flow_server_data:
            total_data += data
            if data > secure_data:
                flow_counter += 1
        
        print('\nData from all flows: {}'.format(total_data))
        print('\n{} TCP connection opened on server side to send website data to client.'.format(flow_counter))
        
        if flow_counter < len(flow_server_data):
            print('1 TCP connection opened merely for TLS key exchange')
        if flow_counter > 1:
            print('\nThis is HTTP/1.1 since it uses parallel(multiple) TCP connection to send website data')
        else:
            print('\nThis is HTTP/2.0 since it uses single TCP connection to send website data')
        
        
    def partC_3(self):
        '''Finally, after you’ve labeled the PCAPs with their appropriate versions of HTTP, 
           answer the following: Which version of the protocol did the site load the fastest under? The Slowest? 
           Which sent the most number of packets and raw bytes? Which protocol sent the least? 
           Report your results and write a brief explanation for your observations.
        '''
        smallest_time  = sys.maxsize
        largest_time   = 0
        packet_counter = 0
        byte_counter   = 0
        for flow in self.flow_list:
            time0, time1 = flow.last_packet_time()
            smallest_time = time0 if time0 < smallest_time else smallest_time
            largest_time  = time1 if time1 > largest_time else largest_time
            packet_counter += flow.packet_from_server()
            byte_counter += flow.data_from_server()
        print('\nLoad time         = {0:4.4f} s'.format(largest_time - smallest_time))
        print('Number of packets = {}'.format(packet_counter))
        print('Raw bytes         = {} byte'.format(byte_counter))


f_1080 = open('http_1080.pcap', 'rb')
pcap_1080 = dpkt.pcap.Reader(f_1080)
packets_bytes_1080 = pcap_1080.readpkts()

flow_manager_1080 = FlowManager()

packets = []
for packet_bytes in packets_bytes_1080:
    packet = Packet(packet_bytes)
    packet.parse_byte_info()
    flow_manager_1080.add_packet(packet)
    packets.append(packet)


flow_manager_1080.partC_1()


f_1081 = open('http_1081.pcap', 'rb')
pcap_1081 = dpkt.pcap.Reader(f_1081)
packets_bytes_1081 = pcap_1081.readpkts()

flow_manager_1081 = FlowManager()

packets = []
for packet_bytes in packets_bytes_1081:
    packet = Packet(packet_bytes)
    packet.parse_byte_info()
    flow_manager_1081.add_packet(packet)
    packets.append(packet)
    
flow_manager_1081.partC_2()


f_1082 = open('http_1082.pcap', 'rb')
pcap_1082 = dpkt.pcap.Reader(f_1082)
packets_bytes_1082 = pcap_1082.readpkts()

flow_manager_1082 = FlowManager()

packets = []
for packet_bytes in packets_bytes_1082:
    packet = Packet(packet_bytes)
    packet.parse_byte_info()
    flow_manager_1082.add_packet(packet)
    packets.append(packet)
    
flow_manager_1082.partC_2()


flow_manager_1080.partC_3()
flow_manager_1081.partC_3()
flow_manager_1082.partC_3()



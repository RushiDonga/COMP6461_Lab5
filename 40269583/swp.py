import enum
import logging
import llp
import queue
import struct
import threading
import time

class SWPType(enum.IntEnum):
    DATA = ord('D')
    ACK = ord('A')

class SWPPacket:
    _PACK_FORMAT = '!BI'
    _HEADER_SIZE = struct.calcsize(_PACK_FORMAT)
    MAX_DATA_SIZE = 1400 # Leaves plenty of space for IP + UDP + SWP header 

    def __init__(self, type, seq_num, data=b''):
        self._type = type
        self._seq_num = seq_num
        self._data = data

    @property
    def type(self):
        return self._type

    @property
    def seq_num(self):
        return self._seq_num
    
    @property
    def data(self):
        return self._data

    def to_bytes(self):
        header = struct.pack(SWPPacket._PACK_FORMAT, self._type.value, 
                self._seq_num)
        return header + self._data
       
    @classmethod
    def from_bytes(cls, raw):
        header = struct.unpack(SWPPacket._PACK_FORMAT,
                raw[:SWPPacket._HEADER_SIZE])
        type = SWPType(header[0])
        seq_num = header[1]
        data = raw[SWPPacket._HEADER_SIZE:]
        return SWPPacket(type, seq_num, data)

    def __str__(self):
        return "%s %d %s" % (self._type.name, self._seq_num, repr(self._data))

class SWPSender:
    _SEND_WINDOW_SIZE = 5
    _TIMEOUT = 1

    def __init__(self, remote_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(remote_address=remote_address,
                loss_probability=loss_probability)

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        self._send_window = []
        self._next_seq_num = 0
        self._lock = threading.Lock()

    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i+SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # TODO
        with self._lock:
            while len(self._send_window) >= self._SEND_WINDOW_SIZE:
                time.sleep(0.1)
            
            packet = SWPPacket(SWPType.DATA, self._next_seq_num, data)
            self._llp_endpoint.send(packet.to_bytes())
            
            self._send_window.append((packet, time.time()))
            
            timer = threading.Timer(self._TIMEOUT, self._retransmit, args=[self._next_seq_num])
            timer.start()
            
            self._next_seq_num += 1
        return
        
    def _retransmit(self, seq_num):
        # TODO
        with self._lock:
            packet_to_resend = next((packet for packet, _ in self._send_window if packet.seq_num == seq_num), None)
            
            if packet_to_resend:
                logging.debug("LLP retransmitting: %s" % packet_to_resend)
                self._llp_endpoint.send(packet_to_resend.to_bytes())
                
                timer = threading.Timer(self._TIMEOUT, self._retransmit, args=[seq_num])
                timer.start()
        return 

    def _recv(self):
        while True:
            # Receive SWP packet
            raw = self._llp_endpoint.recv()
            if raw is None:
                continue
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            if packet.type == SWPType.ACK:
                with self._lock:
                    logging.debug("Received ACK for %d" % packet.seq_num)
                    self._send_window = [(p, t) for p, t in self._send_window if p.seq_num > packet.seq_num]
        return

class SWPReceiver:
    _RECV_WINDOW_SIZE = 5

    def __init__(self, local_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(local_address=local_address, 
                loss_probability=loss_probability)

        # Received data waiting for application to consume
        self._ready_data = queue.Queue()

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()
        
        # TODO: Add additional state variables
        self._recv_buffer = {}
        self._next_expected_seq_num = 0
        self._lock = threading.Lock()

    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)
            
            # TODO
            if packet.type == SWPType.DATA:
                with self._lock:
                    if packet.seq_num < self._next_expected_seq_num:
                        self._send_ack()
                    
                    self._recv_buffer[packet.seq_num] = packet.data
                    
                    while self._next_expected_seq_num in self._recv_buffer:
                        data = self._recv_buffer.pop(self._next_expected_seq_num)
                        self._ready_data.put(data)
                        self._next_expected_seq_num += 1
                    
                    self._send_ack()
        return

    def _send_ack(self):
        ack_packet = SWPPacket(SWPType.ACK, self._next_expected_seq_num - 1)
        self._llp_endpoint.send(ack_packet.to_bytes())
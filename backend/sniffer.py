from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import asyncio
import threading
from datetime import datetime

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.packet_queue = asyncio.Queue()
        self.loop = None

    def process_packet(self, packet):
        if not self.running:
            return
        
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                # Map protocol numbers to names (simple version)
                proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                proto_num = packet[IP].proto
                proto = proto_map.get(proto_num, str(proto_num))
                length = len(packet)
                
                info = ""
                if TCP in packet:
                    info = f"{packet[TCP].sport} -> {packet[TCP].dport} [TCP]"
                elif UDP in packet:
                    info = f"{packet[UDP].sport} -> {packet[UDP].dport} [UDP]"
                else:
                    info = packet.summary()

                pkt_data = {
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "length": length,
                    "info": info,
                    "timestamp": datetime.now().isoformat()
                }
                
                if self.loop:
                    # Thread-safe put into queue
                    self.loop.call_soon_threadsafe(self.packet_queue.put_nowait, pkt_data)
        except Exception:
            pass

    def start_sniffing(self, loop):
        self.running = True
        self.loop = loop
        # Run sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self._run_sniff)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _run_sniff(self):
        # prn is callback, store=0 to avoid memory issues
        try:
            sniff(prn=self.process_packet, store=0)
        except Exception as e:
            print(f"WARNING: Sniffing failed ({e}). Switching to SIMULATION MODE.")
            self._run_mock_sniff()

    def _run_mock_sniff(self):
        import time
        import random
        
        while self.running:
            if self.loop:
                # Simulate a packet
                pkt_data = {
                    "src": f"192.168.1.{random.randint(2, 254)}",
                    "dst": f"10.0.0.{random.randint(2, 254)}",
                    "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                    "length": random.randint(64, 1500),
                    "info": f"Simulated traffic {random.randint(1000, 9999)} -> {random.randint(80, 443)}",
                    "timestamp": datetime.now().isoformat()
                }
                self.loop.call_soon_threadsafe(self.packet_queue.put_nowait, pkt_data)
            time.sleep(random.uniform(0.1, 0.5))

    def stop_sniffing(self):
        self.running = False

sniffer = PacketSniffer()

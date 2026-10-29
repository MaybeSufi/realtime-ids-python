import time
from collections import defaultdict

from scapy.all import IP, TCP


class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": None,
            "last_time": None,
        })



    def analyze_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return None


        flow_key = (packet[IP].src, packet[IP].dst,
                    packet[TCP].sport, packet[TCP].dport)

        stats = self.flow_stats[flow_key]
        stats["packet_count"] += 1
        stats["byte_count"] += len(packet)



        current_time = float(packet.time) if packet.time is not None else time.time()
        if stats["start_time"] is None:
            stats["start_time"] = current_time
        stats["last_time"] = current_time


        return self.extract_features(packet, stats)




    def extract_features(self, packet, stats):
        duration = stats["last_time"] - stats["start_time"]
        safe_duration = duration if duration > 0 else 1e-6


        return {
            "packet_size": len(packet),
            "flow_duration": duration,
            "packet_rate": stats["packet_count"] / safe_duration,
            "byte_rate": stats["byte_count"] / safe_duration,
            "tcp_flage": int(packet[TCP].flags),
            "window_size": packet[TCP].window,
        }
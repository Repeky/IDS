from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from collections import defaultdict
import time


class NetworkMonitor:
    def __init__(self):
        self.activity = defaultdict(lambda: defaultdict(int))
        self.suspicious_packets = []
        self.start_time = time.time()

    def process_packet(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            self.activity[src_ip][dst_port] += 1

            if self.is_suspicious_packet(packet):
                print(f"[!] Потенциально подозрительный пакет от {src_ip} к порту {dst_port}")
                self.suspicious_packets.append((src_ip, dst_port))

    def is_suspicious_packet(self, packet):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        threshold = 20  # Пример порогового значения
        return self.activity[src_ip][dst_port] > threshold

    def start(self):
        print("Запуск мониторинга сетевого трафика...")
        sniff(prn=self.process_packet, store=False)

    def finish(self):
        if self.suspicious_packets:
            print("Обнаруженные подозрительные пакеты:")
            for ip, port in self.suspicious_packets:
                print(f"IP {ip}, Порт {port}")
        else:
            print("Подозрительная активность не обнаружена.")


if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("Остановка мониторинга...")
        monitor.finish()

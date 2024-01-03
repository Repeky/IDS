from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from collections import defaultdict
import threading
import json


class NetworkMonitor:
    def __init__(self):
        self.activity = defaultdict(lambda: defaultdict(int))
        self.suspicious_packets = []
        self.monitoring = True

    def process_packet(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            self.activity[src_ip][dst_port] += 1

            if self.is_suspicious_packet(packet):
                print(f"Обнаружен подозрительный пакет: IP {src_ip}, Порт {dst_port}")
                self.suspicious_packets.append((src_ip, dst_port))

    def is_suspicious_packet(self, packet):
        # Проверка флагов TCP для обнаружения SYN Flood атак
        if TCP in packet and packet[TCP].flags == 'S' and not packet[TCP].flags == 'A':
            return True

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        threshold = 20  # Пример порогового значения
        return self.activity[src_ip][dst_port] > threshold

    def start(self):
        print("Мониторинг запущен. Нажмите 'q', чтобы остановить.")
        sniff_thread = threading.Thread(
            target=lambda: sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.monitoring))
        sniff_thread.start()

        while True:
            if input() == 'q':
                self.monitoring = False
                break

        sniff_thread.join()
        self.finish()

    def finish(self):
        if not self.suspicious_packets:
            print("Подозрительная активность не обнаружена.")

        elif self.suspicious_packets:
            while True:
                user_input = input("Сохранить подозрительные пакеты? (y/n): ").lower()
                if user_input == 'y':
                    with open("suspicious_packets.json", "w") as file:
                        json.dump(self.suspicious_packets, file, indent=4)
                    print("Данные сохранены в файл 'suspicious_packets.json'.")
                    break
                elif user_input == 'n':
                    print("Данные не сохранены.")
                    break
                else:
                    print("Пожалуйста, введите 'y' для сохранения или 'n' для отказа.")


if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.start()

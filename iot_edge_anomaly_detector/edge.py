import logging
import os
import psutil
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP


class IoTEdgeAnomalyDetector:
    def __init__(self, interface=None, quiet=False, no_log=False, log_file='iot_edge_anomaly.log', daemon=False):
        self.interface = interface
        self.quiet = quiet
        self.no_log = no_log
        self.log_file = log_file
        self.daemon = daemon
        self.baseline_window = 300
        self.device_activity = defaultdict(lambda: deque(maxlen=200))
        self.protocol_counts = defaultdict(int)
        self.alerts = []
        self.logger = self._configure_logging()

    def _configure_logging(self):
        handlers = []
        if not self.no_log:
            handlers.append(logging.FileHandler(self.log_file))
        if not self.quiet:
            handlers.append(logging.StreamHandler())

        if handlers:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=handlers)
        else:
            logging.disable(logging.CRITICAL)

        return logging.getLogger(__name__)

    def get_network_interfaces(self):
        return list(psutil.net_if_addrs().keys())

    def analyze_device_behavior(self, packet):
        alerts = []
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            now = datetime.now()
            self.device_activity[src_ip].append(now)
            cutoff = now - timedelta(seconds=self.baseline_window)
            while self.device_activity[src_ip] and self.device_activity[src_ip][0] < cutoff:
                self.device_activity[src_ip].popleft()

            if len(self.device_activity[src_ip]) > 50:
                duration = (now - self.device_activity[src_ip][0]).total_seconds()
                rate = len(self.device_activity[src_ip]) / duration if duration else 0
                if rate > 5:
                    alerts.append(f"Unusual device traffic from {src_ip}: {rate:.1f} pps")

            if packet.haslayer(TCP):
                self.protocol_counts['TCP'] += 1
            elif packet.haslayer(UDP):
                self.protocol_counts['UDP'] += 1

            if packet.haslayer(TCP) and packet[TCP].dport not in {80, 443, 22, 1883, 8883}:
                alerts.append(f"Unexpected destination port for IoT device {src_ip}: {packet[TCP].dport}")

        return alerts

    def packet_handler(self, packet):
        try:
            alerts = self.analyze_device_behavior(packet)
            for alert in alerts:
                self.logger.warning(f"ALERT: {alert}")
                self.alerts.append({'timestamp': datetime.now().isoformat(), 'alert': alert})
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def print_statistics(self):
        if self.quiet:
            return

        total_devices = len(self.device_activity)
        total_alerts = len(self.alerts)
        print('\n' + '=' * 60)
        print('IOT / EDGE DEVICE ANOMALY STATISTICS')
        print('=' * 60)
        print(f"Monitored devices: {total_devices}")
        print(f"Total alerts: {total_alerts}")
        for proto, count in self.protocol_counts.items():
            print(f"  {proto}: {count}")

    def start_monitoring(self):
        if self.daemon:
            self._daemonize()

        if not self.interface:
            interfaces = self.get_network_interfaces()
            self.interface = interfaces[0] if interfaces else None

        if not self.quiet:
            print(f"Starting IoT/edge anomaly detector on {self.interface or 'all interfaces'}")

        sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: False)

    def _daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                raise SystemExit(0)
        except OSError as exc:
            self.logger.error(f"Failed to daemonize: {exc}")
            raise

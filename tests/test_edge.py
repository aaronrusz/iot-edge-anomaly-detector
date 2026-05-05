from scapy.all import IP, TCP

from iot_edge_anomaly_detector.edge import IoTEdgeAnomalyDetector


def test_analyze_device_behavior_unusual_port():
    detector = IoTEdgeAnomalyDetector(quiet=True, no_log=True)
    packet = IP(src='198.51.100.10') / TCP(dport=12345)
    alerts = detector.analyze_device_behavior(packet)
    assert any('Unexpected destination port' in alert for alert in alerts)


def test_packet_handler_collects_alerts():
    detector = IoTEdgeAnomalyDetector(quiet=True, no_log=True)
    packet = IP(src='198.51.100.11') / TCP(dport=80)
    detector.packet_handler(packet)
    assert isinstance(detector.alerts, list)

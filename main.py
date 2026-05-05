#!/usr/bin/env python3
import argparse
from iot_edge_anomaly_detector.edge import IoTEdgeAnomalyDetector


def main():
    parser = argparse.ArgumentParser(description='IoT/Edge Device Anomaly Detector')
    parser.add_argument('--interface', type=str, help='Network interface to monitor')
    parser.add_argument('--quiet', action='store_true', help='Suppress console output')
    parser.add_argument('--no-log', action='store_true', help='Disable logging to file')
    parser.add_argument('--log-file', type=str, default='iot_edge_anomaly.log', help='Log file path')
    parser.add_argument('--daemon', action='store_true', help='Run as a background daemon process')
    args = parser.parse_args()

    detector = IoTEdgeAnomalyDetector(
        interface=args.interface,
        quiet=args.quiet,
        no_log=args.no_log,
        log_file=args.log_file,
        daemon=args.daemon,
    )
    detector.start_monitoring()


if __name__ == '__main__':
    main()

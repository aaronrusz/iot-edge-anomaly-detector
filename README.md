# IoT/Edge Device Anomaly Detector

A specialized anomaly detection utility for IoT and edge networks.

## Features

- Tracks device traffic behavior over time
- Alerts on unusual packet rates and protocol changes
- Reports active devices and suspicious connections
- Supports quiet and no-log modes

## Usage

```bash
python main.py --interface eth0 --quiet
```

## Installation

Install the required runtime dependencies:

```bash
pip install scapy psutil
```

Then run:

```bash
python main.py --interface eth0 --quiet
```

## Testing

Run the unit tests with:

```bash
pip install pytest
python -m pytest tests
```

## AI Usage Disclosure

Parts of this repository utilize AI coding agents for boilerplate generation, unit test expansion, and routine refactoring. All AI-generated code passes through manual QA testing and code review before merge.

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the `LICENSE` file for details.

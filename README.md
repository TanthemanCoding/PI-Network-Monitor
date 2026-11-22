# Pi Network Monitor

A Python tool that detects possible SSH brute-force attacks by watching failed login
attempts in the Linux system journal.

## Overview

Pi Network Monitor reads SSH authentication activity, pulls out the failed
login attempts, groups them by source IP address, and raises an alert when a
single IP crosses a configurable number of failures inside a short time
window — the signature of a brute-force attack.

It can run as a one-shot scan over the system journal, or
as a live monitor that follows the journal in real time. The project is built
as a hands-on security and Python/OOP exercise, comes with an automated test
suite, and is headed for deployment on a Raspberry Pi.

## Features

- Reads failed SSH logins from `journalctl`
- Validates IPv4 and IPv6 source addresses with the `ipaddress` module
- Groups attempts per IP and detects "threshold failures within a time window"
- Live monitoring that alerts once per burst (and re-alerts on a genuine new burst)
- 26 automated unit tests (`unittest`)

## Requirements

- Python 3.10 or newer (uses `X | None` and built-in generic type hints)
- A Linux system with `journalctl` for the journal/live modes
- No third-party dependencies — standard library only

## Installation

```bash
git clone https://github.com/TanthemanCoding/PI-Network-Monitor.git
cd PI-Network-Monitor
```

## Usage

Run the monitor:

```bash
python3 src/monitor.py
```

By default it creates a monitor with a threshold of **5** failed attempts
within a **90**-second window, scans the SSH journal, reports any brute-force
bursts it finds, then follows the journal live.

The detection settings are chosen when the monitor is created:

```python
from src.monitor import NetworkMonitor

monitor = NetworkMonitor(threshold=5, window_seconds=90)
```

Reading the system journal may require appropriate permissions depending on
how your machine is configured.

## Running the tests

From the repository root:

```bash
python3 -m unittest discover -s tests
```

All 26 tests should pass.

## How it works

1. **Collect** — read failed-password lines from a file (`read_logs`) or the
   journal (`read_ssh_journal`).
2. **Parse** — extract and validate the source IP (`extract_ip`) and the
   timestamp (`extract_time`, `convert_time`).
3. **Group** — map each IP to its list of failed-login times
   (`group_timestamps`).
4. **Detect** — alert when an IP reaches the threshold within the window
   (`detect_brute_force` for a batch, `monitor_live` for a live stream).

## Project layout

```
src/monitor.py      # the NetworkMonitor class and main()
tests/              # unittest suite and log fixtures
```

## Status / Roadmap

- [x] Object-oriented detector (`NetworkMonitor` class)
- [x] 26 automated unit tests (all passing)
- [x] File and `journalctl` log reading
- [x] Live monitoring (implemented and unit-tested)
- [ ] End-to-end validation against a real attack in an isolated lab
- [ ] Raspberry Pi deployment
- [ ] Optional: automated blocking, SIEM integration

## Responsible use

Only run brute-force tests against systems you own or are explicitly
authorized to test. This project is for defense and learning, not for
attacking others.

## License

Released under the [MIT License](LICENSE).

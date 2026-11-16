import unittest
from src.monitor import NetworkMonitor
from datetime import datetime
import io
from contextlib import redirect_stdout

class TestNetworkMonitor(unittest.TestCase):
    def test_threshold(self):
        monitor = NetworkMonitor(5, 90)
        self.assertEqual(5,monitor.threshold)


    def test_window_seconds(self):
        monitor = NetworkMonitor(5, 90)
        self.assertEqual(90, monitor.window_seconds)


    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            monitor = NetworkMonitor(0, 90)


    def test_invalid_window_seconds(self):
        with self.assertRaises(ValueError):
            monitor = NetworkMonitor(5,0)


    def test_extract_valid_ipv4(self):
        monitor = NetworkMonitor(5,90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        self.assertEqual("192.168.1.100", monitor.extract_ip(log))


    def test_extract_valid_ipv6(self):
        monitor = NetworkMonitor(5, 90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2" 
        self.assertEqual("2001:db8::1", monitor.extract_ip(log))


    def test_extract_invalid_ip(self):
        monitor = NetworkMonitor(5, 90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 999.999.999.999 port 22 ssh2"
        self.assertIsNone(monitor.extract_ip(log))


    def test_extract_missing_ip(self):
        monitor = NetworkMonitor(5, 90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root"
        self.assertIsNone(monitor.extract_ip(log))


    def test_extract_time(self):
        monitor = NetworkMonitor(5, 90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        self.assertEqual("Nov 15 12:30:00", monitor.extract_time(log))


    def test_convert_valid_time(self):
        monitor = NetworkMonitor(5, 90)
        timestamp = "Nov 15 12:30:00"
        self.assertIsInstance(monitor.convert_time(timestamp), datetime)


    def test_convert_invalid_time(self):
        monitor = NetworkMonitor(5, 90)
        timestamp = "Nov 35 12:30:00"
        self.assertIsNone(monitor.convert_time(timestamp))


    def test_extract_ip_missing_after_from(self):
        monitor = NetworkMonitor(5, 90)
        log = "Nov 15 12:30:00 server sshd[1234]: Failed password for root from"
        self.assertIsNone(monitor.extract_ip(log))


    def test_group_timestamps(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.101 port 22 ssh2"
        ]
        result = monitor.group_timestamps(failed_logs)
        self.assertEqual(2, len(result["192.168.1.100"]))


    def test_group_timestamps_invalid_ip(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from banana port 22 ssh2"
        ]
        result = monitor.group_timestamps(failed_logs)
        self.assertNotIn("banana", result)


    def test_group_timestamps_invalid_time(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 35 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        result = monitor.group_timestamps(failed_logs)
        self.assertEqual(1, len(result["192.168.1.100"]))


    def test_read_logs(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = monitor.read_logs("tests/test_read_logs.log")
        self.assertEqual(2, len(failed_logs))


    def test_read_logs_empty_file(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = monitor.read_logs("tests/empty.log")
        self.assertEqual([], failed_logs)

    def test_read_logs_missing_file(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = monitor.read_logs("tests/this_file_does_not_exist.log")
        self.assertEqual([], failed_logs)


    def test_detect_brute_force(self):
        monitor = NetworkMonitor(5, 90)
        failed_logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:40 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(failed_logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)

        self.assertIn("ALERT 192.168.1.100", output.getvalue())


    def test_detect_below_threshold(self):
        monitor = NetworkMonitor(5, 90)
        logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)
        
        self.assertEqual("", output.getvalue())


    def test_detect_outside_window(self):
        monitor = NetworkMonitor(5, 90)
        logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:31:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:31:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:32:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)

        self.assertEqual("", output.getvalue())


    def test_detect_exact_window(self):
        monitor = NetworkMonitor(5, 90)
        logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:40 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:31:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:31:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)
        
        self.assertIn("ALERT 192.168.1.100", output.getvalue())


    def test_detect_unsorted_timestamp(self):
        monitor = NetworkMonitor(5, 90)
        logs = [
        "Nov 15 12:30:40 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)
                
        self.assertIn("ALERT 192.168.1.100", output.getvalue())


    def test_detect_multiple_ips(self):
        monitor = NetworkMonitor(5, 90)
        logs = [
        "Nov 15 12:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:10 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:20 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
        "Nov 15 12:30:40 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",

        "Nov 15 12:31:00 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2",
        "Nov 15 12:31:10 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2",
        "Nov 15 12:31:20 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2",
        "Nov 15 12:31:30 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2",
        "Nov 15 12:31:40 server sshd[1234]: Failed password for root from 2001:db8::1 port 22 ssh2"
        ]
        output = io.StringIO()
        result = monitor.group_timestamps(logs)
        with redirect_stdout(output):
            monitor.detect_brute_force(result)
                        
        self.assertIn("ALERT 192.168.1.100", output.getvalue())
        self.assertIn("ALERT 2001:db8::1", output.getvalue())
        


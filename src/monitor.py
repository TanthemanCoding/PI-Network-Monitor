from datetime import datetime, timedelta
import ipaddress
import subprocess


class NetworkMonitor:

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

        if self.threshold <= 0:
            raise ValueError("Threshold must be greater than 0")
        if self.window_seconds <= 0:
            raise ValueError("Time window must be greater than 0")

    def detect_brute_force(self, ip_timestamps: dict[str, list[datetime]]) -> None:
        for ip_address, times in ip_timestamps.items():
            times.sort()
            for i in range(len(times) - (self.threshold - 1)):
                difference = times[i + (self.threshold - 1)] - times[i]
                if difference.total_seconds() <= self.window_seconds:
                    print(f"ALERT {ip_address} has {self.threshold} failed attempts within {self.window_seconds} seconds!")
                    break

    def read_logs(self, file_path: str) -> list[str]:
        failed_logs = []
        try:
            with open(file_path, "r") as file:
                for line in file:
                    if "Failed password" in line:
                        failed_logs.append(line.strip())
        except FileNotFoundError:
            print(f"The file path: {file_path} does not exist!")
            return failed_logs
        except PermissionError:
            print(f"Don't have permission to the file path: {file_path}!")
            return failed_logs
        return failed_logs

    def read_ssh_journal(self) -> list[str]:
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "--no-pager"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(result.stderr)
            return []

        logs = result.stdout.splitlines()
        failed_logs = []
        for log in logs:
            if "Failed password" in log:
                failed_logs.append(log)
        return failed_logs

    def group_timestamps(self, failed_logs: list[str]) -> dict[str, list[datetime]]:
        ip_timestamps = {}
        for failed_log in failed_logs:
            ip_address = self.extract_ip(failed_log)
            if ip_address is None:
                continue

            time_stamp = self.extract_time(failed_log)
            converted_time = self.convert_time(time_stamp)
            if converted_time is None:
                continue

            if ip_address in ip_timestamps:
                ip_timestamps[ip_address].append(converted_time)
            else:
                ip_timestamps[ip_address] = [converted_time]
        return ip_timestamps

    def extract_ip(self, log: str) -> str | None:
        words = log.split()
        try:
            from_index = words.index("from")
            ip_address = str(ipaddress.ip_address(words[from_index + 1]))
        except (ValueError, IndexError):
            return None
        return ip_address

    def extract_time(self, log: str) -> str:
        words = log.split()
        return " ".join(words[:3])

    def convert_time(self, timestamp: str) -> datetime | None:
        try:
            year = datetime.now().year
            converted_time = datetime.strptime(
                f"{year} {timestamp}",
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None
        return converted_time

    def monitor_live(self) -> None:
        attempts = {}
        alerted_ips = set()

        result = subprocess.Popen(
            ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager"],
            stdout=subprocess.PIPE,
            text=True
        )

        try:
            for log in result.stdout:
                if "Failed password" in log:
                    ip_address = self.extract_ip(log)
                    if ip_address is not None:
                        timestamp = self.extract_time(log)
                        converted_time = self.convert_time(timestamp)
                        if converted_time is not None:
                            if ip_address not in attempts:
                                attempts[ip_address] = []
                            attempts[ip_address].append(converted_time)
                            cutoff = converted_time - timedelta(seconds=self.window_seconds)
                            recent_attempts = []
                            for time in attempts[ip_address]:
                                if cutoff <= time <= converted_time:
                                    recent_attempts.append(time)
                            attempts[ip_address] = recent_attempts
                            if len(recent_attempts) >= self.threshold:
                                if ip_address not in alerted_ips:
                                    print(f"ALERT: {ip_address} made {self.threshold} failed SSH login attempts within {self.window_seconds} seconds!")
                                    alerted_ips.add(ip_address)
                            else:
                                alerted_ips.discard(ip_address)

        except KeyboardInterrupt:
            print("\nMonitoring stopped")

        finally:
            if result.poll() is None:
                result.terminate()
            result.wait()


def main() -> None:
    monitor = NetworkMonitor(5, 90)
    failed_logs = monitor.read_ssh_journal()
    ip_timestamps = monitor.group_timestamps(failed_logs)
    monitor.detect_brute_force(ip_timestamps)
    monitor.monitor_live()


if __name__ == "__main__":
    main()
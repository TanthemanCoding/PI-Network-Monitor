# Import statements
from datetime import datetime
import ipaddress

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
                # Writing the loop allows the program to read the file one line at a time instead of storing the entire file into a variable
                for line in file:
                    # Only keeps the failed login attempts from the file
                    if "Failed password" in line:
                        # .strip() removes the newline character before adding the line to the list
                        failed_logs.append(line.strip())
        except FileNotFoundError:
            print(f"The file path: {file_path} does not exist!")
            return failed_logs
        except PermissionError:
            print(f"Don't have permission to the file path: {file_path}!")
            return failed_logs
        
        # Returns the list of failed login attempts
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
        # .join puts the list into a string and the " " puts spaces in between the words when calling the function
        return " ".join(words[:3])

    
    def convert_time(self, timestamp: str) -> datetime | None:
        # datetime function helps us convert the string into an actual date time format
        try:
            year = datetime.now().year
            converted_time = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        return converted_time


def main() -> None:
    # Reads the file and stores the failed login entries in a list
    monitor = NetworkMonitor(5,90)
    failed_logs = monitor.read_logs("tests/ip_validation.log")
    ip_timestamps = monitor.group_timestamps(failed_logs)
    monitor.detect_brute_force(ip_timestamps)
    

if __name__ == "__main__":
    main()
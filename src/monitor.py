# Import statements
from datetime import datetime
import ipaddress

def read_logs(file_path: str) -> list[str]:
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


def extract_time(log: str) -> str:
    words = log.split()

    # .join puts the list into a string and the " " puts spaces in between the words when calling the function
    return " ".join(words[:3])


def convert_time(timestamp: str) -> datetime | None:
    # datetime function helps us convert the string into an actual date time format
    try:
        year = datetime.now().year
        converted_time = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return converted_time


def extract_ip(log: str) -> str | None:
    words = log.split()
    try:
        from_index = words.index("from")
        ip_address = str(ipaddress.ip_address(words[from_index + 1]))
    except (ValueError, IndexError):
        return None
    return ip_address


def group_timestamps(failed_logs: list[str]) -> dict[str, list[datetime]]:
    ip_timestamps = {}
    for failed_log in failed_logs:
        ip_address = extract_ip(failed_log)
        if ip_address is None:
            continue
        time_stamp = extract_time(failed_log)
        converted_time = convert_time(time_stamp)
        if converted_time is None:
            continue

        if ip_address in ip_timestamps:
            ip_timestamps[ip_address].append(converted_time)
        else:
            ip_timestamps[ip_address] = [converted_time]

    return ip_timestamps


def detect_brute_force(ip_timestamps: dict[str, list[datetime]], threshold: int, window_seconds: int) -> None:
    if threshold <= 0:
        raise ValueError("Threshold must be greater than 0")
    if window_seconds <= 0:
        raise ValueError("Time window must be greater than 0")
    for ip_address, times in ip_timestamps.items():
        times.sort()
        for i in range(len(times) - (threshold - 1)):
            difference = times[i + (threshold - 1)] - times[i]

            if difference.total_seconds() <= window_seconds:
                print(f"ALERT {ip_address} has {threshold} failed attempts within {window_seconds} seconds!")
                break



def main() -> None:
    # Reads the file and stores the failed login entries in a list
    failed_logs = read_logs("tests/ip_validation.log")
    
    ip_timestamps = group_timestamps(failed_logs)
    
    detect_brute_force(ip_timestamps, 5, 90)


if __name__ == "__main__":
    main()
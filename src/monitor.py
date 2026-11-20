# Import statements

# datetime allows us to work with dates, times, and time differences.
from datetime import datetime

# ipaddress allows us to validate IPv4 and IPv6 addresses.
import ipaddress


# This class contains the functions needed to monitor SSH login failures
# and detect possible brute-force attacks.
class NetworkMonitor:

    # __init__ runs automatically whenever a NetworkMonitor object is created.
    # threshold: Number of failed login attempts needed to trigger an alert.
    # window_seconds: Maximum time allowed between those attempts.
    # self: Refers to the specific NetworkMonitor object being created.
    def __init__(self, threshold: int, window_seconds: int) -> None:
        # Store the configuration settings inside the object.
        self.threshold = threshold
        self.window_seconds = window_seconds

        # Reject invalid settings to prevent creating a monitor
        # with a threshold or time window of zero or less.
        if self.threshold <= 0:
            raise ValueError("Threshold must be greater than 0")
        if self.window_seconds <= 0:
            raise ValueError("Time window must be greater than 0")


    # Detects potential brute-force attacks using grouped login timestamps.
    # ip_timestamps: Dictionary where each IP address has a list
    # of datetime objects representing failed login attempts.
    # Prints an alert when an IP reaches the threshold within the time window.
    # Returns None because this method prints alerts instead of returning them.
    def detect_brute_force(self, ip_timestamps: dict[str, list[datetime]]) -> None:

        # Loop through each IP address and its list of failed login times.
        for ip_address, times in ip_timestamps.items():

            # Sort the timestamps from earliest to latest.
            # This ensures detection works even if logs arrive out of order.
            times.sort()

            # Examine each possible group of consecutive attempts.
            # Subtracting (threshold - 1) prevents going outside the list.
            for i in range(len(times) - (self.threshold - 1)):

                # Calculate how much time passed between the first and
                # last attempts in the current group.
                difference = times[i + (self.threshold - 1)] - times[i]

                # Convert the time difference into seconds and compare it
                # with the configured detection window.
                # <= means an attempt exactly at the boundary still counts.
                if difference.total_seconds() <= self.window_seconds:

                    # Print an alert identifying the suspicious IP.
                    print(f"ALERT {ip_address} has {self.threshold} failed attempts within {self.window_seconds} seconds!")

                    # Stop checking this IP after its first alert.
                    # Continue with the next IP address.
                    break


    # Opens an SSH log file and collects failed password attempts.
    # file_path: Location of the log file we want to read.
    # Returns a list of failed SSH login entries as strings.
    def read_logs(self, file_path: str) -> list[str]:

        # Empty list used to store failed login attempts.
        failed_logs = []

        try:
            with open(file_path, "r") as file:

                # Read the file one line at a time instead of
                # loading the entire file into memory.
                for line in file:

                    # Only keep entries containing "Failed password".
                    # Successful SSH logins are ignored.
                    if "Failed password" in line:

                        # Remove whitespace/newline characters at the
                        # beginning and end before storing the line.
                        failed_logs.append(line.strip())

        # Handle situations where the requested file does not exist.
        except FileNotFoundError:
            print(f"The file path: {file_path} does not exist!")
            return failed_logs

        # Handle situations where we don't have permission to read the file.
        except PermissionError:
            print(f"Don't have permission to the file path: {file_path}!")
            return failed_logs

        # Return the collected failed login entries.
        # If no entries were found, return an empty list.
        return failed_logs


    # Groups failed login timestamps by their source IP address.
    # failed_logs: List of failed SSH login strings.
    # Returns a dictionary containing IP addresses and lists of datetime objects.
    def group_timestamps(self, failed_logs: list[str]) -> dict[str, list[datetime]]:

        # Dictionary that stores each IP address and its failed login times.
        ip_timestamps = {}

        # Examine each failed SSH login entry.
        for failed_log in failed_logs:

            # Extract the source IP address from the current log.
            ip_address = self.extract_ip(failed_log)

            # Skip logs that don't contain a valid IP address.
            if ip_address is None:
                continue

            # Extract the date and time as a string.
            time_stamp = self.extract_time(failed_log)

            # Convert the timestamp string into a datetime object.
            converted_time = self.convert_time(time_stamp)

            # Skip logs containing invalid dates or times.
            if converted_time is None:
                continue

            # If the IP already exists, append another timestamp to its list.
            if ip_address in ip_timestamps:
                ip_timestamps[ip_address].append(converted_time)

            # If this is a new IP, create a dictionary entry with
            # a list containing its first timestamp.
            else:
                ip_timestamps[ip_address] = [converted_time]

        # Return all valid IP addresses and their failed login timestamps.
        return ip_timestamps


    # Extracts and validates the IP address from an SSH log entry.
    # log: One SSH login entry stored as a string.
    # Returns the valid IP address as a string, or None if invalid/missing.
    def extract_ip(self, log: str) -> str | None:

        # Split the log into individual words using whitespace.
        words = log.split()

        try:
            # Find the position of the word "from".
            from_index = words.index("from")

            # The IP address should be the word immediately after "from".
            # ipaddress.ip_address() validates IPv4 and IPv6 addresses.
            # str() converts the validated IP address back into a string.
            ip_address = str(ipaddress.ip_address(words[from_index + 1]))

        # ValueError: "from" is missing or the IP is invalid.
        # IndexError: There is nothing after "from".
        except (ValueError, IndexError):
            return None

        # Return the validated IP address.
        return ip_address


    # Extracts the timestamp from the beginning of an SSH log.
    # log: One SSH log entry stored as a string.
    # Returns the timestamp as a string, such as "Nov 15 12:30:00".
    def extract_time(self, log: str) -> str:

        # Split the log into individual words.
        words = log.split()

        # words[:3] selects the first three elements:
        # Month, day, and time.
        # " ".join() combines them into one string with spaces.
        return " ".join(words[:3])


    # Converts a timestamp string into a Python datetime object.
    # timestamp: A string such as "Nov 15 12:30:00".
    # Returns a datetime object if valid, or None if conversion fails.
    def convert_time(self, timestamp: str) -> datetime | None:

        try:
            # SSH syslog timestamps may not include a year.
            # Use the current year for conversion.
            year = datetime.now().year

            # Combine the year and timestamp into one string.
            # strptime() parses that string using the specified format.
            # %Y = year, %b = abbreviated month, %d = day
            # %H = hour, %M = minute, %S = second
            converted_time = datetime.strptime(
                f"{year} {timestamp}",
                "%Y %b %d %H:%M:%S"
            )

        # Return None if the timestamp contains an invalid date or format.
        except ValueError:
            return None

        # Return the successfully converted datetime object.
        return converted_time


# main() controls the overall flow of the program.
# It creates a monitor, reads logs, groups timestamps, and detects attacks.
# Returns None because its purpose is to execute the program.
def main() -> None:

    # Create a NetworkMonitor object.
    # 5 = failed attempts needed to trigger an alert.
    # 90 = detection time window in seconds.
    monitor = NetworkMonitor(5, 90)

    # Read failed SSH login entries from our test log file.
    failed_logs = monitor.read_logs("tests/real_failed_ssh.log")

    # Organize the failed login timestamps by IP address.
    ip_timestamps = monitor.group_timestamps(failed_logs)

    # Check each IP address and print alerts for suspicious activity.
    monitor.detect_brute_force(ip_timestamps)


# Only run main() when this file is executed directly.
# Importing NetworkMonitor into another file won't automatically run main().
if __name__ == "__main__":
    main()

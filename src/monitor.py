# Import statements
from datetime import datetime

def read_logs(file_path: str) -> list[str]:
    failed_logs = []

    with open(file_path, "r") as file:
        # Writing the loop allows the program to read the file one line at a time instead of storing the entire file into a variable
        for line in file:
            # Only keeps the failed login attempts from the file
            if "Failed password" in line:
                # .strip() removes the newline character before adding the line to the list
                failed_logs.append(line.strip())

    # Returns the list of failed login attempts
    return failed_logs


def count_failures(failed_logs: list[str]) -> dict[str, int]:
    failed_attempts = {}

    for failed_log in failed_logs:
        # Splits string into a list of words
        words = failed_log.split()

        # "from" is the word that appears before the IP address, so .index() gives us the index of where "from" is at
        from_index = words.index("from")

        # Since "from" appears right before the IP and .index() gives us an int, from_index + 1 gives us the index of the IP address
        ip_address = words[from_index + 1]

        # Checks to see if the IP address is already in the dict.
        # If it is, increase its value by 1. If it isn't, assign 1 to its value.
        if ip_address in failed_attempts:
            failed_attempts[ip_address] += 1
        else:
            failed_attempts[ip_address] = 1

    # Returns the dictionary containing each IP and its failed login count
    return failed_attempts


def alert(failed_attempts: dict[str, int], threshold: int) -> list[str]:
    alerts = []

    # .items() helps separate the key and value from the dict so we can check each IP and its count
    for failed_ip, count in failed_attempts.items():

        # Checks if the IP has reached the number of failed attempts required for an alert
        if count >= threshold:
            # Adds the alert message to the list instead of stopping the function
            alerts.append(f"ALERT {failed_ip} has {count} failed login attempts!")

    # Returns the list of alert messages
    return alerts


def extract_time(log: str) -> str:
    words = log.split()

    # .join puts the list into a string and the " " puts spaces in between the words when calling the function
    return " ".join(words[:3])


def convert_time(timestamp: str) -> datetime:
    # datetime function helps us convert the string into an actual date time format
    converted_time = datetime.strptime("2026 " + timestamp, "%Y %b %d %H:%M:%S")
    return converted_time


def main() -> None:
    # Reads the file and stores the failed login entries in a list
    failed_logs = read_logs("tests/sample_auth.log")

    # Passes the failed logs into the function to count attempts by IP address
    failed_attempts = count_failures(failed_logs)

    # Checks which IP addresses have 5 or more failed login attempts
    alerts = alert(failed_attempts, 5)

    # Prints each alert individually instead of printing the entire list
    for message in alerts:
        print(message)

    # Extracts and prints the timestamp from each failed login entry
    for log in failed_logs:
        time_stamp = extract_time(log)
        print(time_stamp)

    time1 = convert_time("Nov 11 19:54:48")
    time2 = convert_time("Nov 11 19:55:20")

    difference = time2 - time1
    print(difference)
    print(difference.total_seconds())
        

if __name__ == "__main__":
    main()
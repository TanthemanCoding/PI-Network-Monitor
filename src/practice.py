def read_logs(file_path: str) -> list[str]:
    failed_logs = []
    with open(file_path, "r") as file:
        for line in file:
            if "Failed password" in line:
                failed_logs.append(line.strip())
    return failed_logs

def count_failures(failed_logs: list[str]) -> dict[str,int]:
    failed_attempts = {}
    for failed_log in failed_logs:
        words = failed_log.split()
        from_index = words.index("from")
        ip_address = words[from_index + 1]
        if ip_address in failed_attempts:
            failed_attempts[ip_address] += 1
        else:
            failed_attempts[ip_address] = 1
    return failed_attempts

def alert(failed_attempts: dict[str,int], threshold: int) -> list[str]:
    alerts = []
    for failed_ip, count in failed_attempts.items():
        if count >= threshold:
            alerts.append(f"ALERT {failed_ip} has {count} failed login attempts!")
    return alerts






failed_logs = read_logs("tests/sample_auth.log")

failed_attempts = count_failures(failed_logs)

alerts = alert(failed_attempts, 5)
print(failed_attempts)

for message in alert_message:
    print(message)
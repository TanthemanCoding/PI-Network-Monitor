recent_attempts = []
alerted_ips = set()
for time in attempts[ip_address]:
    if cutoff <= time <= timestamp:
        recent_attempts.append(time)

attempts[ip_address] = recent_attempts
if len(attempts[ip_address]) >= self.threshold:
    if ip_address not in alerted_ips:
        print("Possible brute-force attack detected!")
        alerted_ips.add(ip_address)
else:
    alerted_ips.discard(ip_address)



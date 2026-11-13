class NetworkMonitor:
    threshold = 5

monitor1 = NetworkMonitor()
monitor2 = NetworkMonitor()

monitor1.threshold=10

print(monitor1.threshold)
print(monitor2.threshold)
print(NetworkMonitor.threshold)


class NetworkMonitor:
    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
    
    def display_settings(self) -> None:
        print(f"Threshold: {self.threshold}, Window: {self.window_seconds} seconds")

    def update_threshold(self, threshold: int) -> None:
        self.threshold = threshold

    def update_window(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds

    def check_threshold(self, attempts: int) -> bool:
        return attempts >= self.threshold

    def detect_brute_force(self, attempts: int) -> None:
        if self.check_threshold(attempts):
            print("ALERT")
        else:
            print("No alert")

monitor1 = NetworkMonitor(5, 60)
monitor2 = NetworkMonitor(10, 120)

#monitor1.display_settings()
#monitor2.display_settings()
#monitor1.update_threshold(8)
#monitor1.display_settings()
#monitor2.update_window(90)
#monitor2.display_settings()
#print(monitor1.check_threshold(7))
#print(monitor1.check_threshold(8))

monitor1.detect_brute_force(4)
monitor1.detect_brute_force(5)
monitor2.detect_brute_force(7)
monitor2.detect_brute_force(10)








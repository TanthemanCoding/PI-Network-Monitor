import subprocess 

process = subprocess.Popen(
    ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager"],
    stdout=subprocess.PIPE,
    text=True
)

for log in process.stdout:
    print(log.strip())


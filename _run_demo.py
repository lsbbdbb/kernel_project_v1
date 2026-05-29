import sys
from paramiko import SSHClient, AutoAddPolicy

client = SSHClient()
client.set_missing_host_key_policy(AutoAddPolicy())
client.connect("100.64.162.82", username="lee", password="040102", look_for_keys=False)

# Find the kernel-livepatch-agent directory first
_, stdout, stderr = client.exec_command("find / -type d -name 'kernel-livepatch-agent' 2>/dev/null | head -5")
paths = stdout.read().decode().strip().split('\n')
print("Found paths:", paths)

target = None
for p in paths:
    if p and 'kernel-livepatch-agent' in p:
        target = p
        break

if not target:
    print("ERROR: kernel-livepatch-agent directory not found")
    client.close()
    sys.exit(1)

print(f"Using directory: {target}")

# Run the script
cmd = f"cd {target} && bash demo.sh"
print(f"Running: {cmd}")
stdin, stdout, stderr = client.exec_command(cmd)

# Print output as it comes
import select
import time

# Wait a bit for initial output
time.sleep(2)

# Read available output
out = stdout.read().decode()
err = stderr.read().decode()
exit_code = stdout.channel.recv_exit_status()

print("STDOUT:")
print(out)
if err:
    print("STDERR:")
    print(err)
print(f"Exit code: {exit_code}")

client.close()

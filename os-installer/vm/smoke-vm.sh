#!/usr/bin/env bash
set -eu

VM_IP="$1"

if [[ -z "$VM_IP" ]]; then
  echo "Usage: $0 <VM_IP>" >&2
  exit 1
fi

pass_count=0
fail_count=0

run_test() {
  local name="$1" cmd="$2"
  if eval "$cmd" > /dev/null 2>&1; then
    echo "PASS: $name"
    ((pass_count++))
  else
    echo "FAIL: $name"
    ((fail_count++))
  fi
}

# 1. SSH reachable
run_test "SSH reachable" "ssh -o StrictHostKeyChecking=no kilas@$VM_IP whoami"

# 2. nasd running (expect HTTP 200 from localhost:8080)
run_test "nasd running" "ssh $VM_IP 'curl -s -f http://localhost:8080/ > /dev/null'"

# 3. ZFS tools present
run_test "ZFS tools present" "ssh $VM_IP 'which zpool'"

# 4. Samba installed
run_test "Samba installed" "ssh $VM_IP 'which smbd'"

# 5. SMART tools present
run_test "SMART tools present" "ssh $VM_IP 'which smartctl'"

# 6. Disk space > 2GB
run_test "Disk space > 2GB" "ssh $VM_IP 'df -h / | awk '\''/\/$/ {if (\$2 ~ /G/ && \$2+0 > 2) exit 0; else exit 1}'\'' || echo 0"'

# 7. Memory > 1GB
run_test "Memory > 1GB" "ssh $VM_IP 'free -m | awk '\''/Mem:/{if (\$2+0 > 1024) exit 0; else exit 1}'\'' || echo 0"'

echo ""
echo "Summary: $pass_count passed, $fail_count failed"

if [[ $fail_count -gt 0 ]]; then
  exit 1
fi

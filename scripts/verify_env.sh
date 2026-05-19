#!/bin/bash
echo "=== 1. System ==="
cat /etc/anolis-release 2>/dev/null || head -3 /etc/os-release

echo ""
echo "=== 2. kpatch-build ==="
kpatch-build --version 2>&1

echo ""
echo "=== 3. kernel-devel ==="
rpm -qa 2>/dev/null | grep kernel-devel

echo ""
echo "=== 4. Python ==="
python3 --version

echo ""
echo "=== 5. pip packages ==="
python3 -c "import requests; print('requests:', requests.__version__)"
python3 -c "import yaml; print('yaml:', yaml.__version__)"

echo ""
echo "=== 6. gcc / make ==="
gcc --version 2>&1 | head -1
make --version 2>&1 | head -1

echo ""
echo "=== 7. Kernel src mount ==="
ls -la /kernel-src/ 2>&1

echo ""
echo "=== 8. Agent tools import ==="
cd /app
python3 -c "from agent.tools.kpatch_builder import KpatchBuilder; print('builder OK')"
python3 -c "from agent.state import StateManager; print('state OK')"

echo ""
echo "=== ALL CHECKS DONE ==="

#!/usr/bin/env python3
"""Patch the frontend: make Start button directly trigger demo.sh (one-click)."""

import re

HTML_PATH = "/home/lee/kernel-livepatch-agent/agent/web/templates/index.html"

with open(HTML_PATH, "r") as f:
    content = f.read()

changes = 0

# ---- Change 1: Add startAgentDemo() function before function showRunForm ----
old_func = "function showRunForm(){"
new_func = (
    "function startAgentDemo(){\n"
    "  fetch('/api/run',{method:'POST'})"
    ".then(function(r){return r.json()})"
    ".then(function(d){if(d.error)showToast('Error: '+d.error,'error');else{showToast('Demo started!','success')}})"
    ".catch(function(e){showToast('Failed: '+e.message,'error')});\n"
    "}\n"
    "function showRunForm(){"
)
if old_func in content:
    content = content.replace(old_func, new_func)
    changes += 1
    print("Change 1 (added startAgentDemo): OK")
else:
    print("Change 1: FAILED")

# ---- Change 2: Replace onclick="showRunForm()" with onclick="startAgentDemo()" on the main start button ----
# The main button is: <span class="btn btn-primary" onclick="showRunForm()">...启动 / Start</span>
old_button = 'onclick="showRunForm()">▶ 启动 / Start'
new_button = 'onclick="startAgentDemo()">▶ 启动 / Start'
if old_button in content:
    content = content.replace(old_button, new_button)
    changes += 1
    print("Change 2 (button now calls startAgentDemo): OK")
else:
    print("Change 2: FAILED - checking with different encoding")
    # Try to match with just the key part
    match = re.search(r'onclick="showRunForm\(\)">.+启动 / Start', content)
    if match:
        original = match.group(0)
        replacement = original.replace('showRunForm()', 'startAgentDemo()')
        content = content.replace(original, replacement)
        changes += 1
        print("Change 2 (via regex): OK")
    else:
        print("Change 2: not found at all")

# ---- Write back ----
with open(HTML_PATH, "w") as f:
    f.write(content)

print(f"Total changes: {changes} — frontend patched.")

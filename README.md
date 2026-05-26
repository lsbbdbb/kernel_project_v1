# Kernel CVE Livepatch Auto-Generation Agent

Anolis OS 鍐呮牳 CVE 鐑ˉ涓佽嚜鍔ㄧ敓鎴愭櫤鑳戒綋銆傝嚜鍔ㄨВ鏋?CVE 鈫?鑾峰彇琛ヤ竵 鈫?鍒嗘瀽 鈫?鏋勫缓 鈫?楠岃瘉銆?
## 褰撳墠鐘舵€?(2026-05-26)

**Docker 鍏ㄦ祦绋嬪凡璺戦€氥€?* 鐩爣鍐呮牳 Anolis 6.6.102-5.2.an23 宸插悎鍏ュ綋鍓?3 涓?sample CVE 鐨勮ˉ涓侊紝agent 姝ｇ‘璇嗗埆骞惰烦杩?鎶ュ憡銆?
### 鏈疆淇

| 淇 | 鏂囦欢 | 璇存槑 |
|------|------|------|
| Source tree 娓呯悊 | `agent/__main__.py:_clean_kernel_source` | 鏂板闈?git 鏍戠殑 .orig 鎭㈠ |
| 涓夐樁娈佃ˉ涓佹鏌?| `agent/__main__.py:_action_apply_patch` | forward 鈫?reverse 鈫?fuzz |
| Docker entrypoint | `docker-entrypoint.sh` | run 妯″紡浼犻€?LLM 鍙傛暟 |

### 涓婃杩愯缁撴灉 (Docker)

| CVE | 鐘舵€?| 鍘熷洜 |
|-----|------|------|
| CVE-2026-43284 | failed | Docker 缃戠粶涓嶅彲杈?git.kernel.org |
| CVE-2026-43018 | skipped | 琛ヤ竵宸插悎鍏?Anolis 鍐呮牳 |
| CVE-2025-38182 | manual_required | kpatch-build: no functional changes found |

### 宸查獙璇侀€氳繃

- CVE-2026-43284 livepatch.ko 鍦?Anolis VM 涓?insmod 鈫?patching complete 鈫?rmmod 鍏ㄧ敓鍛藉懆鏈?- 110 鍗曞厓娴嬭瘯鍏ㄩ儴閫氳繃
- Agent Docker 鍏ㄦ祦绋?pipeline 姝ｅ父杩愯

## 蹇€熶娇鐢?
```bash
# Docker锛堟帹鑽愶級
cd ~/kernel-livepatch-agent
export DEEPSEEK_API_KEY=sk-xxx
docker compose up agent-run

# 瑁告満锛堥渶瑕?kpatch-build + 鍖归厤鐨?GCC锛?python3 -m agent --cves sample_cves.txt --workdir /tmp/run \
  --llm-provider deepseek --llm-model deepseek-v4-pro
```

## 鐜

| 缁勪欢 | 璇存槑 |
|------|------|
| 鏋勫缓鏈嶅姟鍣?| lee@100.64.162.82 (Fedora 43, Docker) |
| 鐩爣 VM | kxr@10.99.2.182 (Anolis OS 23, kernel 6.6.102-5.2.an23) |
| kpatch-build | upstream dynup/kpatch @ 6e58fed |
| GCC (Docker) | 12.3.0-16.an23 (鍖归厤鍐呮牳缂栬瘧鍣? |

## 寰呰В鍐?
1. **闇€瑕佹湭鍚堝叆鐨?CVE** 鈥?褰撳墠 3 涓?sample 鍧囧凡鍚堝叆 Anolis锛岄渶鏂版祴璇曢泦楠岃瘉瀹屾暣 build 鈫?.ko 璺緞
2. **Docker 缃戠粶** 鈥?瀹瑰櫒鍐呭伓灏旀棤娉曡闂?git.kernel.org
3. **澶辫触鍒嗙被** 鈥?`no functional changes found` 搴斿綊绫讳负 `already_applied`

## 椤圭洰缁撴瀯

```
agent/__main__.py        # CLI 鍏ュ彛 + pipeline action executors
agent/state.py           # 18 鐘舵€佺姸鎬佹満
agent/planner.py         # LLMPlanner (2 LLM 鍐崇瓥鐐?
agent/tools/             # 13 宸ュ叿妯″潡
agent/rag/               # BM25 鐭ヨ瘑妫€绱?docker-compose.yml       # 4 鏈嶅姟 (agent/agent-dev/agent-run/agent-run-no-llm)
Dockerfile               # Anolis OS 23 + upstream kpatch-build
```

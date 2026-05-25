# Findings

## Scope Notes
- Project has `README_PLAN.md` with Phase 0 through Phase 6 details.
- Phase 0-5 implementation exists; final environment-backed module loading acceptance is still pending a matching build baseline. Default LLM provider is DeepSeek.

## Initial Code Review
- `agent/tools/kpatch_builder.py` already imports `shutil`.
- `agent/knowledge/loader.py`, YAML rule files, `failure_classifier.py`, and `rewrite_advisor.py` exist and are wired.
- Default LLM provider is DeepSeek (not Qwen as originally planned in README_PLAN.md).

## Fixed Issues
- YAML failure patterns had drifted from the hardcoded fallback; because YAML loads first, matchers such as `error: patch failed`, `error: passing argument`, `section change`, and `ERROR:.*vmlinux` were unavailable at runtime.
- YAML rewrite strategies lacked `missing_include`; `missing_api_or_include` and `undefined_symbol` failures mapped to that strategy but became manual-only because no YAML strategy existed.
- `KpatchBuilder` looked for generated livepatch modules under the kernel source tree only. It now runs `kpatch-build` from the CVE artifacts directory and collects the generated module from artifacts first.
- `LLMPlanner` no longer intercepts `VerifyFailed` — `classify_verify_failure` runs first, ensuring LLM decides on verification evidence rather than stale build failure data.
- `LLMPlanner` `_decide_on_build_failure` attempt indexing fixed: now correctly reads `build_{attempt+1}.log` after rewrites.
- CLI `--llm-provider` now recomputes `api_key` and `base_url` when provider is changed.
- `create_rewrite_plan()` directory creation added — no longer crashes on missing cve_dir.
- All Qwen/DashScope references removed from code — only DeepSeek/OpenAI/Ollama providers remain.
- `retriever.py` BM25 index auto-refreshes when documents are added after retriever creation.

## Verification
- Initial full suite before fixes: 50 passed.
- Full suite after all fixes: 67 passed (13 test files, all green).
- Phase 0-5 checks: 72/72 passed in `verify_all_phases.sh`.
- Integration tests: `tests/test_integration_llm.py` covers LLMClient graceful degradation, LLMPlanner fallback, CLI `--no-llm` end-to-end, and summary.json generation.

## 2026-05-25 Phase 0-5 Audit Corrections
- Confirmed `pytest -q`: 67 passed; `scripts/verify_all_phases.sh`: 72/72 checks passed; `scripts/verify_phase5_rag.sh` returns retrieved chunks.
- Phase 5 is materially implemented: YAML/API chunks, BM25 dependency and retriever, RAG context generation, and validation script are present.
- Prior claim that build-failure attempt indexing is fixed is not consistent with current code: `_action_run_build` writes `build_{attempt}.log` while `LLMPlanner` reads `build_{attempt + 1}.log`.
- CLI provider override is still defective: `DEFAULT_BASE_URLS` is module-level, but `agent/__main__.py` references `LLMConfig.DEFAULT_BASE_URLS`; the provider path falls into the broad graceful-fallback exception.
- Phase 4 safety gate is weakened by design in current code: any responsive LLM can elevate `struct_abi` / `no_fentry` from manual-only to automatic rewrite, while `SemanticValidator` does not prove those transformations safe.
- Phase 4 has functional scaffolding but is not safely complete: fallback rewrites are accepted without `git apply --check`, and locally discovered source trees are not passed to validation unless `KERNEL_SRC` is explicitly set.

## 2026-05-25 Phase 3-4 Repairs
- Removed LLM override of `struct_abi`/`no_fentry` rewrite safety gates; these stay `manual_required`.
- Routed both LLM output and rule fallback through rewrite validation; a failed fallback no longer writes an attempt patch as success.
- `_action_prepare_rewrite` now passes the resolved local kernel source directory into validation, enabling `git apply --check` when the local source tree exists without relying on `KERNEL_SRC`.
- Aligned LLM build-failure diagnosis with builder log naming: initial build reads `build_0.log`, rewritten attempt 1 reads `build_1.log`.
- Replaced broken `LLMConfig.DEFAULT_BASE_URLS` provider override with `_apply_llm_overrides()` using the module-level `DEFAULT_BASE_URLS`, covered by a unit test.
- Updated the Phase 4 verification assertion to require preservation of the manual safety gate under an active LLM.

## Latest Verification
- Focused Phase 3/4/CLI/integration tests: 24 passed.
- Full pytest suite after repairs: 72 passed.
- `scripts/verify_phase5_rag.sh`: passed; 29 knowledge chunks loaded with representative retrieval results.
- `scripts/verify_all_phases.sh`: 72 passed, 0 failed.

## 2026-05-25 Phase 4-5 Acceptance Completion
- A substantive context-divergence fixture now proves that the original patch fails `git apply --check`, an LLM-produced adaptation preserves the security check, passes `SemanticValidator` plus target-tree `git apply --check`, and is handed to `kpatch-build` as `attempt_1.patch`.
- Fixed an uncovered LLM rewrite defect: fenced diff extraction removed the final newline and could make an otherwise valid generated patch fail Git parsing.
- `git apply --check` failures no longer advance to `PatchApplied`; they produce failure evidence and enter classification/rewrite flow.
- `_rule_based_rewrite()` behavior is explicitly covered: hunk-header offset adjustment and API/include annotations are emitted, while strict validation prevents an offset-only attempt from masquerading as a repair for real context divergence.
- Added `KernelConfigChecker`, resolving patched `.c` files through Kbuild Makefiles and target `.config`. On the checked Anolis 6.6.102 source tree, `drivers/block/ublk_drv.c` maps to disabled `CONFIG_BLK_DEV_UBLK` and `net/bluetooth/hci_core.c` maps to disabled `CONFIG_BT`; both are automatically `skipped`.
- Added runtime VM verification wiring via `--vm-host`: module transfer, `insmod`, `/sys/kernel/livepatch/<module>` visibility, `rmmod`, and retained `dmesg` evidence. An opt-in validated `--vm-poc /absolute/path` runs a pre-provisioned VM-side PoC and makes its return code part of acceptance. Unit tests cover pass, failed-load attribution, and unsafe PoC-path rejection.
- A real Anolis VM with the built `.ko` and an authorized CVE PoC was not available in this workspace, so actual runtime load and exploit-regression execution remain an environment-backed acceptance step rather than a claimed result.

## Latest Verification After Acceptance Repairs
- Full pytest suite: 84 passed.
- `scripts/verify_all_phases.sh`: 72 passed, 0 failed.
- `scripts/verify_phase5_rag.sh`: passed; rule additions increased loaded YAML/API chunks to 31.

## 2026-05-25 Follow-up Audit Repairs
- Reproduced a locale-dependent apply-failure failure: under a Chinese Git locale, stderr no longer matches the English failure rules. Agent-owned `git apply --check` invocations now force `LC_ALL=C` and `LANG=C`, making evidence/classification deterministic.
- Refined CONFIG-aware skipping: a patch is `skipped` only when every patched target can be established as disabled. A mixed patch containing a disabled optional object and an unresolved/build-relevant object continues through validation.
- Closed an LLM safety bypass in `LLMPlanner`: after deterministic classification, `manual_required` and `skip` decisions now take priority, so an LLM cannot turn load failures, ABI/data changes, or disabled-module outcomes into automatic rewrites.
- Preserved rewrite provenance after failed rebuilds: classification now merges `failure` evidence into `attempt_N.json` rather than overwriting the generated patch and rewrite-source record.
- `--vm-poc` represents a VM-side verification checker whose exit code `0` means the mitigation holds; it must not be passed an exploit binary whose successful exploitation returns `0`.
- Runtime verification now rejects a reachable but wrong-kernel VM before `insmod`: it compares remote `uname -r` to the requested target kernel and records `kernel_match=false` on mismatch.

## Verification After Follow-up Audit
- Full pytest suite: 89 passed.
- `scripts/verify_all_phases.sh`: 72 passed, 0 failed.
- Global `git diff --check` is blocked by a pre-existing/unowned modification in `sample_cves.txt`; repaired implementation and tests are checked separately.

## 2026-05-25 Real Docker/VM Acceptance Findings
- Ran the actual `sample_cves.txt` list in the Anolis Docker builder and retained evidence under `run_acceptance_20260525_r4/`.
- The buildable sample `CVE-2026-43284` applies cleanly, but its target source reports `make kernelrelease` as `6.6.102-gcb8aaa58ca2c`, while the supplied VM runs `6.6.102-5.2.an23.x86_64`. It is unsafe to build or load a livepatch from this baseline.
- Earlier exploratory runs exposed three environmental defects: SELinux denied writes through an unlabeled kernel-source mount, Git rejected container ownership, and the packaged `kpatch-build` calls `scripts/setlocalversion --save-scmversion`, which the current Anolis source script does not implement.
- Added a pre-build release gate, classifications for kernel mismatch and setlocalversion incompatibility, SELinux-labelled mounts, and safe-directory setup. The pipeline now stops before kpatch touches a mismatched tree.
- A transient `git.kernel.org` network failure for `CVE-2026-43018` formerly became a placeholder patch; fetch failure now remains a failed acquisition with `patch_source.json` evidence.
- `CVE-2025-38182` successfully downloaded and was correctly skipped with `CONFIG_BLK_DEV_UBLK=not_set`, proving the config-aware skip on a real patch.
- Removed silent source-tree `git checkout`/`git clean` and automatic `olddefconfig` from the build path. A verification run may not erase or change an operator's kernel baseline without an explicit remediation step.
- The VM is reachable only up to SSH host-key verification from this environment. Runtime loading remains pending confirmation of ED25519 fingerprint `SHA256:SVO+9zr9oo60EaNJSzC2ZDFtzW/iFAQHgWY04jFJKks`, retrieval of the VM config/matching build inputs, successful `livepatch.ko` construction, and then `insmod`/sysfs/`rmmod`/`dmesg` verification.

## 2026-05-25 VM Baseline Collection
- The user accepted the expected ED25519 host key and installed key-based SSH access; `ssh -o BatchMode=yes` now returns `6.6.102-5.2.an23.x86_64`, confirms passwordless sudo, and reports `CONFIG_LIVEPATCH=y`.
- VM package inventory contains `kernel-6.6.102-5.2.an23.x86_64` and matching kernel tools, but not `kernel-devel-6.6.102-5.2.an23.x86_64` or kernel debuginfo; `/lib/modules/.../build` is a dangling link.
- VM `/boot/config-6.6.102-5.2.an23.x86_64` differs materially from the currently mounted source `.config`: VM has `# CONFIG_LOCALVERSION_AUTO is not set`, `CONFIG_MODVERSIONS=y`, module signing enabled, and `CONFIG_DEBUG_INFO_BTF=y`/`CONFIG_DEBUG_INFO_BTF_MODULES=y`; current local baseline has automatic Git localversion and no modversions/signing/BTF.
- Inference: the local defconfig-built `vmlinux` is not a trustworthy runtime target even aside from its different release string. The next build must use exact VM config and matching Anolis kernel source/debuginfo artifacts.
- Downloaded the official matching source, devel, and debuginfo RPMs into `acceptance_vm_20260525/packages/` and stored SHA-256 digests. The devel `.config` hashes identically to the VM config and its generated release is exactly `6.6.102-5.2.an23.x86_64`.
- Extracted an isolated RPM source tree and precise debuginfo `vmlinux`. Reproduced the RPM spec setup by setting `EXTRAVERSION = -5.2.an23.x86_64`; added a recorded compatibility branch because installed `kpatch-build-1.0.0-3.an23` calls `scripts/setlocalversion --save-scmversion`, while this Anolis kernel script predates that option.
- `make olddefconfig`/`modules_prepare` in the container yields the exact target release. The sole config diff versus the official/VM config is `CONFIG_CC_VERSION_TEXT`: the VM/RPM was built with Anolis GCC package revision `-16`, while the current Anolis build image has revision `-17` of GCC 12.3.0. This is an explicit residual build risk while the existing builder uses `--skip-compiler-check`.

## Verification After Real Acceptance Repairs
- Focused safety/build tests: 41 passed.
- Full pytest suite: 102 passed.
- `git diff --check` passed for the modified implementation and test files.

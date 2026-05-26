# Task Plan: Phase 0-2 Review And Fix

## Goal
Review and repair code completed before Phase 3, then summarize implementation status for the user.

## Phases
| Phase | Status | Notes |
|---|---|---|
| 1. Restore phase scope | complete | Phase 0 is Docker/Anolis build env; Phase 1 is kpatch_builder import + YAML-backed rules; Phase 2 is LLM config/client/prompts. |
| 2. Run current tests | complete | Initial full suite passed, then review found hidden coverage gaps. |
| 3. Fix defects | complete | YAML rule parity and kpatch artifact discovery fixes applied. |
| 4. Verify | complete | Focused tests and full suite pass. |
| 5. Explain status | complete | Ready to summarize completed work, repaired issues, and remaining Phase 3+ gaps. |
| 6. Phase 3 code review | complete | Reviewed LLMPlanner, CLI LLM wiring, and Phase 3 verification coverage. |
| 7. Phase 0-5 status audit | complete | Phase 5 scaffolding and retrieval verified; Phase 3/4 still have correctness/safety issues despite green scripts. |
| 8. Phase 3-4 safety repair | complete | Fixed four audit findings; full tests and Phase 0-5 verification pass with corrected safety assertion. |
| 9. Phase 4-5 acceptance gaps | complete | Real divergent-context closure, rebuild-loop coverage, VM runtime wiring, and CONFIG-disabled skipping implemented and verified where local environment permits. |
| 10. Phase 5 follow-up audit | complete | Fixed locale-dependent classification, mixed-patch config skipping, non-retryable LLM bypass, and rewrite evidence retention. |
| 11. Environment-backed acceptance | complete | Exact RPM/config/debuginfo/GCC baseline produced `build_r9_external_vmlinux/.../artifacts/livepatch.ko`, and authorized VM module runtime validation passed without PoC. |
| 12. Function-padding toolchain remediation | complete | Pinned upstream kpatch commit `6e58fedec8d04fd5e7963c89eb2f906dba21a949`, installed its matching templates, used immutable debuginfo `VMLINUX_PATH`, and generated a strict `.ko` despite target `CONFIG_CALL_PADDING=y`. |
| 13. VM runtime module acceptance | complete | After authorized removal of historical residue using livepatch disable-then-rmmod, candidate transfer/hash check/insmod/sysfs/dmesg/disable-then-rmmod all passed on `kxr@10.99.2.182`; PoC explicitly not run. Evidence in `acceptance_vm_20260525/runtime_r10_vm_load/`. |

## Errors Encountered
| Error | Attempt | Resolution |
|---|---|---|
| `git apply` hunk-failure test fails under Chinese locale because log matchers expect English | 1 | Pin agent-owned Git applicability checks to `LC_ALL=C` and cover locale override. |
| Existing test expected LLM ownership for a `struct_or_data_change` manual decision | 1 | Updated assertion: deterministic non-retryable safety gates now take precedence over LLM output. |
| Global `git diff --check` reports whitespace in modified `sample_cves.txt` outside the repaired paths | 1 | Left the unrelated CVE-list content untouched; validated edited implementation/test files separately. |
| Docker kpatch build first failed writing mounted `vmlinux`, then failed Git ownership validation | 1-2 | Added SELinux-labelled source mounts, safe-directory entrypoint setup, and explicit environment classification. |
| Real build exposed source release `6.6.102-gcb8aaa58ca2c` against VM target `6.6.102-5.2.an23.x86_64` | 3-4 | Added pre-build kernel release gate and `kernel_mismatch` evidence; acceptance awaits a correctly prepared target baseline. |
| Network failure wrote a placeholder patch which reached apply/build stages | 3 | Fetch failures now stop as failed evidence; parser rejects files with no unified diff. |
| VM lacks installed matching `kernel-devel` and debuginfo; local `.config` differs in modversions/signing/BTF/localversion policy | 5 | Do not reuse defconfig baseline for live load; acquire exact target packages/config and rebuild in an isolated baseline. |
| Exact-release kpatch build fails at `GENKEY certs/signing_key.pem`: `/bin/sh: openssl: command not found` | 6 | Add the `openssl` executable package to the Anolis builder image; `openssl-devel` alone supplied headers, not the signing command. |
| Current build action silently regenerates config, accepts detected release as expected, and cleans source after build | 6 | Re-audit and restore target-release validation against run config without hidden baseline mutation or cleanup. |
| Repaired-image run reveals builder uses `--skip-compiler-check` while official/kernel-image GCC RPM revisions differ | 7 | Abort non-strict build and remove compiler-check bypass; acquire matching compiler before runtime load acceptance. |
| Strict GCC-matched real build fails in `create-diff-object`: symbols at offset `16` in function sections | 8 | Preserve failure as `kpatch_limit.symbol_section_offset`; VM config enables `CONFIG_CALL_PADDING=y`, and repository has no newer `kpatch-build` to upgrade. Do not load until a padding-capable toolchain can produce a strict artifact. |
| Packaged tool rejects valid 16-byte function prefixes while upstream source contains `sym->pfx` expected-offset handling | 9 | Experiment with upstream `dynup/kpatch` toolchain in an isolated container; retain strict VM-matching config/compiler gates. |
| Existing upstream experiment was not reproducible through the default image, which still selected Anolis packaged `kpatch-build` | 10 | Pin the successful upstream build-tool commit in `Dockerfile` and record `KPATCH_BUILD_BIN` / `KPATCH_BUILD_REF` in build result evidence. |
| Image rebuild using Git smart protocol failed fetching pinned upstream commit: `RPC failed; curl 55 Failed sending data to the peer` | 11 | Fetch the pinned GitHub source tarball with curl retry during image build instead of relying on `git fetch`. |
| Rebuilt image with upstream binaries failed at startup: `cp: cannot stat '/usr/local/share/kpatch/patch'` | 12 | Install the same upstream commit's `kmod` patch templates along with `kpatch-build`; the build script needs both artifacts. |
| Standard upstream build using source-tree `vmlinux` hit permission errors after kpatch backs up/rebuilds bind-mounted inputs | 13 | Add explicit `VMLINUX_PATH` and `KERNEL_DEVEL_PATH` pipeline inputs; run strict acceptance against extracted immutable RPM debuginfo `vmlinux`, not the mutable source-tree output. |
| No VM target/checker is present in repository or environment (`VM_HOST=` and `VM_POC=`) | 14 | Stop after module metadata verification; request authorized host and mitigation-checker path before any transfer, load, unload, or PoC execution. |
| Public-key SSH from this execution environment is rejected by `kxr@10.99.2.182`, while user-provided password authentication succeeds | 15 | Use password only as the authorized connection fallback for this validation run; do not persist it in repository evidence. |
| Target VM already exposes enabled `/sys/kernel/livepatch/livepatch_original` before this run transfers an artifact; `/tmp/livepatch.ko` is absent | 16 | Do not overwrite or unload an unknown active patch without explicit confirmation; request authorization for cleanup and a clean reload test. |
| User observed `modinfo livepatch_original` not found, but a fresh VM recheck still shows `/sys/kernel/livepatch/livepatch_original` and `lsmod` entry | 17 | Treat `modinfo` as an on-disk metadata lookup only; loaded-module state is governed by sysfs/`lsmod`, so acceptance remains blocked pending explicit unload authorization. |
| Direct `rmmod livepatch_original` on an enabled livepatch returns `Module ... is in use` | 18 | Disable via `/sys/kernel/livepatch/<name>/enabled`, wait for transition completion, then call `rmmod`; apply the same sequence in `Verifier`. |

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
| 11. Environment-backed acceptance | in_progress | VM SSH/key/sudo/livepatch checks passed; Docker real-sample run correctly blocks mismatched source. Preparing an exact VM-matching source/config/debuginfo baseline before module loading. |

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

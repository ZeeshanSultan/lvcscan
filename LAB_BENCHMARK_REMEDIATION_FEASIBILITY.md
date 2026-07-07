# Laravel CVE Benchmark — Remediation Feasibility

> ## ✅ EXECUTION LEDGER (what was actually done)
> The feasibility analysis below is preserved as written. Status of each item (all fixes verified live; 170/170):
>
> **DONE — systemic:** proof-of-execution nonce gate ✅ · version gate (43617) ✅ · 6 honest relabels ✅ ·
> failing test + workbook drift ✅ · dedup/label of 2870≡2886 ✅.
>
> **DONE — faithful rebuilds (verified with real RCE):** CVE-2025-54068 (real authed sink) ✅ ·
> CVE-2021-43617 (real 8.70.2 `.phar` bypass) ✅ · CVE-2018-15133 (real `.env` key leak+recover) ✅ key-axis ·
> CVE-2026-23524 (real `laravel/reverb` 1.6.3 → root RCE + real 1.7.0 hardened) ✅.
>
> **DONE — honestly documented (empirically NOT faithfully rebuildable):** CVE-2020-24940/24941 — booted the
> lab and confirmed the framework `$guarded` holds against JSON-path/nested/table-prefix keys, so the advisory's
> guarded bypass does not reproduce ✅ · CVE-2020-19316 — Windows-only `mklink`, infeasible on this Linux host ✅ ·
> CVE-2021-28254 — `/deserialize` sink is inherent to the CVE, gadget genuine ✅.
>
> **NOT DONE (marginal / hard, deliberately deferred):** CVE-2024-52301 detector no longer keying on the lab
> marker (low realism gain) · CVE-2018-15133 reaching the real `EncryptCookies` cookie-decrypt path (blind-OOB rework).
> `tools/lab_matrix_runner.py` still absent (the scratch driver built during validation is a starting point).
>
> **Not started (still-hand-rolled hardened twins):** the systemic "hardened twins must apply the real vendor fix"
> item (§Part 1 #3) was addressed for the rebuilt labs (43617 blocklist, 26-23524 reverb 1.7.0, 54068 patched
> Livewire) but not swept across every remaining lab.

---

Companion to `LAB_BENCHMARK_AUDIT.md` + `LAB_BENCHMARK_EVIDENCE_APPENDIX.md`.
For every gap: can detection / exploitation / lab be made **realistic** (would work against a genuine vulnerable deployment), and what does it cost?

**Feasibility scale:** 🟩 HIGH (config/label/wire-existing-code) · 🟨 MEDIUM (real rebuild, doable on this infra) · 🟧 HARD (infra or fundamental constraints) · 🟥 INFEASIBLE (the claimed vuln does not exist as described).

---

## Part 1 — Systemic fixes (highest leverage; fix these first)

### 1. Proof-of-execution gate on `success=True` — 🟩 HIGH
**Root cause of the worst rigging.** Faithful module `cve_2021_3129.py:324-340` wraps each command in a **per-run random marker** (`printf '<rand>_START'; (cmd) 2>&1; printf '<rand>_END'`) and only accepts output found *between* those random delimiters. The faked/weak modules instead match **static markers** — `cve_2024_55661.py:376` and `cve_2022_2870.py` look for a literal `uid=`, which a lab hardcodes (`pulse/app/index.php:184`).
**Fix:** make the random-marker wrap+extract the *mandatory* success contract for every command-capable module, and enforce it centrally in `modules/helpers/pipeline.py:normalize_exploit_result` — `success=True` requires an `evidence` blob containing the per-run nonce the module injected. A reflected constant or echoed source can no longer score.
**Effort:** ~1–2 days (shared helper already exists in 3129; retrofit the other command modules + add the central assertion). **Impact:** auto-neutralizes CVE-2024-55661 and CVE-2022-25838, and hardens every real RCE. **Do this first.**

### 2. Affected-version gate before "vulnerable"/exploit — 🟩 HIGH
`version_suppresses` already exists (`modules/registry/exploit.py:19`). Today a wrong-version lab (43617 on Laravel 11) still reports vulnerable.
**Fix:** require the fingerprinted version to fall inside the advisory's affected range (from `metadata.py`) before a confirmed verdict; otherwise cap at `version_mismatch`. **Effort:** ~1 day. Prevents the whole "wrong version passes" class.

### 3. Hardened twins must apply the real vendor fix — 🟨 MEDIUM
Several twins block at the web/nginx tier (e.g. 403 on `/storage/*.php`, 21546/55555) instead of the actual patch → weak negative control.
**Fix:** per lab, swap to the real remediation (version bump or the vendor config/code change). Trivial where the fix is a version bump; needs the patched package otherwise. **Effort:** ~0.5 day/lab.

### 4. Detection independent of lab-only signals — 🟨 MEDIUM
Detection leans on web-served `composer.lock` and lab marker strings (e.g. `cve_2024_52301.py:166` matches the lab's own marker). Real hosts rarely expose these.
**Fix:** key on signals present on real deployments (response headers, real error fingerprints, behavioral probes) and accept honest `version_applicable`/`candidate` when unprovable. **Effort:** ~0.5 day/module. Trade-off: lower "confirmed" rate, higher honesty.

### 5. Housekeeping — 🟩 HIGH (hours)
Dedup 2886≡2870; regenerate the CVE-2025-49132 workbook cell (fixes the failing `test_workbook_preconditions_match_unified_cve_metadata`); add the missing CVE-2016-10074 workbook row or drop it; collapse to one workbook source of truth; **write the missing `tools/lab_matrix_runner.py`** (the driver I built in scratchpad is a working starting point).

---

## Part 2 — Per-CVE feasibility

### Group A — Wire the real path / relabel (🟩 HIGH, cheap, do next)

| CVE | Action | Why feasible |
|---|---|---|
| **CVE-2025-54068** | Drop the lab `PublicDemo`/`/demo` glue; drive detect+exploit through the **real authenticated** `PersonalAccessTokens` component (untyped `$name` exists in stock 8.1.18). | The module already supports `-U/-P`; the faithful sink is real. **Just stop using the synthetic shortcut.** |
| **CVE-2025-27515** | Reclass `--list`/`metadata.py` to **validation-bypass** (advisory: "Not directly RCE"). Keep RCE only as an explicitly app-dependent, labeled chain. | Bypass itself is already faithful on 11.44.0; only the label is wrong. |
| **CVE-2023-43661** | Relabel `chained_rce` → **SSTI/config-disclosure**; have the module **create** the malicious IncidentTemplate via the authed API instead of pre-seeding it (`entrypoint.sh:124`). | Creating a template is a real authed-user capability; removes the seeded-artifact crutch. |
| **CVE-2022-2870 / 2886** | **Dedup to one**; relabel as "insecure app `unserialize()` pattern" demo, not a framework CVE. | They are disputed non-framework entries; can't be a framework RCE (see 🟥 below). |
| **CVE-2016-10074** | Move out of the Laravel core catalog; if kept, reclassify as a **SwiftMailer dependency** finding. | It is a SwiftMailer CVE; realism as "Laravel" is impossible (see 🟥). |

### Group B — Real rebuild, feasible on this infra (🟨 MEDIUM)

| CVE | Rebuild to make it realistic | Effort / notes |
|---|---|---|
| **CVE-2021-43617** | Laravel **≤8.70.2** app validating uploads with `mimes:`/`image`; defeat it with a **`.phar`** on Debian (`application/x-httpd-php`) — the actual bug. | Medium. Needs Debian MIME config + a real validated endpoint. Makes detection+exploit genuinely CVE-specific. |
| **CVE-2018-15133** | Recover APP_KEY from the exposed `/.env` via existing `appkey_recovery.py` **instead of injecting** `--app-key`; reach the framework's real `EncryptCookies`+`serialize=true` cookie-decrypt path instead of `/decrypt-token`. | Medium. Recovery infra already exists; wiring the real cookie path is the work. |
| **CVE-2021-28254** | Replace the contrived `/deserialize` route with a **plausible real app sink** (a cache/queue/session payload path that unserializes). Gadget is already genuine. | Medium. Or keep as a clearly-labeled "requires app unserialize sink" class demo. |
| **CVE-2026-23524** | Vendor **real `laravel/reverb` 1.6.3** with `REVERB_SCALING_ENABLED`, reachable Redis, and use a **real phpggc chain** against an autoloadable gadget + **POST-callback OOB** (module supports both) instead of the planted `ChainedBatchTruthTest` + `/reverb-oob`. | Medium–High. Sink + precondition are real; gadget/OOB realism is the effort. |
| **CVE-2020-24941** | Make the model guard a **sensitive** column and show the JSON-path key writing it on 6.18.34 vs blocked on 6.18.35. | Medium. Then it demonstrates a real authz boundary crossing. |

### Group C — Hard or fundamentally infeasible (🟧 / 🟥)

| CVE | Verdict | Reason |
|---|---|---|
| **CVE-2020-19316** | 🟧 HARD | Real bug is **Windows-only `mklink`**. Not reproducible on this Linux Docker host without Windows containers; the Linux `ln` route is not the CVE. Recommend: scope Windows-only + mark "not reproduced," or drop. |
| **CVE-2017-14775** | 🟥 INFEASIBLE as RCE | It is a **timing side-channel** (info disclosure). Realistic RCE is impossible (wrong bug); realistic remote timing-token recovery is not achievable over HTTP (why no public PoC exists). Recommend: relabel Medium info-disclosure, drop the RCE/seeded-cred chain. |
| **CVE-2020-24940** | 🟧 HARD to show real impact | The module's own docstring concedes a dotted key **cannot reach a guarded column** on either version — so it can only over-write already-fillable attributes. Best: relabel to the narrow real behavior; a convincing priv-esc demo isn't achievable from this mechanism. |
| **CVE-2022-2870 / 2886** | 🟥 INFEASIBLE as framework CVE | VulDB-disputed, no framework file/commit/fix. There is no framework bug to reproduce; only an app-code `unserialize()` pattern. Keep as a labeled demo, not a CVE pass. |
| **CVE-2016-10074** | 🟥 INFEASIBLE as Laravel | SwiftMailer package CVE; realistic only as an old-Laravel (4.x/5.0) + `sendmail` transport + attacker-controlled `From` dependency lab — niche, and not "Laravel core." |
| **CVE-2024-52301** | 🟨 vuln real / 🟧 detection | The env-flip is real, but **realistic detection is inherently hard** (real apps don't echo `app()->environment()`). Best achievable: detect the precondition (`register_argc_argv=On` + affected version) and mark exploit as app-observability-dependent; remove the lab-marker special-casing. |

### Group D — Already faithful (no work; keep as the real capability)
CVE-2021-3129, 2017-16894, 2024-29291, 2025-14894, 2024-47823, 2024-48987, 2024-55555, 2024-55556, 2024-22836, 2023-46865, 2020-5256, 2025-49132, 2024-21546 (authed labs). The three default-APP_KEY deserialization RCEs are the strongest real exposure.

---

## Part 3 — Recommended sequencing

1. **Systemic #1 (proof-of-execution gate) + #2 (version gate) + #5 (dedup/test/runner).** Highest leverage; auto-kills fabricated success and wrong-version passes. ~3–4 days.
2. **Group A relabels/wire-real-path.** Cheap honesty + one genuine win (54068). ~2–3 days.
3. **Systemic #3/#4 (real hardened twins, honest detection).** ~1 week across the suite.
4. **Group B rebuilds** where a faithful lab is worth the cost (prioritize 43617, 18-15133, 26-23524). ~1–2 weeks.
5. **Group C:** relabel/scope/drop — do not attempt to force realism where the bug doesn't support it.

**Net:** ~13 CVEs are already production-honest today. With Part 1 + Group A (~1.5 weeks) the benchmark stops reporting fabricated/wrong-version passes and gains one more faithful CVE (54068). Group B can lift several 🟡→🟢 over a further 1–2 weeks. A hard floor of ~6 CVEs (19316, 17-14775, 24940, 2870, 2886, 16-10074) cannot be made a realistic Laravel RCE and should be relabeled, scoped, or removed — not "fixed."

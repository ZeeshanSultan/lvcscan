# Laravel CVE Benchmark — Engineering Audit

> ## ⤴ SUPERSEDING UPDATE — 3 more CVEs now faithful (advisory reconciliation)
> After a per-CVE advisory re-check, three items in the body/status below were re-verified and turned
> out **better than first assessed** — all now 🟢 faithful and matching their advisories:
> - **CVE-2023-43661 (Cachet)** — NOT disclosure-only. Verified real **chained RCE** (SSTI→APP_KEY→Laravel 5.2 X-XSRF deser via Guzzle/RCE1 → `uid=33(www-data)`). Class restored to `ssti_chained_rce` (the earlier relabel to `ssti_config_disclosure` had understated it AND broken the auto-chain).
> - **CVE-2020-24940** — NOT a strawman. Verified via the emitted SQL that `users.is_admin` defeats the app key-filter and writes `is_admin=1` (bare key blocked) — a genuine table-name-stripping priv-esc (CWE-20).
> - **CVE-2022-25838 (Fortify)** — rebuilt faithful: real TOTP validation, secret never disclosed, `/otp-intercept` models the AC:H captured code, vuln allows replay / hardened rejects reuse.
> So the "hard floor / not-rebuildable" claims below for 24940 and 43661 are **superseded**.
>
> ## ✅ REMEDIATION STATUS (post-audit update)
> The body below is the **as-found** forensic record (what was rigged/broken at audit time). It is
> preserved intact. The following was subsequently fixed and **verified live** (suite 170/170 throughout):
>
> **Systemic (commit `ef53feb`, `df5b29c`)**
> - Proof-of-execution **nonce gate** — `success=True` now requires a per-run random marker in real
>   command output; a lab echoing a constant `uid=` can no longer score (killed CVE-2024-55661's fake RCE).
> - **Version gate** (fail-open) on CVE-2021-43617 — patched hosts that leak their version no longer false-positive.
> - **6 honest relabels** (17-14775→timing, 23-43661→ssti/disclosure, 25-27515→validation-bypass,
>   16-10074→swiftmailer, 22-2870/2886→disputed) so `--list` stops overclaiming.
> - **Failing test fixed** + workbook/metadata drift synced (170/170).
>
> **Faithful lab rebuilds — verified with real root/authenticated RCE**
> - **CVE-2025-54068** (`6dc8737`) → real authenticated Snipe-IT `PersonalAccessTokens` component (dropped synthetic `/demo`). 🟢
> - **CVE-2021-43617** (`c4945b5`) → real Laravel 8.70.2 `.phar`/`mimes` framework bypass on Debian. 🟢
> - **CVE-2018-15133** (`665d7d6`) → real random APP_KEY leaked via `/.env`, recovered (not injected). Key axis 🟢 (sink still lab-provided).
> - **CVE-2026-23524** (`40b27b3`) → **real `laravel/reverb` 1.6.3** + Redis + real phpggc gadget → **root RCE**; real 1.7.0 hardened twin. 🟢
>
> **Remainders empirically resolved (`69f5169`)** — 24940/24941 guarded-bypass **verified NOT reproducible**
> (framework guard holds), 19316 Windows-only (infeasible on Linux), 28254 sink inherent to the CVE. All now
> honestly labeled rather than faithfully rebuildable.
>
> **Net:** Tier-A fabricated success eliminated; ~16 CVEs faithful; the rest honestly labeled. See
> `LAB_BENCHMARK_REMEDIATION_FEASIBILITY.md` for the full done/not-done ledger.

---

**Subject:** Faked results and non-green defects in the CVE scanner + vuln-labs
**Scope:** `lvcscan/` scanner (`check.py`, `modules/cves/*`), `vuln-labs/*`, `docs/Laravel_Vulnerabilities.xlsx`
**Method:** (1) built + booted all 30 lab containers and ran `check.py` detect/exploit against each vulnerable port + hardened twin (`--json-out -`), (2) cross-checked every CVE against its public advisory (NVD / GitHub Security Advisory / vendor), (3) read each lab's `docker-compose.yml`, `entrypoint.sh`, `exploit.py`, and the scanner module to compare the *real* attack surface against what the lab manufactures.
**Bottom line:** the benchmark shows "30/30 green," but green means "matches the lab," not "works on a real target." **9 CVEs are faked/misattributed, 8 are real bugs with a staged precondition, ~13 are faithful.** All findings below are verified first-hand. No code was changed.

---

## How the "green" is misleading

Every lab passed its own matrix in the container run (detect ✓ / exploit ✓ on the vuln port / blocked on the hardened twin). But two labs return a **hardcoded success string** — the container run still scored them `EXPLOITED`. That is the core problem: **`success=True` is not backed by a real side effect**, so a rigged target trivially produces a green result.

The rigging is **entirely concentrated in the `framework/` and `first-party/` "minimal harness" labs** (hand-written PHP, no real product). Every `apps/` lab that runs a real upstream application at the correct vulnerable version is faithful. This reads as documented lab-design shortcuts that were then reported as clean passes — not concealed fraud (the modules/README often admit the shortcuts in comments) — but it must not ship as a production capability claim.

---

## SECTION 1 — FAKED / MISATTRIBUTED (9 CVEs, must not be reported as exploited)

### Tier A — Fabricated success: nothing executes

#### CVE-2024-55661 (Pulse) — hardcoded RCE output
- **Real vuln:** Livewire `remember()` is public → invocation of no-arg callables. Authenticated, limited impact. Not an APP_KEY→deserialization RCE.
- **What was faked:** the lab does **not** vendor `laravel/pulse`; it is a hand-written `app/index.php`.
  - `index.php:8` — bakes a null key `$appKey = 'base64:AAAA…='`.
  - `index.php:184` — the `/decrypt-token` endpoint literally does `echo "uid=33(www-data) gid=33(www-data) …"`. **No `unserialize`, no `system`, no execution.** The scanner forges a gadget, POSTs it, and reads back the constant string as "RCE proof."
  - Misattributed: sold as a 2018-15133-class chain, which is not what CVE-2024-55661 is.
- **Container run:** scored `EXPLOITED` against a canned string.
- **Required fix:** rebuild against genuine `laravel/pulse` exercising the real `remember()` callable path, or remove from the benchmark. Never present as RCE.

#### CVE-2022-25838 (Fortify) — secret handed out, any code accepted
- **Real vuln:** a valid TOTP code can be replayed within its ~30s window. Marginal, high-complexity.
- **What was faked:** hand-written `app/index.php`, no `laravel/fortify`.
  - `index.php:6` — hardcodes the TOTP secret.
  - `index.php:10` — `/two-factor-secret` **hands the secret to any caller**.
  - `index.php:16-31` — `/two-factor-challenge` **accepts any non-empty string**; it never validates the code against the secret or a time step. It does not model TOTP at all.
- **Real Fortify** has no `/two-factor-secret` endpoint and gates the challenge behind an authenticated 2FA-pending session → the scanner's technique gets zero traction in production.
- **Required fix:** rebuild against real `laravel/fortify` with a real authenticated 2FA flow, or remove.

### Tier B — Synthetic gadget / fabricated sink: code runs, but the sink is planted

#### CVE-2022-2870 & CVE-2022-2886 (Laravel 5.1 "deserialization")
- **Real "vuln":** both are **VulDB-disputed** entries with no framework file/commit; they describe *application* code calling `unserialize()`, not a framework flaw.
- **What was faked:** `overlay/app/Http/routes.php:19-27` defines the lab's **own gadget class** `LvcSyntheticCommand { __wakeup(){ … shell_exec($this->cmd) } }` writing to `$GLOBALS['lvc_deser_command_output']`, plus a `/deserialize` route unserializing request input. The "POP-chain RCE" executes a class **that exists only in the lab** — sending the payload to a real target does nothing.
- **Duplicate:** the two labs' gadget files are **byte-for-byte identical**. 2870 and 2886 are the same rig counted as two CVE passes.
- **Required fix:** collapse to one; relabel as an "insecure-`unserialize()` app pattern" demo, not a framework CVE. Do not count as two.

#### CVE-2020-19316 (Filesystem::link command injection)
- **Real vuln:** Windows-only `mklink` command injection in `Filesystem::link()`, Laravel **<5.8.17**.
- **What was faked:** `overlay/routes/web.php:96-98` — a hand-added `GET /storage/link` route running `$cmd = "ln -s " . $target . " " . $link; shell_exec($cmd)` on Laravel **11 / Linux**. Real Laravel's `link()` calls PHP-native `symlink()` (the route even shows it at `web.php:88`) and never shells out. Wrong OS, wrong version, invented sink; detection keys on the lab-only route + echoed output.
- **Required fix:** rebuild on Windows + Laravel <5.8.17 with the real `Storage::link()`, or scope explicitly Windows-only and mark "not reproduced on Linux."

### Tier C — Misattribution: wrong version / wrong product / wrong bug class

#### CVE-2021-43617 (upload validation)
- **Real vuln:** framework `.phar`/MIME allowlist gap in `ValidatesAttributes`, Laravel **≤8.70.2**.
- **What was faked:** `apache/Dockerfile:39` runs `composer create-project laravel/laravel:^11.0` — **not the affected version** (the Dockerfile comment at `:3` even admits NVD attributes it to ≤8.70.2). `overlay/routes/web.php:87-88` stores `getClientOriginalName()` with **no validation at all** → tests generic unvalidated `.php` upload, not the CVE's `.phar` bypass.
- **Required fix:** rebuild on ≤8.70.2 exercising the real `mimes:`/`image` validation defeated by `.phar`, or relabel as "generic unrestricted upload."

#### CVE-2017-14775 (remember-me timing)
- **Real vuln:** a **timing side-channel** (CWE-200, info disclosure, Medium), <5.5.10. No practical remote token-recovery PoC exists.
- **What was faked:** module hardcodes `vuln_class = "rce"` (`modules/cves/cve_2017_14775.py:422`); the "exploit" logs in with **seeded creds `admin@lab.local/password`** (`run.sh:50,53`) and uploads a shell to an invented `/admin/upload` sink. The container run's "success" came via `auth_path="password_login"` — the timing oracle never fired. A Medium info-leak relabeled and demonstrated as High RCE via credentials an external attacker would not have.
- **Required fix:** relabel Medium timing/info-disclosure; drop the RCE class and the seeded-cred + custom-upload chain.

#### CVE-2016-10074 (SwiftMailer) — not Laravel, no lab, undocumented
- **Real vuln:** a **SwiftMailer** sendmail argument-injection RCE (<5.4.5). Not a Laravel CVE.
- **What was faked / missing:** **no lab exists**; the module (`modules/cves/cve_2016_10074.py`) only works against a fake sendmail that logs its argv to a web-readable file — no real Laravel app exposes that. It is also **absent from the workbook** yet ships in `--list` as a Critical Laravel RCE.
- **Required fix:** remove from a *Laravel* catalog, or move to an explicit old-Laravel (4.x/5.0) + SwiftMailer-with-sendmail dependency lab and add the missing workbook row.

### Tier D — No security impact

#### CVE-2020-24941 (guarded JSON mass-assignment)
- **Real vuln:** a JSON-path key slipping past `$guarded` to write a **protected** column.
- **What was faked:** `overlay/app/Setting.php:21` sets `$guarded = ['id','is_admin']` with a free `data` array column. The scanner writes `data->marker` (`modules/cves/cve_2020_24941.py:72`) — but **`data` is not guarded**, so writing to it is normal permitted behavior. The container run confirmed `is_admin` stayed false. The "bypass" crosses no security boundary; the advisory's actual concern (reaching the guarded `is_admin`) is never exercised.
- **Required fix:** make the JSON-path key reach the guarded `is_admin`, or drop — current form demonstrates nothing.

---

## SECTION 2 — NOT FULLY GREEN: real bugs with a staged precondition (8 CVEs)

These are genuine vulnerabilities; the lab or module stages one condition. Fix = relabel or wire the real path — not rip-out.

| CVE | What's staged | Evidence | Required fix |
|---|---|---|---|
| **CVE-2018-15133** | All-zeros APP_KEY baked + handed via `--app-key`; trigger is a lab `/decrypt-token` route (real `Crypt::decrypt` sink though; `.env` is web-exposed so key is legitimately recoverable) | `entrypoint.sh:31,36`; `overlay/routes/web.php:18` | Label "requires known APP_KEY"; optionally recover the key via the exposed `.env` instead of injecting it |
| **CVE-2021-28254** | `/deserialize` sink is lab-added (comment admits contrived), but the gadget is a **genuine** phpggc PendingBroadcast chain | `overlay/routes/web.php:58-79` | Label "requires an app-level `unserialize()` sink"; keep as class demo |
| **CVE-2025-27515** | Advisory impact is **validation bypass, "Not directly [RCE]"**; lab manufactures RCE via public-disk + original filename + mod_php | GHSA-78fx-h6xr-vch4 | Fix class label to bypass; drop the RCE claim |
| **CVE-2023-43661** | Cataloged `chained_rce`, but the demonstrated primitive is only **APP_KEY disclosure**; lab **pre-seeds the malicious `poc` template** | `entrypoint.sh:7,26,124` | Relabel SSTI/config-disclosure; have the module create the template instead of pre-seeding |
| **CVE-2025-54068** | Real vuln + real Synacktiv gadget, but the real Snipe-IT sink is **auth-gated**; lab injects an **unauthenticated `/demo` component** so the unauth run lands | `app-glue/Livewire/PublicDemo.php`, `app-glue/public-demo-route.php:18` | Run the real authed path (module supports `-U/-P`); drop or flag the synthetic unauth shortcut |
| **CVE-2026-23524** | Real CVE + real `unserialize()` sink modeled, but **`laravel/reverb` not vendored**, a **fabricated `ChainedBatchTruthTest::__wakeup→system` gadget**, success via lab-only `/reverb-oob` | `app/index.php:50,67`; `entrypoint.sh:45-51,68,134` | Use a real phpggc chain + real POST-callback OOB, or keep as precondition-detected only |
| **CVE-2024-52301** | Real env-flip on correct version + real precondition, but only observable via a **lab-added echo route**, and the detector regex matches the **lab's own marker string** | `modules/cves/cve_2024_52301.py:166` | Detect via a real observable, not the lab marker |
| **CVE-2020-24940** | Real dotted-key mechanism, but "priv-esc" only works because the lab adds a **strawman filter** blocking bare `is_admin` but not `users.is_admin`, plus a JSON readback route | lab `web.php` (`$blocked=['is_admin']`) | Remove the strawman; demonstrate a real guarded-column write or downgrade |

---

## SECTION 3 — SYSTEMIC ENGINEERING DEFECTS (apply across the suite)

1. **Result contract has no proof-of-execution gate.** `success=True` can be set from a reflected/constant string (Tier A proves it). **Require observed real command output or a real side effect for `success=True`.** This single change auto-flags the fabricated-success labs.
2. **No affected-version gating.** A wrong-version lab (43617 on Laravel 11) reports vulnerable. Enforce the advisory's affected-version range before claiming applicability.
3. **Hardened twins block at the wrong layer.** Several twins apply a web-tier/nginx 403 (e.g. block `/storage/*.php`) instead of the real vendor fix → weak negative control. Apply the actual patch (version bump / config change) in the hardened profile.
4. **Detection over-relies on web-served `composer.lock` and lab marker strings** → high false-negative rate on real hosts that don't expose those, and false confidence from lab-only markers.
5. **Duplicate CVE from one rig:** 2886 ≡ 2870 (identical gadget file). Dedup.
6. **Catalog/code drift (from the static review):**
   - Failing test: `modules/detection/tests/test_new_modules_registered.py::test_workbook_preconditions_match_unified_cve_metadata` — workbook preconditions for **CVE-2025-49132** drifted from `metadata.py`.
   - `docs/Laravel_Vulnerabilities.xlsx` documents **29** CVEs; code ships **30** (CVE-2016-10074 undocumented).
   - Two divergent workbook copies (root `Laravel Vulnerabilities - 20260619.xlsx` vs `docs/Laravel_Vulnerabilities.xlsx`) — pick one source of truth.
   - `tools/lab_matrix_runner.py` is referenced in `vuln-labs/README.md` but **does not exist** — no automated fleet validation ships.
7. **CVEs with no lab:** CVE-2016-10074 and CVE-2024-29291 cannot be lab-validated (2024-29291 is documented catalog-only; 2016-10074 is not).

---

## SECTION 4 — WHAT IS SOLID (keep; this is the real capability)

Faithful reproductions — real product, correct vulnerable version, real primitive, real command output, genuine hardened control:

- **Default-APP_KEY deserialization RCEs (strongest):** CVE-2024-48987 (Snipe-IT 7.0.9), CVE-2024-55555 (Invoice Ninja 5.10.10), CVE-2024-55556 (InvoiceShelf 1.3.0). The "handed" APP_KEYs are the **genuine committed public-repo default keys** each advisory names — a real default deployment is exploitable with the same key.
- **Upload/RCE in real apps:** CVE-2025-14894 (livewire-filemanager 1.0.4), CVE-2024-47823 (Livewire 2.12.5), CVE-2024-21546 (authed badaso + S-Cart), CVE-2023-46865 (Crater 6.0.6), CVE-2020-5256 (BookStack 0.25.2), CVE-2024-22836 (Akaunting 3.1.3).
- **Ignition RCE:** CVE-2021-3129 — real chain, real precondition (debug on).
- **Disclosure/traversal:** CVE-2017-16894 (`.env`), CVE-2025-49132 (Pterodactyl locale traversal → APP_KEY; RCE step config-dependent, honestly labeled).
- **Honest detector:** CVE-2024-29291 (read-only; underlying CVE is a disputed misconfig).

---

## Appendix A — Full realism verdict (30 CVEs)

Legend: 🟢 faithful · 🟡 lab-assisted · 🔴 faked/misattributed

| CVE | Product | Verdict |
|---|---|---|
| CVE-2021-3129 | Ignition | 🟢 |
| CVE-2017-16894 | Laravel .env | 🟢 |
| CVE-2024-29291 | Laravel logs | 🟢 (disputed CVE) |
| CVE-2025-14894 | livewire-filemanager | 🟢 |
| CVE-2024-47823 | Livewire | 🟢 |
| CVE-2024-48987 | Snipe-IT | 🟢 |
| CVE-2024-55555 | Invoice Ninja | 🟢 |
| CVE-2024-55556 | InvoiceShelf | 🟢 |
| CVE-2024-22836 | Akaunting | 🟢 |
| CVE-2023-46865 | Crater | 🟢 |
| CVE-2020-5256 | BookStack | 🟢 |
| CVE-2025-49132 | Pterodactyl | 🟢 (RCE step config-dependent) |
| CVE-2024-21546 | UniSharp LFM | 🟢 authed / 🟡 unauth lab |
| CVE-2018-15133 | Laravel deser | 🟡 |
| CVE-2021-28254 | Laravel POP | 🟡 |
| CVE-2025-27515 | Laravel files.* | 🟡 (bypass, not RCE) |
| CVE-2024-52301 | Laravel env | 🟡 |
| CVE-2020-24940 | Mass-assign | 🟡 |
| CVE-2023-43661 | Cachet SSTI | 🟡 (disclosure, not RCE) |
| CVE-2026-23524 | Reverb | 🟡 |
| CVE-2025-54068 | Snipe-IT / Livewire | 🟡 |
| CVE-2021-43617 | Laravel upload | 🔴 wrong version + custom sink |
| CVE-2020-19316 | Laravel link() | 🔴 fabricated shell route |
| CVE-2020-24941 | Mass-assign JSON | 🔴 no impact |
| CVE-2017-14775 | Remember-me timing | 🔴 timing sold as RCE |
| CVE-2016-10074 | SwiftMailer | 🔴 not Laravel / no lab |
| CVE-2022-2870 | "Laravel 5.1" deser | 🔴 synthetic gadget |
| CVE-2022-2886 | "Laravel 5.1" deser | 🔴 duplicate of 2870 |
| CVE-2024-55661 | Pulse | 🔴 hardcoded success |
| CVE-2022-25838 | Fortify | 🔴 hardcoded success |

## Appendix B — Container run

30/30 labs booted (no boot failures) and matched their documented matrix in the automated run: detect on the vulnerable port, exploit on the vulnerable port, and `blocked_by_control` on the hardened twin. **This confirms the labs behave as their authors intended — it does not confirm real-world exploitability**, which is the subject of Sections 1–2. Notably CVE-2024-55661 and CVE-2022-25838 scored `EXPLOITED` here against fabricated success strings, demonstrating why matrix-green is insufficient evidence.

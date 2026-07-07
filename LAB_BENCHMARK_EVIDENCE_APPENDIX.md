# Laravel CVE Benchmark — Per-CVE Evidence Appendix

Reference companion to `LAB_BENCHMARK_AUDIT.md`. One block per CVE with: public advisory, the real vulnerability, what the **lab** implements (`file:line`), what the **scanner** does (`file:line`), the **actual container-run verdict** (from `--json-out -`), rigging flags, and the realism verdict.

Paths are relative to `lvcscan/`. Run verdicts use the vulnerable port; every hardened twin returned `success=False` (shown only where notable). Legend: 🟢 faithful · 🟡 lab-assisted · 🔴 faked/misattributed.

---

## 🟢 FAITHFUL (13)

### CVE-2021-3129 — Ignition RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2021-3129 — Ignition ≤2.5.1 / Laravel <8.4.2; unauth RCE via `/_ignition/execute-solution`; **precondition: debug mode on**; public PoC (Ambionics).
- **Lab:** real `laravel/laravel:8.4.*` + real `facade/ignition:2.5.1` (`apache/Dockerfile:37-40`), real precondition `APP_DEBUG=true` (`scripts/entrypoint.sh:23-40`).
- **Scanner:** `modules/cves/cve_2021_3129.py` — probes real endpoint (`_is_vulnerable_response`), builds a genuine phpggc-equivalent phar + log-poison chain, success only on real marked command output (`_run_chain`, `_extract_marked_output`).
- **Run:** DET `sink_reachable` · EXP `success=True` (real `uid=33(www-data)`). 
- **Flags:** NONE. **Verdict:** 🟢 FAITHFUL.

### CVE-2017-16894 — Laravel .env disclosure
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2017-16894 — Laravel ≤5.5.21; unauth `GET /.env` secret disclosure, CVSS 7.5.
- **Lab:** real Laravel 5.5.*, `.env` web-reachable via `apache/apache.conf:14-17`; realistic secrets seeded `entrypoint.sh:17-33`.
- **Scanner:** `cve_2017_16894.py:83-123` GET `/.env` + secret-pattern; exploit dumps secrets `:202-264`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True`.
- **Flags:** minor VERSION_STANDIN (installs newest 5.5.x; detector is version-agnostic on the exposure). **Verdict:** 🟢 FAITHFUL — matches how real exposed-`.env` hosts are found.

### CVE-2024-29291 — laravel.log DB-credential disclosure
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-29291 — **DISPUTED**; reduces to a misconfiguration (logs web-served + creds logged).
- **Lab:** NONE (catalog-only).
- **Scanner:** `cve_2024_29291.py:103,159-188` — reuses `log_exposure`, raises to `confirmed_vulnerable` only if real DB-credential material present; read-only exploit `:138`; documents the dispute `:58-61`.
- **Run:** no lab.
- **Flags:** NONE (honest). **Verdict:** 🟢 FAITHFUL detector; underlying CVE is a disputed misconfig.

### CVE-2025-14894 — livewire-filemanager upload RCE
- **Advisory:** https://github.com/advisories/GHSA-9g95-48c6-r778 , https://www.kb.cert.org/vuls/id/650657 — `livewire-filemanager/filemanager` ≤1.0.4; **unauthenticated** `.php` upload RCE; precondition `storage:link`.
- **Lab:** real Laravel 11 + genuine `livewire-filemanager/filemanager:1.0.4` (`apache/Dockerfile`), real `<x-livewire-filemanager />`, mounted unauth at `/filemanager` (matches advisory), `storage:link` in entrypoint.
- **Scanner:** `cve_2025_14894.py:12-17` inert-marker detect; exploit `:800-893` real Livewire upload handshake → exec at `/storage/<id>/<name>.php`, with a guard that echoed source is not counted `:881-882`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (real `uid=33`).
- **Flags:** NONE. **Verdict:** 🟢 FAITHFUL.

### CVE-2024-47823 — Livewire temp-file upload bypass
- **Advisory:** https://github.com/livewire/livewire/security/advisories/GHSA-f3cx-396f-7jqp — Livewire <2.12.7/<3.5.2; MIME-guessed extension bypass; app must store under original name on public disk.
- **Lab:** real ERPSAAS app + genuine `livewire/livewire v2.12.5` (committed lock). Lab adds a `LabUpload` component at `/upload` (`overlay/app/Http/Livewire/LabUpload.php:20-28`, `overlay/routes/lab-cve-2024-47823.php:5-7`) — a **verbatim reproduction of the advisory's own vulnerable pattern**.
- **Scanner:** `cve_2024_47823.py:1393-1446` real Livewire-2 upload handshake; exec at `/storage/lab-uploads/<name>.php` `:1450`.
- **Run:** DET `version_applicable` · EXP `success=True`.
- **Flags:** CUSTOM_SINK (advisory-accurate, lab-supplied). **Verdict:** 🟢 FAITHFUL (class faithful).

### CVE-2024-48987 — Snipe-IT cookie deserialization RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-48987 — Snipe-IT <7.0.10; `XSRF-TOKEN` unserialize RCE; **requires known APP_KEY**; NVD notes default `.env` repo keys.
- **Lab:** real `grokability/snipe-it` v7.0.9; stock sink. Baked `APP_KEY base64:3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ=` — **verified byte-identical to the committed `v7.0.9/.env.docker` default** (`cve_2024_48987.py:371`).
- **Scanner:** unauth reports `surface_present` (honest); with key → phpggc Laravel/RCE13 as `XSRF-TOKEN`, marker-file readback `:537-592`.
- **Run:** DET `surface_present` · EXP `success=True` with `--app-key …IVwMQ=` (the real repo default) · HARD `blocked_by_control` (key rotated + `$serialize=false`).
- **Flags:** SEEDED_SECRET = the genuine public default (reproduces, not fakes, the precondition). **Verdict:** 🟢 FAITHFUL.

### CVE-2024-55555 — Invoice Ninja route deserialization RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-55555 — Invoice Ninja 5.8.22–<5.10.43; `GET /route/{hash}` → decrypt → unserialize RCE; requires known APP_KEY (repo default ships).
- **Lab:** real official `invoiceninja/invoiceninja:5.10.10`. `APP_KEY base64:RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno=` — **verified byte-identical to `v5.10.10/.env.example`** (`cve_2024_55555.py:271`).
- **Scanner:** version header `X-APP-VERSION: 5.10.10`; exploit `:395-463` phpggc Laravel/RCE22, Laravel-encrypt, `GET /route/<cipher>`, web readback.
- **Run:** DET `version_applicable` · EXP `success=True` with the real default key (`uid=82(www-data)`).
- **Flags:** SEEDED_SECRET = genuine default. **Verdict:** 🟢 FAITHFUL.

### CVE-2024-55556 — InvoiceShelf cookie deserialization RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-55556 — InvoiceShelf ≤1.3.0; ships `SESSION_DRIVER=cookie` + default APP_KEY → forge `laravel_session` → unserialize RCE unauth.
- **Lab:** real InvoiceShelf 1.3.0; entrypoint copies real `.env.example` verbatim — **verified `SESSION_DRIVER=cookie` + `APP_KEY=base64:kgk/4DW1vEVy7aEvet5FPp5un6PIGe/so8H0mvoUtW0=` match the repo** (`cve_2024_55556.py:283`).
- **Scanner:** session-shape behavioral probe + exploit `:468-634` two-cookie phpggc RCE22, OOB callback proof.
- **Run:** DET `version_applicable` · EXP `success=True` (OOB `uid=33`) · HARD flips `SESSION_DRIVER=file` (real fix).
- **Flags:** SEEDED_SECRET = genuine default. **Verdict:** 🟢 FAITHFUL — the most faithful of the set (the vuln *is* the shipped default config).

### CVE-2024-22836 — Akaunting locale command injection
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-22836 — Akaunting ≤3.1.3; authenticated locale→OS command injection.
- **Lab:** **real official `akaunting/akaunting:3.1.3`** image (`apache/Dockerfile:235`), real `php artisan install`, seeded admin.
- **Scanner:** `cve_2024_22836.py:208-356` fingerprint/version gate; exploit `:553-724` login → poison `locale` → `apps/install` → parse `uid=` from `ProcessFailedException`.
- **Run:** DET `version_applicable` · EXP `success=True` with `-U admin@example.com` (realistic company-admin).
- **Flags:** PRIVILEGE minor (admin is the real precondition). **Verdict:** 🟢 FAITHFUL.

### CVE-2023-46865 — Crater logo-upload RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2023-46865 — Crater ≤6.0.6; superadmin PNG+PHP upload RCE.
- **Lab:** real `crater-invoice-inc/crater` 6.0.6 (`apache/Dockerfile:505`), real superadmin seed, `MEDIA_DISK=public` + `storage:link`.
- **Scanner:** `cve_2023_46865.py:103-230` detect; exploit `:335-526` Sanctum login → upload PNG+PHP named `.php` → exec.
- **Run:** DET `version_applicable` · EXP `success=True` with `-U admin@craterapp.com`.
- **Flags:** NONE material (superadmin = advisory PR:H). **Verdict:** 🟢 FAITHFUL.

### CVE-2020-5256 — BookStack image-upload RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2020-5256 — BookStack <0.25.5; authenticated `is_image` MIME-only bypass RCE.
- **Lab:** real `BookStackApp/BookStack` v0.25.2; `apache/Dockerfile:608-614` **self-corrects a wrong version in the build brief** to a genuinely pre-fix tag.
- **Scanner:** `cve_2020_5256.py:127-242` detect + exec control probe; exploit `:303-484` login → `GIF89a`-prefixed `.php` via `/images/gallery/upload` → exec.
- **Run:** DET `version_applicable` · EXP `success=True` with `-U admin@admin.com`.
- **Flags:** PRIVILEGE minor (default admin has upload perms). **Verdict:** 🟢 FAITHFUL.

### CVE-2025-49132 — Pterodactyl locale traversal → APP_KEY (→ RCE)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2025-49132 — Pterodactyl <1.11.11; **unauth**, CVSS 10.0; `/locales/locale.json` traversal → LFI/APP_KEY; PoC escalates via `pearcmd.php`.
- **Lab:** real upstream `v1.11.10` (`apache/Dockerfile:40`), unauth, no attacker creds; APP_KEY/DB seeded only as the *disclosure target* (`entrypoint.sh:45-48`). RCE preconditions PEAR + `register_argc_argv=On` installed (`Dockerfile:22,29`) — **official image ships neither**; labeled "config-dependent" (`metadata.py:161`).
- **Scanner:** `cve_2025_49132.py:116-133` traversal discriminator; exploit `:330-386` LFI + pearcmd; `requires` lists PEAR/argv `:460-464`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True`.
- **Flags:** RCE step LAB_ASSISTED but transparently disclosed. **Verdict:** 🟢 FAITHFUL (detection + LFI/APP_KEY = real advisory core).

### CVE-2024-21546 — UniSharp laravel-filemanager upload RCE (3 labs)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-21546 — `unisharp/laravel-filemanager` ≤2.9.0; trailing-dot + PNG-magic bypass → `.php` RCE; no APP_KEY.
- **Labs:** all use the real vulnerable package. `41013` (badaso) keeps the real `auth,browse_file_manager` gate + seeded admin (most faithful). `35001` real S-Cart admin. `35002` mounts `Lfm::routes()` with **auth middleware removed** (`third-party/…35002-36002/app/routes/web.php:14`).
- **Scanner:** `cve_2024_21546.py:245,520-544` version-gate + trailing-dot upload → sentinel readback.
- **Run (all three):** EXP `success=True` (`uid=33`); `41013` with `-U admin@badaso.test`, `35001` with `-U admin`, `35002` unauth.
- **Flags:** LAB_ONLY_READBACK (`composer.lock` aliased into webroot for the version signal); 35002 = manufactured unauth reachability; hardened twins block web-tier PHP exec rather than upgrading to 2.9.1.
- **Verdict:** 🟢 FAITHFUL (41013, 35001) · 🟡 LAB_ASSISTED (35002).

---

## 🟡 LAB-ASSISTED (8) — real bug, one staged precondition

### CVE-2018-15133 — X-XSRF-TOKEN deserialization RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2018-15133 — Laravel ≤5.5.40/≤5.6.29; `Encrypter::decrypt` default `$unserialize=true`; **requires known APP_KEY**; Metasploit exists.
- **Lab:** real `laravel/framework:5.6.29`, real crypto/gadget. Assists: **all-zeros APP_KEY baked** (`scripts/entrypoint.sh:31,36`) + handed via `--app-key`; trigger is lab route `/decrypt-token` (`overlay/routes/web.php:18`, real `Crypt::decrypt`). `.env` web-exposed → key legitimately recoverable.
- **Scanner:** real Laravel/RCE2 PendingBroadcast gadget + AES-CBC/HMAC; success on reflected command output.
- **Run:** DET `version_applicable` · EXP `success=True` with `--app-key …AAAA=` · HARD `blocked_by_control`.
- **Flags:** SEEDED_SECRET, CUSTOM_SINK. **Verdict:** 🟡 LAB_ASSISTED.

### CVE-2021-28254 — PendingBroadcast POP chain RCE
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2021-28254 — Laravel ≤8.5.9; POP gadget; exploitable only where an app unserializes attacker input.
- **Lab:** real `laravel/framework:8.4.*` (ships the gadget); adds a **contrived** `POST /deserialize` `@unserialize()` sink (`overlay/routes/web.php:58-79`, comment admits it). Gadget itself is a **genuine** phpggc PendingBroadcast chain — *not* a lab class (contrast 2870/2886).
- **Scanner:** `cve_2021_28254.py:124-125` escalates to `confirmed_vulnerable` when sink responds; real gadget sweep; success on real `uid=` output.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (real `uid=33`).
- **Flags:** CUSTOM_SINK, LAB_ONLY_MARKER. **Verdict:** 🟡 LAB_ASSISTED.

### CVE-2025-27515 — files.* validation bypass
- **Advisory:** https://github.com/advisories/GHSA-78fx-h6xr-vch4 — Laravel 10.x<10.48.29 / 11.x≤11.44.0 / 12.0–12.1; **impact = validation bypass, "Not directly [RCE]."**
- **Lab:** pins correct **11.44.0** (`apache/Dockerfile:51-55`); real `files.*` rule, then stores under original name on public disk + mod_php to manufacture RCE (`overlay/routes/web.php:64-83`; `entrypoint.sh:38-40`).
- **Scanner:** version-only detect `cve_2025_27515.py:139-193`; exploit `:254-357` genuine `files[.]` bypass then exec.
- **Run:** DET `version_applicable` · EXP `success=True`.
- **Flags:** CUSTOM_SINK for the RCE step (advisory = bypass). **Verdict:** 🟡 LAB_ASSISTED — **class label inflated to RCE**.

### CVE-2024-52301 — env/argv manipulation
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-52301 — Laravel <11.31.0; with `register_argc_argv=On`, `?--env=` flips resolved environment.
- **Lab:** correct **11.30.0**, real precondition `register_argc_argv=On` (`zz-lab.ini:4`); adds a route echoing `app()->environment()` (`overlay/routes/web.php:17-27`).
- **Scanner:** `cve_2024_52301.py` baseline-vs-`?--env=local`; detector regex **special-cases the lab's own marker** `cve-2024-52301:<env>` (`:166`).
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` · HARD `not_detected` (`register_argc_argv=Off`).
- **Flags:** LAB_ONLY_MARKER/READBACK. **Verdict:** 🟡 LAB_ASSISTED — real bug, lab-only observability + marker.

### CVE-2020-24940 — mass-assignment (table-prefix strip)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2020-24940 — Laravel <6.18.34/<7.23.2; `removeTableFromKey()` strips `table.` before the fillable check.
- **Lab:** vuln 6.18.33 / hardened 6.18.34 (honest versions); `User` is `$guarded=[]`; a `app_filter()` blocks **only the bare key** `is_admin` (`overlay/routes/web.php`, `$blocked=['is_admin']`); registration route echoes `is_admin` JSON.
- **Scanner:** `cve_2020_24940.py:80,220` POSTs `users.is_admin`, success iff readback `is_admin===true` while control bare key stays false.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` · HARD `blocked_by_control`.
- **Flags:** STRAWMAN_HARDENING (bare-name filter), LAB_ONLY_READBACK. Module docstring concedes `:146` a dotted key can't reach a guarded column. **Verdict:** 🟡 LAB_ASSISTED.

### CVE-2023-43661 — Cachet Twig SSTI
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2023-43661 — Cachet <2.4; **authenticated** SSTI → RCE.
- **Lab:** real `cachethq/cachet v2.3.18`, Twig 1.40.1; seeds admin + **pre-seeds a malicious IncidentTemplate slug `poc`** = `{{ config('app.key') }}` (`scripts/entrypoint.sh:7,26,124`).
- **Scanner:** `cve_2023_43661.py` version-gate; `vuln_class` defaults `chained_rce` `:545`; stage-1 leaks APP_KEY via the seeded template `:635-663`; stage-2 forges X-XSRF-TOKEN gadget `:483-533` (module honest that pinned Twig can't in-band exec).
- **Run:** DET `version_applicable` · EXP `success=True` with `-U admin@cachet.test`.
- **Flags:** SEEDED template, PRIVILEGE minor, class-label overclaim. **Verdict:** 🟡 LAB_ASSISTED — **demonstrated primitive is APP_KEY disclosure, not RCE**.

### CVE-2026-23524 — Reverb Redis-scaling deserialization RCE
- **Advisory:** https://github.com/advisories/GHSA-m27r-m6rx-mhm4 — laravel/reverb ≤1.6.3 with `REVERB_SCALING_ENABLED=true`; unserialize of Redis PubSub message; CVSS 9.8. (Real, verified published.)
- **Lab:** **does NOT vendor laravel/reverb** (`app/index.php:50`); hand-rolled worker `SUBSCRIBE`s and `unserialize($application)` (`scripts/entrypoint.sh:134` — real sink modeled) but **defines a fabricated gadget** `class ChainedBatchTruthTest{ …system($this->cmd) }` (`entrypoint.sh:45-51`); output written to `storage/reverb-oob.txt` and served at lab route `/reverb-oob` (`index.php:67`, `entrypoint.sh:68`).
- **Scanner:** `cve_2026_23524.py:486-507` honest `precondition_detected`/"not HTTP proof"; exploit `:295-315` gadget matched to the lab worker; success by polling `/reverb-oob` `:804-841`. Module also supports a real phpggc chain + POST-callback OOB.
- **Run:** DET `precondition_detected` · EXP `success=True` via `--opt oob_read_url=http://localhost:37002/reverb-oob …`.
- **Flags:** VERSION_STANDIN, fabricated gadget, LAB_ONLY_READBACK. **Verdict:** 🟡 LAB_ASSISTED (borderline — real CWE-502 sink + Redis precondition; demonstrated RCE is planted).

### CVE-2025-54068 — Snipe-IT / Livewire unsafe hydration RCE
- **Advisory:** https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3 — Livewire 3.0.0-beta.1..3.6.3; unsafe property hydration RCE; requires a reachable mounted component with an untyped public property. CISA KEV.
- **Lab:** real `grokability/snipe-it v8.1.18` + real vulnerable `livewire 3.5.18`; the real authed sink exists (verified `PersonalAccessTokens.php` untyped `public $name`). **But the lab injects an unauthenticated `App\Livewire\PublicDemo` on `/demo`** (`app-glue/Livewire/PublicDemo.php`, `app-glue/public-demo-route.php:18`) into the vuln image only.
- **Scanner:** `cve_2025_54068.py:364-423` finds `wire:snapshot` on `/demo` → Synacktiv Livepyre POP → `system()`. The passing run hit the **lab-added** route.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` at `/demo`.
- **Flags:** CUSTOM_SINK (real sink is auth-gated). **Verdict:** 🟡 LAB_ASSISTED — module supports the faithful authed path (`-U/-P`); the run used the synthetic unauth shortcut.

---

## 🔴 FAKED / MISATTRIBUTED (9)

### CVE-2024-55661 — Pulse (Tier A: hardcoded success)
- **Advisory:** https://github.com/advisories/GHSA-8vwh-pr89-4mw2 — laravel/pulse <1.3.1; public `remember()` invokes no-arg callables; authenticated, limited. **Not** an APP_KEY→decrypt RCE.
- **Lab:** hand-rolled, no laravel/pulse. `app/index.php:8` null key; `:184` `echo "uid=33(www-data)…"` **constant** on `/decrypt-token` — no unserialize, no exec.
- **Scanner:** `cve_2024_55661.py:629-702` forges Laravel/RCE22, POSTs, treats the reflected constant as RCE.
- **Run:** DET `version_applicable` · EXP **`success=True` against a canned string** with `-U admin@example.com`.
- **Flags:** VERSION_STANDIN, SEEDED_SECRET, LAB_ONLY_READBACK, MISATTRIBUTION. **Verdict:** 🔴.

### CVE-2022-25838 — Fortify (Tier A: secret handed out)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2022-25838 , GHSA-6w4v-qr4m-97gg — laravel/fortify <1.11.1; TOTP replay within window; high complexity.
- **Lab:** hand-rolled, no fortify. `app/index.php:6` hardcoded secret; `:10` `/two-factor-secret` **hands it out**; `:16-31` challenge **accepts any non-empty code**; unauthenticated (no 2FA-pending session).
- **Scanner:** `cve_2022_25838.py:110-171` fetches secret, POSTs a code twice → `confirmed_vulnerable`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (`--opt totp_secret=JBSWY3DPEHPK3PXP`).
- **Flags:** VERSION_STANDIN, SEEDED_SECRET, LAB_ONLY_MARKER, STRAWMAN. **Verdict:** 🔴 — can't fire on real Fortify.

### CVE-2022-2870 — "Laravel 5.1" deser (Tier B: synthetic gadget)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2022-2870 — VulDB-**disputed**, no framework file/commit; describes app code, not framework.
- **Lab:** `overlay/app/Http/routes.php:19-27` lab-authored `LvcSyntheticCommand{ __wakeup(){…shell_exec($this->cmd)} }` + `/deserialize` route; output echoed from `$GLOBALS`.
- **Scanner:** `cve_2022_2870.py:312-317` sends the lab class, reads `command_output`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (executes a lab-only class).
- **Flags:** CUSTOM_SINK, LAB_ONLY_MARKER/READBACK, VERSION_STANDIN, STRAWMAN_HARDENING, MISATTRIBUTION. **Verdict:** 🔴.

### CVE-2022-2886 — "Laravel 5.1" deser (Tier B: duplicate of 2870)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2022-2886 — VulDB-disputed sibling.
- **Lab:** **gadget file byte-identical to 2870** (verified); same `LvcSyntheticCommand`/`/deserialize`/readback; only banner/port differ.
- **Scanner:** `cve_2022_2886.py` mirrors 2870.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True`.
- **Flags:** same as 2870 + duplication. **Verdict:** 🔴 — one rig, two CVE numbers.

### CVE-2020-19316 — Filesystem::link cmdi (Tier B: fabricated route)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2020-19316 — Windows-only `mklink` in `Filesystem::link()`, Laravel <5.8.17.
- **Lab:** Laravel **11 / Linux**; `overlay/routes/web.php:73` `GET /storage/link` → `:96-98` `shell_exec("ln -s " . $target . " " . $link)`. Real `link()` uses PHP `symlink()` (shown at `:88`).
- **Scanner:** `cve_2020_19316.py:38,96-140` probes the lab route + echoed marker; exploit `:255-341` arithmetic-marker confirm.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (lab-only route).
- **Flags:** CUSTOM_SINK, LAB_ONLY_MARKER/READBACK, VERSION_STANDIN, MISATTRIBUTION. **Verdict:** 🔴.

### CVE-2021-43617 — upload validation (Tier C: wrong version)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2021-43617 — framework `.phar`/MIME allowlist gap, Laravel ≤8.70.2.
- **Lab:** `apache/Dockerfile:39` `composer create-project laravel/laravel:^11.0` (Dockerfile `:3` admits NVD says ≤8.70.2); `overlay/routes/web.php:87-88` `getClientOriginalName()` + `move()` **no validation** → tests generic `.php`, not `.phar`.
- **Scanner:** `cve_2021_43617.py:69-119` marker upload; exploit `:259-322`.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` (planted route).
- **Flags:** VERSION_STANDIN, CUSTOM_SINK, MISATTRIBUTION. **Verdict:** 🔴.

### CVE-2017-14775 — remember-me timing (Tier C: timing sold as RCE)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2017-14775 — **timing side-channel** (CWE-200, Medium), Laravel <5.5.10; no practical remote PoC.
- **Lab:** module hardcodes `vuln_class="rce"` (`cve_2017_14775.py:422`); exploit logs in with **seeded `admin@lab.local/password`** (`run.sh:50,53`) + null `--app-key`, uploads to invented `/admin/upload`.
- **Scanner:** timing oracle falls through to password login `:455` → `_upload_shell` `:361-394`.
- **Run:** DET `precondition_detected` · EXP `success=True` via `auth_path="password_login"` (timing never fired).
- **Flags:** MISATTRIBUTION, CUSTOM_SINK, SEEDED_SECRET. **Verdict:** 🔴.

### CVE-2016-10074 — SwiftMailer (Tier C: not Laravel, no lab)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2016-10074 — **SwiftMailer** <5.4.5 sendmail arg-injection RCE. Laravel not mentioned.
- **Lab:** NONE. Undocumented in the workbook.
- **Scanner:** `cve_2016_10074.py:94,109-114,229` targets a fake sendmail `/index.php` + web-readable `runtime/sendmail_argv.log` + hardcoded write path.
- **Run:** no lab.
- **Flags:** MISATTRIBUTION, CUSTOM_SINK, LAB_ONLY_READBACK. **Verdict:** 🔴 — SwiftMailer CVE in a Laravel catalog; only works against a bespoke harness.

### CVE-2020-24941 — guarded JSON mass-assignment (Tier D: no impact)
- **Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2020-24941 — Laravel <6.18.35/<7.24.0; JSON-path key reaching a **guarded** column.
- **Lab:** `overlay/app/Setting.php:21` `$guarded=['id','is_admin']`, free `data` array column; scanner writes `data->marker` (`cve_2020_24941.py:72`) — `data` is **not** guarded.
- **Run:** DET `confirmed_vulnerable` · EXP `success=True` but response shows `is_admin:false` (marker only in `data`).
- **Flags:** LAB_ONLY_READBACK; no security boundary crossed. **Verdict:** 🔴 — benign over-post; the guarded-column bypass is never exercised.

---

## Summary counts
- 🟢 Faithful: **13** (incl. 21546 authed labs) — real product, real primitive, real proof.
- 🟡 Lab-assisted: **8** — real bug, one staged precondition (fix = relabel / wire real path).
- 🔴 Faked/misattributed: **9** — includes 2 hardcoded-success labs, 2 synthetic-gadget labs (one a duplicate), and 3 wrong-version/product/class.

Container run: 30/30 booted, 0 failures, all matched their documented matrix — including the fabricated-success labs, which is why matrix-green is not evidence of real exploitability.

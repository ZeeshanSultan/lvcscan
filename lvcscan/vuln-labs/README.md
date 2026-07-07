# Laravel Vulnerability Labs

Docker labs for validating CVE detection, exploitation, and mitigation via repo-root `check.py`.

**Documentation lives here only.** Individual lab directories do not carry README files.

## Taxonomy

| Directory | Use |
| --- | --- |
| `apps/` | Full Laravel applications (Snipe-IT, BookStack, Cachet, etc.), including real apps made vulnerable by bundled dependencies. Path: `apps/<application>/<version>/cve-<id>_<attack>_<ports>/` |
| `third-party/` | Community/vendor packages in a minimal Laravel host. Path: `third-party/<package>/<version>/cve-<id>_<attack>_<ports>/` |
| `first-party/` | Laravel-maintained packages (Reverb, Pulse, Fortify, Horizon, Livewire). Path: `first-party/<package>/<version>/cve-<id>_<attack>_<ports>/` |
| `framework/` | `laravel/framework` behaviors in a minimal host. Path: `framework/laravel/<version>/cve-<id>_<attack>_<ports>/` |

CVE inventory and mitigation steps: `docs/Laravel_Vulnerabilities.xlsx`.

## Apps Inventory

`apps/` entries must run a real upstream application. A dependency CVE belongs here when the
application bundles, pins, routes, or configures that dependency as part of the deployed app surface.

| App | Lab | Upstream app source | Vulnerable surface |
| --- | --- | --- | --- |
| Akaunting | `apps/akaunting/3.1.3/cve-2024-22836_authed-locale-cmdi-rce_41010-42010/` | `akaunting/akaunting:3.1.3` | Akaunting locale command injection |
| Badaso | `apps/badaso/2.9.10/cve-2024-21546_auth-filemanager-upload-rce_41013-42013/` | Laravel app with `badaso/core:2.9.10` | Bundled authenticated `unisharp/laravel-filemanager` upload RCE |
| BookStack | `apps/bookstack/0.25.2/cve-2020-5256_upload-rce_41012-42012/` | `BookStackApp/BookStack` tag `v0.25.2` | BookStack image upload RCE |
| Cachet | `apps/cachet/2.3.18/cve-2023-43661_authed-twig-ssti-config-disclosure_41009-42009/` | `cachethq/cachet` tag `v2.3.18` | Cachet incident-template Twig SSTI |
| Crater | `apps/crater/6.0.6/cve-2023-46865_authed-upload-logo-rce_41011-42011/` | `crater-invoice-inc/crater` tag `6.0.6` | Crater company logo upload RCE |
| Invoice Ninja | `apps/invoice-ninja/5.10.10/cve-2024-55555_unauth-route-deserialize-rce_41002-42002/` | `invoiceninja/invoiceninja:5.10.10` | Invoice Ninja `/route/{hash}` deserialization |
| InvoiceShelf | `apps/invoice-shelf/1.3.0/cve-2024-55556_unauth-cookie-deserialize-rce_41001-42001/` | `InvoiceShelf/InvoiceShelf` tag `1.3.0` | Cookie-session deserialization with known `APP_KEY` |
| Pterodactyl | `apps/pterodactyl/1.11.10/cve-2025-49132_unauth-locale-lfi-appkey-disclosure_41008-42008/` | `pterodactyl/panel` tag `v1.11.10` | Pterodactyl locale endpoint traversal/RCE |
| Snipe-IT | `apps/snipe-it/7.0.9/cve-2024-48987_unauth-cookie-deserialize-rce_41003-42003/` | `grokability/snipe-it` tag `v7.0.9` | Passport cookie deserialization with known `APP_KEY` |
| Snipe-IT | `apps/snipe-it/8.1.18/cve-2025-54068_auth-deserialize-rce_41004-42004/` | `grokability/snipe-it` tag `v8.1.18` | Authenticated Livewire unsafe property hydration RCE |

## Harness Truth Labels

Not every non-`apps/` lab is a full upstream application. Framework, first-party, and third-party
package labs must be read as minimal harnesses unless this inventory says otherwise.

| Lab | Truth label | Why |
| --- | --- | --- |
| `first-party/fortify/1.10.0/cve-2022-25838_totp-reuse_37004-38004/` | Minimal behavior harness | Tiny PHP route set proves TOTP replay semantics with a seeded secret; not a stock Fortify app/session flow. |
| `first-party/livewire/2.12.5/cve-2024-47823_unauth-upload-rce_37001-38001/` | Minimal package-behavior harness | Real Laravel host with vulnerable `livewire/livewire` and a lab upload sink; not a standalone upstream app. |
| `first-party/pulse/1.2.0/cve-2024-55661_auth-livewire-remember-rce_37003-38003/` | Minimal behavior harness | Tiny PHP route set models the authenticated Livewire `remember()` chain and mitigation flag; not stock Pulse. |
| `first-party/reverb/1.6.3/cve-2026-23524_redis-scaling-deserialize-rce_37002-38002/` | Minimal behavior harness | Tiny PHP worker/readback route plus Redis Pub/Sub models the scaling deserialization path; exploit requires reachable Redis. |
| `third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/` | Minimal package-behavior harness | Real Laravel host with `livewire-filemanager/filemanager:1.0.4`; not a full product app. |
| `third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_unauth-filemanager-upload-rce_35002-36002/` | Minimal package-behavior harness | Real Laravel host with `unisharp/laravel-filemanager:2.8.1` mounted without auth middleware; not a full product app. |
| `third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_auth-filemanager-upload-rce_35001-36001/` | Minimal package-behavior harness | Real Laravel/S-Cart host with `unisharp/laravel-filemanager:2.8.1` and seeded admin auth. |
| `framework/laravel/5.1.x/cve-2022-2870_laravel51-deser-catalog_39010-40010/` | Synthetic app-owned deserialization harness | Disputed Laravel 5.1 catalog row with a deliberately reachable `/deserialize` sink; vulnerable twin calls `unserialize()` on base64 request params, hardened twin uses `allowed_classes=false`. |
| `framework/laravel/5.1.x/cve-2022-2886_laravel51-deser-catalog_39011-40011/` | Synthetic app-owned deserialization harness | Disputed Laravel 5.1 catalog row with a deliberately reachable `/deserialize` sink; vulnerable twin calls `unserialize()` on base64 request params, hardened twin uses `allowed_classes=false`. |
| `framework/laravel/5.6.x/cve-2018-15133_xsrf-deserialize-rce_39002-40002/` | Minimal framework/app-sink harness | Uses a lab XSRF decrypt sink and fixed APP_KEY to prove the class; the Docker build is not a pinned stock vulnerable full app. |
| `framework/laravel/11.x/cve-2020-19316_filesystem-link-cmdi_39000-40000/` | Minimal app-owned command harness | Linux lab proves the unsafe link-command behavior through a custom route; the Windows harness is the closer `mklink` precondition proof. |
| `framework/laravel/11.x/cve-2021-43617_upload-rce_39004-40004/` | Minimal app-owned upload harness | Laravel host with deliberate no-validation upload route; real lab RCE, not a package-version proof. |
| `framework/laravel/8.5.9/cve-2021-28254_pendingbroadcast-deser_39008-40008/` | Minimal gadget/app-sink harness | Proves a PendingBroadcast POP chain through a deliberate unserialize sink; the framework fingerprint is harness-controlled. |

## Canonical reference lab

Copy this layout exactly for every new or migrated lab:

`third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/`

## Lab contract (minimal)

Each lab provides **only**:

| File | Role |
| --- | --- |
| `docker-compose.yml` | Two services: vulnerable + hardened twin |
| `run.sh` | Build/start and full teardown |
| `mitigate.sh` | Apply / preview / revert remediation |
| `exploit.py` | Standalone reference PoC for the lab's chain (the documented ground truth that the `modules/cves/cve_*.py` detector mirrors). Not part of the lab lifecycle — primary validation runs through repo-root `check.py` + the CVE module. |
| `scripts/entrypoint.sh` | In-container bootstrap (migrate, seed, links) |
| Stack Dockerfiles + minimal `app/` glue | Only what exposes the vuln surface |

**Host lifecycle shell scripts (exactly these two — no other `*.sh` lifecycle wrappers):**

```bash
bash run.sh        # docker compose up -d --build (both profiles)
bash run.sh down   # down -v --rmi local --remove-orphans

LVC_KEEP_IMAGES=1 bash run.sh down
# matrix/dev teardown: down -v --remove-orphans, preserving local images/cache

bash mitigate.sh         # apply xlsx remediation (idempotent)
bash mitigate.sh try     # print planned actions; change nothing
bash mitigate.sh revert  # undo remediation; re-arm for re-testing
```

`exploit.py` is the lab's standalone reference PoC (`python3 exploit.py`), not a lifecycle script. It documents the full chain; the authoritative validation path is still repo-root `check.py` + the CVE module (see **Validation** below).

Do **not** add per-lab `README.md`, `migrate.sh`, `lab.env`, Makefile targets, or fleet wrappers. Pin compose project name: `vuln-lab_<lab-dir-name>`.

Matrix runs should preserve local Docker images and layer cache. Use `tools/lab_image_preflight.py`
to pre-pull base/service images, then run `tools/lab_matrix_runner.py --preflight-images`; the
runner sets `LVC_KEEP_IMAGES=1` unless `--purge-images` is explicitly requested.

## Port ranges (one block per category)

Global rule: **hardened port = vulnerable port + 1000**. Each category owns a 2000-port reservation (vuln block + hardened block + buffer before the next category). Directory names must encode both: `cve-<id>_<slug>_<vulnPort>-<hardenedPort>`.

| Category | Vulnerable | Hardened (+1000) | Capacity | Examples |
| --- | --- | --- | --- | --- |
| `third-party/` | **35000–35099** | **36000–36099** | 100 labs | CVE-2025-14894 → `35000-36000` |
| `first-party/` | **37000–37099** | **38000–38099** | 100 labs | Reverb, Pulse, Fortify, Horizon, Livewire |
| `framework/` | **39000–39099** | **40000–40099** | 100 labs | Core routing, env, mass-assignment, debug |
| `apps/` | **41000–41199** | **42000–42199** | 200 labs | Snipe-IT, BookStack, Akaunting, Pterodactyl |

**Reserved buffers (do not assign lab ports):**

| Range | Purpose |
| --- | --- |
| `36100–36999` | Between third-party hardened and first-party vuln |
| `38100–38999` | Between first-party hardened and framework vuln |
| `40100–40999` | Between framework hardened and apps vuln |
| `42200+` | Future app expansion |

## Dual-port / WAF twin model

Every lab runs two profiles:

| Profile | Port | Role |
| --- | --- | --- |
| **Vulnerable** | category vuln range | Unpatched / exploitable — **primary `check.py` target** |
| **Hardened twin** | vuln + 1000 | Same stack with edge hardening (nginx rules, blocked sinks) — negative control |

Container names: `vuln-lab_<lab-dir-name>-vuln-<stack>` and `vuln-lab_<lab-dir-name>-hardened-<stack>`.

## Validation (repo root)

```bash
bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/run.sh
python3 check.py http://localhost:35000 --cve CVE-2025-14894
python3 check.py http://localhost:35000 --cve CVE-2025-14894 --exploit --command id
python3 check.py http://localhost:36000 --cve CVE-2025-14894 --exploit --command id   # expect fail (hardened)
bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/mitigate.sh
python3 check.py http://localhost:35000 --cve CVE-2025-14894 --exploit --command id   # expect fail
bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/mitigate.sh revert
bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/run.sh down
```

Expected outcomes: vulnerable port detect ✓ / exploit ✓ at rest; hardened port exploit ✗; after `mitigate.sh` apply, vulnerable exploit ✗; after `revert`, exploit ✓ again.

## Safety

Bind to localhost only. Do not expose lab containers outside the development machine.

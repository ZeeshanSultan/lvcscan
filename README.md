# lvcscan

Detection and exploitation of known CVEs across the Laravel ecosystem — the framework, first-party
packages (Reverb, Pulse, Fortify, Livewire), common third-party packages, and popular Laravel apps.
One scanner (`lvcscan/check.py`), one module per CVE, and a matching Docker lab (vulnerable + hardened
twin) for every module.

**Authorized use only.** Run this against systems you own or are contracted to test, or the bundled
labs. It exercises public CVEs with public PoCs; using it outside an authorized scope may be illegal.

## Requirements

- Python 3.10+ — `pip install -r lvcscan/requirements.txt` (`requests`, `colorama`, `urllib3`, `cryptography`)
- Docker + Compose — only to run the vuln-labs

## Usage

```bash
cd lvcscan

python3 check.py --list                                  # all CVEs, ranked, with required flags
python3 check.py https://target                          # detect-only sweep
python3 check.py https://target --cve CVE-2021-3129 --exploit --cmd id
python3 check.py https://target --cve CVE-2023-46865 --exploit --cmd id -U admin@site -P pass
python3 check.py https://target --cve CVE-2024-55555 --exploit --cmd id --app-key base64:...
python3 check.py https://target --json-out report.json --proxy http://127.0.0.1:8080
```

| Flag | Purpose |
| --- | --- |
| `--cve <ID>` | Target a single CVE (omit to sweep all) |
| `--exploit` | Attempt exploitation (default is detect-only) |
| `--cmd <cmd>` | Command to run for RCE modules |
| `-U` / `-P` | Credentials for authenticated CVEs |
| `--app-key <key>` | APP_KEY for deserialization CVEs (else recovered from a leak if present) |
| `--opt K=V` | Module-specific preconditions (e.g. `--opt redis_host=… --opt oob_read_url=…`) |
| `--json-out <path>` | Machine-readable report (`-` for stdout) |
| `--proxy <url>` | Route all traffic through a proxy; `--in-house` for hardened/internal targets |
| `--list-detectors` / `--trace-http` | List non-CVE detectors / log every request |

Verdicts are explicit: `confirmed_vulnerable`, `version_applicable`, `precondition_detected`,
`surface_present`, `blocked_by_control`, `not_detected`. An RCE only reports success on real command
output; a leaked-but-patched version is not reported vulnerable.

## Layout

```
lvcscan/
  check.py                    entry point
  modules/
    cves/                     one detect+exploit module per CVE, + metadata.py (catalog)
    detection/                non-CVE detectors (.env, git, debug tools, …) + tests/
    exploitation/ helpers/    shared exploitation + pipeline helpers
    generators/php_gadgets/   pure-python POP chains (Laravel/Guzzle/Monolog/Symfony)
    probes/ registry/ core/   APP_KEY recovery, registries, HTTP config
  vuln-labs/                  dual-port Docker labs (see vuln-labs/README.md)
  wordlists/  docs/           recon lists; CVE catalog spreadsheet
```

## Labs

Each lab ships a vulnerable profile and a hardened twin (same stack, real vendor fix) on paired ports
(`hardened = vulnerable + 1000`), bound to localhost. `.env` is generated at start from `.env.example`;
the APP_KEYs and seeded credentials in `run.sh`/entrypoints are public repo-default fixtures, not real
secrets. Full taxonomy and per-lab notes: [`lvcscan/vuln-labs/README.md`](lvcscan/vuln-labs/README.md).

```bash
cd lvcscan/vuln-labs/framework/laravel/8.4.x/cve-2021-3129_ignition-rce_39003-40003
bash run.sh                                                   # build + start both profiles
python3 ../../../../../check.py http://localhost:39003 --cve CVE-2021-3129 --exploit --cmd id
python3 ../../../../../check.py http://localhost:40003 --cve CVE-2021-3129 --exploit --cmd id   # hardened: blocked
bash mitigate.sh          # apply vendor fix in place (revert to re-arm)
bash run.sh down          # tear down
```

## Coverage

`--cmd` = command-capable RCE · `-U/-P` = needs auth · `--app-key` = needs a known/leaked APP_KEY.

| CVE | Sev | Target | Class | Needs |
| --- | --- | --- | --- | --- |
| CVE-2021-3129 | Critical | Laravel / Ignition (debug) | rce | `--cmd` |
| CVE-2021-43617 | Critical | Laravel ≤8.70.2 upload | rce (`.phar`/mimes) | `--cmd` |
| CVE-2021-28254 | Critical | Laravel PendingBroadcast | deserialize_rce | `--cmd` |
| CVE-2024-21546 | Critical | UniSharp laravel-filemanager | rce (upload) | `--cmd` |
| CVE-2024-22836 | Critical | Akaunting | rce (locale cmdi) | `--cmd -U/-P` |
| CVE-2024-55556 | Critical | InvoiceShelf / Crater | deserialize_rce | `--cmd --app-key` |
| CVE-2025-14894 | Critical | livewire-filemanager | rce (upload) | `--cmd` |
| CVE-2025-49132 | Critical | Pterodactyl Panel | rce (locale traversal) | `--cmd` |
| CVE-2025-54068 | Critical | Snipe-IT / Livewire v3 | deserialize_rce | `--cmd -U/-P` |
| CVE-2026-23524 | Critical | Laravel Reverb (Redis scaling) | deserialize_rce | `--cmd` + `--opt redis/oob` |
| CVE-2016-10074 | Critical | SwiftMailer (dependency) | rce (sendmail arg-inj) | `--cmd` |
| CVE-2024-48987 | High | Snipe-IT | deserialize_rce | `--cmd --app-key` |
| CVE-2024-55555 | High | Invoice Ninja | deserialize_rce | `--cmd --app-key` |
| CVE-2018-15133 | High | Laravel cookie / X-XSRF | deserialize_rce | `--cmd --app-key` |
| CVE-2023-43661 | High | Cachet (Twig SSTI chain) | ssti_chained_rce | `--cmd -U/-P` |
| CVE-2023-46865 | High | Crater upload-logo | rce | `--cmd -U/-P` |
| CVE-2020-5256 | High | BookStack image upload | rce | `--cmd -U/-P` |
| CVE-2024-55661 | High | Laravel Pulse (Livewire) | rce (`remember()`) | `--cmd -U/-P` |
| CVE-2024-47823 | High | Livewire temp-file upload | rce | `--cmd` |
| CVE-2020-19316 | High | Laravel `Filesystem::link()` (Windows) | rce (cmdi) | `--cmd` |
| CVE-2017-16894 | High | Laravel `.env` disclosure | info_disclosure | — |
| CVE-2022-25838 | High | Fortify 2FA (TOTP reuse) | totp_replay | — |
| CVE-2025-27515 | Medium | Laravel `files.*` validation | file_validation_bypass | `--cmd` |
| CVE-2024-52301 | Medium | Laravel `register_argc_argv` | config_manipulation | — |
| CVE-2020-24940 | Medium | Eloquent mass-assignment (table-strip) | mass_assignment | — |
| CVE-2020-24941 | Medium | Eloquent mass-assignment (JSON nesting) | mass_assignment | — |
| CVE-2024-29291 | Medium | `laravel.log` DB-cred disclosure (disputed) | info_disclosure | — |
| CVE-2017-14775 | Medium | Remember-me timing side-channel | timing_info_disclosure | `--cmd -U/-P` |
| CVE-2022-2870 | Low | Laravel 5.1 app-unserialize (disputed) | disputed_app_deser_pattern | `--cmd` |
| CVE-2022-2886 | Low | Laravel 5.1 app-unserialize (disputed) | disputed_app_deser_pattern | `--cmd` |

`python3 check.py --list` is the authoritative, live version of this table.

## License

No warranty. For authorized security assessment, research, and education only.

# lvcscan — Laravel CVE Scanning & Exploitation Framework

A detection-and-exploitation framework for **known, published CVEs in the Laravel ecosystem**
(the framework itself, first-party packages, common third-party packages, and popular Laravel
applications). It ships:

- a single-entry scanner (`lvcscan/check.py`) with per-CVE **detection** and **exploitation** modules,
- a fleet of **dual-port Docker vuln-labs** (vulnerable + hardened twin) to validate every module end-to-end,
- an honest, advisory-checked catalog (`docs/Laravel_Vulnerabilities.xlsx` + `modules/cves/metadata.py`).

> ## ⚠️ Authorized use only
> This is offensive security tooling. Use it **only** against systems you own or are explicitly
> authorized to test (your own infrastructure, the bundled labs, a sanctioned engagement). It targets
> **already-public** CVEs with **already-public** PoCs. Do not point it at third-party systems without
> written permission. You are responsible for staying within scope and applicable law.

---

## Why this exists

Built to inventory and demonstrate the org's Laravel exposure: scan internal hosts for known CVEs and
prove impact against **isolated, self-contained labs** before touching anything real. A core design goal
is **honesty** — a "green" result must reflect a real vulnerability, not a rigged lab. Every module was
cross-checked against its public advisory and validated against a real vulnerable build; see the audit
reports in the repo root:

- `LAB_BENCHMARK_AUDIT.md` — what each module really does vs. its advisory.
- `LAB_BENCHMARK_EVIDENCE_APPENDIX.md` — per-CVE evidence (advisory ↔ lab ↔ actual run).
- `LAB_BENCHMARK_REMEDIATION_FEASIBILITY.md` — realism remediation ledger.

Integrity features baked into the scanner:
- **Proof-of-execution gate** — an RCE `success` requires real command output carrying a per-run random
  nonce (a lab echoing a constant string cannot score a false positive).
- **Fail-open version gating** — a target that leaks a patched framework version is not reported vulnerable.
- **Honest verdicts** — `version_applicable` / `precondition_detected` / `surface_present` /
  `blocked_by_control` are distinguished from `confirmed_vulnerable`; OOB-only RCEs are reported as such.

---

## Install

```bash
cd lvcscan
python3 -m pip install -r requirements.txt   # requests, colorama, urllib3, cryptography
# Docker (+ compose) is required only to run the vuln-labs.
```

Python 3.10+ recommended.

## Usage

```bash
cd lvcscan

# List every exploit-capable CVE, ranked by independent severity, with the flags each needs
python3 check.py --list

# Detect-only sweep of a target (no exploitation)
python3 check.py https://target.example

# Detect + exploit a single CVE
python3 check.py https://target.example --cve CVE-2021-3129 --exploit --cmd 'id'

# Authenticated CVEs: pass credentials
python3 check.py https://target.example --cve CVE-2023-46865 --exploit --cmd 'id' -U admin@site -P '...'

# APP_KEY-gated deserialization CVEs: the scanner recovers a leaked/default key, or pass one
python3 check.py https://target.example --cve CVE-2024-55555 --exploit --cmd 'id' --app-key 'base64:...'

# Machine-readable report + route everything through a proxy (e.g. Burp)
python3 check.py https://target.example --json-out report.json --proxy http://127.0.0.1:8080
```

Useful flags: `--exploit`, `--cve <ID>`, `--cmd/--command`, `-U/-P`, `--app-key`, `--opt KEY=VALUE`
(module-specific preconditions, e.g. `--opt redis_host=… --opt oob_read_url=…`), `--json-out`,
`--proxy`, `--in-house` (de-emphasize noisy public probes on hardened/internal deployments),
`--list-detectors`, `--trace-http`.

## Repository layout

```
lvcscan/
  check.py                 # single entry point (banner, ranking, pipeline, reporting)
  requirements.txt
  modules/
    cves/                  # one detection+exploitation module per CVE + metadata.py (the catalog)
    detection/             # non-CVE detectors (.env, git, debug tools, mass-assignment, …) + tests/
    exploitation/          # shared exploitation helpers (OOB proof, …)
    generators/php_gadgets # pure-python phpggc-equivalent POP chains (Laravel/Guzzle/Monolog/Symfony)
    probes/                # APP_KEY recovery, path wordlists, response memo
    registry/              # CVE + detector registries (single source of truth)
    core/                  # HTTP config (proxy/TLS/headers/tracing)
    helpers/               # pipeline + livewire upload helpers
  vuln-labs/               # dual-port Docker labs (see vuln-labs/README.md)
  wordlists/               # recon + webshell path lists
  docs/Laravel_Vulnerabilities.xlsx   # the CVE catalog / sheet
```

## Vulnerability labs

Each lab is a self-contained Docker environment with a **vulnerable** profile and a **hardened twin**
(same stack, real vendor fix), on paired ports (`hardened = vulnerable + 1000`). Full docs, taxonomy,
port map, and per-lab truth labels: **`lvcscan/vuln-labs/README.md`**.

```bash
cd lvcscan/vuln-labs/framework/laravel/8.4.x/cve-2021-3129_ignition-rce_39003-40003
bash run.sh                 # build + start both profiles
python3 ../../../../../check.py http://localhost:39003 --cve CVE-2021-3129 --exploit --cmd id
python3 ../../../../../check.py http://localhost:40003 --cve CVE-2021-3129 --exploit --cmd id   # hardened → blocked
bash mitigate.sh            # apply the vendor remediation in-place (revert to re-arm)
bash run.sh down            # tear down
```

Labs bind to `127.0.0.1` only. `.env` files are generated at container start from `.env.example`
(never committed — see `.gitignore`); the APP_KEYs / seeded credentials that appear in `run.sh` and
lab entrypoints are the **public repo-default lab fixtures** the advisories themselves cite, not real
secrets.

## CVE coverage (30)

Detection + exploitation modules span Laravel framework, first-party packages (Reverb, Pulse, Fortify,
Livewire), third-party packages (UniSharp / livewire filemanagers), and applications (Snipe-IT, Invoice
Ninja, InvoiceShelf, Pterodactyl, Cachet, Akaunting, Crater, BookStack, Badaso). Highlights include the
Ignition RCE (CVE-2021-3129), the default-`APP_KEY` deserialization RCEs (CVE-2024-48987 / 55555 / 55556),
the Livewire/filemanager upload RCEs, the Pterodactyl locale traversal (CVE-2025-49132), and the Reverb
Redis-scaling deserialization RCE (CVE-2026-23524). Run `python3 check.py --list` for the current,
authoritative list with per-CVE severity, class, and required flags; per-CVE realism/status is in the
audit reports above.

## License / disclaimer

No warranty. Provided for authorized security assessment, research, and education. The maintainers accept
no liability for misuse. See the ⚠️ notice above.

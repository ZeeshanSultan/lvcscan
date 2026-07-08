"""Unified CVE metadata and loaders for scan/exploit modules."""

from __future__ import annotations

import importlib
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, Optional

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


@dataclass(frozen=True)
class CveMetadata:
    cve: str
    slug: str
    module: str
    severity: str
    vuln_class: str
    category: str
    description: str
    command_capable: bool
    auth: Dict[str, bool]
    app_key: Dict[str, Any]
    requires_component: Optional[str] = None
    scope: str = "generic"
    pass_creds: bool = False
    requires_auth: bool = False
    lab_default_creds: Optional[tuple[str, str]] = None
    preconditions: list[str] | None = None

    @property
    def cve_meta_tuple(self) -> tuple[str, str, bool, bool, bool]:
        return (
            self.severity,
            self.vuln_class,
            self.command_capable,
            bool(self.auth.get("exploit_required")),
            bool(self.app_key.get("required_for_exploit")),
        )

    def detector_spec(self) -> Dict[str, Any]:
        spec: Dict[str, Any] = {
            "name": self.slug,
            "module": self.module,
            "func": "scan",
            "category": "cve",
            "cve": self.cve,
            "description": self.description,
        }
        if self.requires_component:
            spec["requires_component"] = self.requires_component
        if self.requires_auth:
            spec["requires_auth"] = True
        if self.pass_creds:
            spec["pass_creds"] = True
        if self.scope != "generic":
            spec["scope"] = self.scope
        return spec


_CVE_ROWS = [{'cve': 'CVE-2017-16894',
  'slug': 'cve_2017_16894',
  'module': 'modules.cves.cve_2017_16894',
  'severity': 'High',
  'vuln_class': 'info_disclosure',
  'category': 'cve',
  'description': '.env disclosure / APP_KEY + credential leak',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': ['app_key'],
              'provides_on_exploit': ['app_key'],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Published advisory cites Laravel through 5.5.21, but the exposure is a deploy/permissions misconfiguration that is version-agnostic on the 5.5 line (no version-specific framework code path). The lab installs the latest Laravel 5.5.x release via `composer create-project laravel/laravel:5.5.*` (resolves above 5.5.21) and reports the real version via `app()->version()`; neither the detector nor the exploit applies a version gate (both are purely behavioral: GET /.env + secret-pattern match).',
                    'Config: Web server serves dotfiles or backup env files (document root is the Laravel project root, or the webserver serves dotfiles, instead of the intended /public subdirectory)',
                    'Network: Attacker must reach a web server path that exposes .env or backup environment files directly. Proof is direct HTTP file disclosure; no command execution or OOB channel is involved.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2017-14775',
  'slug': 'cve_2017_14775',
  'module': 'modules.cves.cve_2017_14775',
  'severity': 'Medium',
  'vuln_class': 'timing_info_disclosure',
  'category': 'cve',
  'description': '[Advisory: timing side-channel / info-disclosure, CWE-200. Lab RCE uses seeded creds plus a custom /admin/upload sink, not the real CVE impact.] Remember-me timing oracle → session hijack → admin upload RCE chain',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': True,
  'lab_default_creds': None,
  'preconditions': ['Auth: No-default exploit — the operator must supply explicit credentials (-U/-P) OR known remember-me token material (--opt remember_token=... with --app-key, or --opt remember_chain=1 to attempt the timing oracle). The exploit injects no built-in default credentials. Working chain: explicit seeded-admin login (the lab seeds admin@lab.local / password; pass them via -U/-P, e.g. run.sh does) → authenticated session → POST /admin/upload of a .php webshell → in-band RCE. A known remember_token can alternatively forge a valid remember-me cookie that hijacks the admin session. The remember-me timing side channel is the modeled root cause only: the timing differential in EloquentUserProvider::retrieveByToken() is real but not reliably recoverable over HTTP, so the lab ships no working unauthenticated token-recovery PoC. Lab pins APP_KEY for reproducible cookie forgery; pass it via --app-key (run.sh does).',
                    'Affected version: laravel/framework < 5.5.10 (EloquentUserProvider::retrieveByToken compared remember_token in a SQL WHERE clause — non-constant-time at the DB layer — before the 5.5.10 fix that loads the user by id then compares with hash_equals()).',
                    'Config: Application uses database remember-me tokens and exposes a post-auth file-upload sink under public/uploads (lab: POST /admin/upload).',
                    'Network: Attacker must reach HTTP(S) /login, remember-me cookie handling, and the admin upload path. Proof is in-band PHP execution via uploaded webshell readback; no OOB channel required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2025-49132',
 'slug': 'cve_2025_49132',
 'module': 'modules.cves.cve_2025_49132',
 'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Pterodactyl Panel unauthenticated RCE via /locales/locale.json traversal and PHP PEAR',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': ['app_key'],
              'provides_on_exploit': ['app_key'],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
 'preconditions': ['Auth:',
                   '- Unauthenticated.',
                   '- No credentials required.',
                   '- No APP_KEY required; config disclosure may reveal one.',
                   '',
                   'Affected version:',
                   '- Pterodactyl Panel <= 1.11.10.',
                   '- Lab pins Pterodactyl Panel 1.11.10 on `php:8.2-apache` with PEAR available.',
                   '',
                   'Config:',
                   '- `/locales/locale.json` traversal can include/read unintended files.',
                   '- Command-capable proof requires reachable PEAR `pearcmd.php` and `register_argc_argv=On`.',
                   '- Hardened profile blocks traversal/PEAR command path.',
                   '',
                   'Network:',
                   '- Attacker must reach `/locales/locale.json`.',
                   '- Proof is in-band HTTP LFI/config disclosure and PEAR file-write/include for command-capable path.',
                   '- No callback or OOB channel is required.',
                   '',
                   'Lab rebuild (standard vulnerable/hardened pair):',
                   '- Required files: `run.sh`, `mitigate.sh`.',
                   '- HTTP ports: vulnerable `41008`; hardened `42008`.',
                   '- Lifecycle: from the lab directory run `bash run.sh`; stop with `bash run.sh down`; apply mitigation with `bash mitigate.sh`; revert with `bash mitigate.sh revert`.',
                   '- Services/runtime: vulnerable `vulnerable-apache` (php:8.2-apache; Lab pins Pterodactyl Panel 1.11.10 on `php:8.2-apache` with PEAR available.); hardened `hardened-nginx` (php:8.2-apache; Lab pins Pterodactyl Panel 1.11.10 on `php:8.2-apache` with PEAR available.); topology vuln-db, vulnerable-apache, hardened-db, hardened-nginx.',
                   '- Delta/surface/data: vulnerable condition: Pterodactyl 1.11.10 locale traversal plus PEAR/register_argc_argv command path.; hardened control: Patch locale traversal and block PEAR/include command path.; route/surface: /locales/locale.json?locale=...&namespace=...; seeded data: a real APP_KEY (php artisan key:generate) and real DB credentials (DB_USERNAME/DB_PASSWORD) are written into .env — these are the disclosure TARGET of the LFI/config-disclosure chain, not an attacker precondition.',
                   '- Generic validation oracle: vulnerable profile proves the issue; hardened profile is negative or blocked; command-capable proofs should execute only on the vulnerable profile; non-RCE/catalog labs should produce their documented non-command proof or refusal.',
                   '',
                   'Flags:',
                   '- Requires Auth (detect): No',
                   '- Requires Auth (exploit): No',
                   '- Command Capable: Yes',
                   '- APP_KEY Required: No',
                   '- Scenario Type: Realistic but config-dependent']},
 {'cve': 'CVE-2023-43661',
  'slug': 'cve_2023_43661',
  'module': 'modules.cves.cve_2023_43661',
  'severity': 'High',
  'vuln_class': 'ssti_chained_rce',
  'category': 'cve',
  'description': '[Advisory: authenticated Twig SSTI -> RCE. VERIFIED chained RCE: SSTI leaks APP_KEY, then a forged Laravel 5.2 encrypted X-XSRF-TOKEN (Guzzle/RCE1) unserializes -> command exec (uid=33(www-data) observed). Direct Twig command-exec is unavailable on the pinned Twig 1.40.1, but the CVE RCE is achieved via the key-leak deserialization chain.] Cachet authenticated Twig SSTI APP_KEY disclosure -> Laravel X-XSRF-TOKEN deserialization RCE chain',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': ['app_key'],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': ('admin@cachet.test', 'Password123'),
  'preconditions': ['Auth: Public Cachet API fingerprint/version detection is unauthenticated; the actual '
                    'Twig SSTI proof requires a dashboard session with ability to create or render incident '
                    'templates. No APP_KEY is required because this CVE can PRODUCE an APP_KEY via config '
                    'disclosure. The local lab seeds admin@cachet.test / Password123; the module logs in '
                    'and extracts the user API key from /dashboard/user before calling the API sink.',
                    'Affected version: Cachet <= 2.3.18.',
                    'Network: Attacker must authenticate to Cachet and reach incident-template/config '
                    'rendering over HTTP(S), then reach a Laravel web route protected by VerifyCsrfToken '
                    '(default lab sink: POST /auth/login). Stage 1 is in-band APP_KEY disclosure; stage 2 '
                    'uses that key to forge an encrypted X-XSRF-TOKEN carrying a compatible Guzzle/Monolog '
                    'PHP object gadget. Command proof is reflected in-band; no callback/OOB is required.',
                    'Flags:',
                    '- Requires Auth (detect): No for fingerprint/version; Yes for active SSTI proof/exploit',
                    '- Command Capable: Yes (via APP_KEY -> Laravel 5.2 decrypt/unserialize chain)',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2018-15133',
  'slug': 'cve_2018_15133',
  'module': 'modules.cves.cve_2018_15133',
  'severity': 'High',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'Encrypted X-XSRF-TOKEN deserialization (known APP_KEY)',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': True,
              'consumes': ['app_key'],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; requires a known/leaked APP_KEY.',
                    'Affected version: Laravel <= 5.5.40 or 5.6.x <= 5.6.29 (affected range)',
                    'Config: Old app images / committed .env shipping default or leaked APP_KEY enable the '
                    'unauthenticated path (with a valid APP_KEY, an encrypted serialized gadget in '
                    'X-XSRF-TOKEN executes via Encrypter::decrypt() -> unserialize())',
                    'Network: Attacker must reach the HTTP(S) Laravel endpoint that decrypts '
                    'X-XSRF-TOKEN/cookie payloads. Exploitation requires a valid APP_KEY to forge the '
                    'encrypted serialized gadget; proof is direct HTTP sink/readback, not OOB.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: Yes']},
 {'cve': 'CVE-2024-48987',
  'slug': 'cve_2024_48987',
  'module': 'modules.cves.cve_2024_48987',
  'severity': 'High',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'Snipe-IT cookie/session deserialization RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': False},
  'app_key': {'required_for_exploit': True,
              'consumes': ['app_key'],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': 'base64:3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ='},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': ('admin', 'Password123!'),
  'preconditions': ['Auth: Unauthenticated; requires a known/leaked APP_KEY.',
                    'Affected version: Snipe-IT < 7.0.10.',
                    'Config: Passport cookie serialization plus EncryptCookies serialize=true causes '
                    'decrypted XSRF-TOKEN cookie plaintext to enter PHP unserialize(); a valid APP_KEY is '
                    'required to forge the encrypted cookie.',
                    'Network: Attacker must reach the HTTP(S) app endpoint accepting XSRF-TOKEN/session '
                    'cookies, typically /login. Exploitation is direct HTTP cookie delivery with marker-file '
                    'readback; no login, callback, or external OOB channel is required, but APP_KEY material '
                    'is mandatory.',
                    'Lab rebuild: '
                    '`vuln-labs/apps/snipe-it/7.0.9/cve-2024-48987_unauth-cookie-deserialize-rce_41003-42003/run.sh`; '
                    'Snipe-IT v7.0.9 on php:8.2-apache; lab .env bakes APP_KEY '
                    'base64:3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ=; optional creds admin/Password123!; '
                    'ports 41003/42003.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: Yes']},
 {'cve': 'CVE-2024-55555',
  'slug': 'cve_2024_55555',
  'module': 'modules.cves.cve_2024_55555',
  'severity': 'High',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'Invoice Ninja route/hash deserialization RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': True,
              'consumes': ['app_key'],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': 'base64:RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno='},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; requires a known/leaked APP_KEY.',
                    'Affected version: Invoice Ninja < 5.10.43 (fixed in 5.10.43 per NVD/GHSA); '
                    'Metasploit-validated exploitable range is >= 5.8.22 and <= 5.10.10',
                    'Network: Attacker must reach the HTTP(S) route/hash endpoint that accepts encrypted '
                    'Laravel payloads. Exploitation requires a valid APP_KEY to forge the payload, and proof '
                    'is direct HTTP sink/readback rather than OOB.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: Yes']},
 {'cve': 'CVE-2024-55556',
  'slug': 'cve_2024_55556',
  'module': 'modules.cves.cve_2024_55556',
  'severity': 'Critical',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'InvoiceShelf/Crater cookie-session deserialization RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': True,
              'consumes': ['app_key'],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': 'base64:kgk/4DW1vEVy7aEvet5FPp5un6PIGe/so8H0mvoUtW0='},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; requires a known/leaked APP_KEY.',
                    'Affected version: InvoiceShelf <= 1.3.0 (patched in 2.0.0); affected Crater <= 6.0.6.',
                    'Config: SESSION_DRIVER=cookie (encrypted laravel_session carries serialized PHP) and a valid APP_KEY is known or recovered by chaining.',
                    'Network: Attacker must reach the HTTP(S) app endpoint that accepts encrypted cookie sessions. The proof channel is an out-of-band HTTP callback from the target to a listener (an always-on auto-bound local listener by default, or an operator-supplied OOB/OAST URL the target POSTs d=<base64url(output)> to). The module additionally tees command output to candidate web-served paths as a best-effort readback, but on a default InvoiceShelf deploy that readback is non-functional: DocumentRoot is public/ (root-owned, not www-data-writable) and /storage is not symlinked, so there is no web-served path the scanner can read back. Consequently, if egress to the listener is blocked and no reachable operator OOB URL is supplied, the exploit reports "sink fired (gadget verified); no proof channel reachable in this environment" rather than a successful in-band readback. APP_KEY material is mandatory for the forged cookie.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: Yes']},
 {'cve': 'CVE-2024-47823',
  'slug': 'cve_2024_47823',
  'module': 'modules.cves.cve_2024_47823',
  'severity': 'High',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Livewire temp-file upload validation bypass',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': 'livewire',
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Advisory rates this PR:L — a real deployment requires an AUTHENTICATED low-privilege user able to reach a Livewire upload component. The lab mounts the component on a PUBLIC /upload route (no auth) for reproduction, so the scanner needs no credentials here, but production exploitation is not truly anonymous. No APP_KEY required.',
                    'Affected version: Livewire < 2.12.7 or v3 < 3.5.2 (v3 affected range v3.0.0-beta.1 through v3.5.1; fixed in 2.12.7 and 3.5.2)',
                    "Config: Application stores uploads using the original client filename (e.g. $file->getClientOriginalName() / storeAs() preserving the client name) rather than Livewire's default randomized hashed filename",
                    'Network: Attacker must reach the Livewire upload HTTP(S) endpoint and then request the web-served uploaded file path for proof. The primary unauthenticated /upload path needs no credentials; seeded credentials (admin@example.com / Password123!) are only for the secondary authenticated Filament logo-upload sink. No callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2025-54068',
  'slug': 'cve_2025_54068',
  'module': 'modules.cves.cve_2025_54068',
  'severity': 'Critical',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'Livewire v3 unsafe-hydration RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': 'livewire',
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': ('admin', 'Password123!'),
  'preconditions': ['Auth: AUTHENTICATED against this lab. The lab now exploits the REAL stock Snipe-IT sink — the untyped `public $name` on App\\Livewire\\PersonalAccessTokens at the authenticated route /account/api (the synthetic unauthenticated /demo component was removed for realism). Detection runs unauthenticated (finds no reachable component -> not_detected); exploitation requires seeded staff creds (-U admin -P Password123!). The Livewire hydration bug is unauthenticated by CVE class, but the genuine Snipe-IT surface is auth-gated. No APP_KEY required.',
                    'Affected version: Reachable Livewire v3 component, versions 3.0.0-beta.1 through 3.6.3 (fixed in 3.6.4)',
                    'Config: Component has at least one untyped/weakly-typed public property (e.g. public $count = 0;); a scalar type hint such as public int $count closes the hole',
                    'Network: Attacker must authenticate to Snipe-IT and reach the real Livewire component at /account/api (the module logs in with -U/-P, fetches the component snapshot, and sends the malicious hydration update). The exploit trigger and proof are in-band HTTP, not OOB.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2025-14894',
  'slug': 'cve_2025_14894',
  'module': 'modules.cves.cve_2025_14894',
  'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'livewire-filemanager unrestricted PHP upload RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': 'livewire',
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: livewire-filemanager/filemanager <= 1.0.4 installed '
                    '(patched by v1.0.5+ / v1.1.0 file validation). Third-party package, '
                    'NOT Laravel core.',
                    'Config: `php artisan storage:link` created so uploaded media at '
                    'storage/app/public/<media_id>/<file> is web-served at /storage/<id>/<file> (public '
                    'storage exposure)',
                    'Network: Attacker must reach the filemanager upload HTTP(S) endpoint and then request '
                    'the web-served uploaded file path under public storage for proof. No separate callback, '
                    'listener, or OOB channel is required.',
                    'Lab rebuild: `bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/run.sh`; '
                    'php:8.2-apache image; `composer create-project laravel/laravel:^11.0` + '
                    'livewire-filemanager/filemanager:1.0.4; entrypoint runs migrate + storage:link; '
                    'HTTP 127.0.0.1:35000 (vulnerable) / :36000 (hardened); no seeded credentials.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2026-23524',
  'slug': 'cve_2026_23524',
  'module': 'modules.cves.cve_2026_23524',
  'severity': 'Critical',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'Laravel Reverb Redis-scaling deserialization RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': 'laravel_reverb',
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: laravel/reverb <= 1.6.3 (fixed 1.7.0 with an allow-list).',
                    "Config: In production, the Redis horizontal-scaling backend must be enabled (REVERB_SCALING_ENABLED=true) so a Reverb worker subscribes to the Redis scaling channel. This lab models that end state directly: its worker subscribes to the 'reverb' channel unconditionally in BOTH the vulnerable and hardened profiles (no REVERB_SCALING_ENABLED env gate is read; compose sets only APP_URL, LAB_HARDENED, REDIS_HOST, REDIS_PORT), so an active scaling subscriber is always present and there is no config gate to satisfy.",
                    'Network: Exploitation is OOB/side-channel, not an HTTP route exploit. Attacker must be able to publish a crafted serialized message to the Redis scaling bus (local lab: redis on host 127.0.0.1:6379 vulnerable / :6380 hardened, or operator-supplied redis_host/redis_port). HTTP 37002/38002 fingerprints Reverb and polls optional /reverb-oob readback; the RCE trigger is Redis Pub/Sub consumption by the worker.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2021-3129',
  'slug': 'cve_2021_3129',
  'module': 'modules.cves.cve_2021_3129',
  'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Laravel Ignition /_ignition execute-solution RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: facade/ignition <= 2.5.1 (vulnerable; Laravel < 8.4.2 ships it); affected: facade/ignition < 2.5.2 with Laravel APP_DEBUG=true',
                    'Config: APP_ENV != production AND APP_DEBUG=true. The GATING condition is APP_ENV != production -- facade/ignition only registers its /_ignition/* debug routes when the app is NOT in production, so APP_DEBUG=true alone is insufficient. The lab sets APP_ENV=local + APP_DEBUG=true (vulnerable); hardening/mitigation flips APP_ENV=production, which deregisters POST /_ignition/execute-solution -> HTTP 404 and neutralizes the bug.',
                    "Network: Attacker must reach Ignition's HTTP(S) solution endpoint while APP_ENV != production and APP_DEBUG=true. Exploitation is triggered through direct HTTP requests and local log-file manipulation; no callback or OOB channel is required.",
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2021-28254',
  'slug': 'cve_2021_28254',
  'module': 'modules.cves.cve_2021_28254',
  'severity': 'Critical',
  'vuln_class': 'deserialize_rce',
  'category': 'cve',
  'description': 'PendingBroadcast deserialization RCE (direct unserialize)',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Vulnerable framework Laravel/laravel-framework <= 8.5.9 installed to provide the PendingBroadcast::__destruct() POP gadget',
                    'Config: Target application exposes a reachable unserialize() sink on attacker-controlled data…',
                    'Network: Attacker must reach a developer-provided HTTP(S) endpoint that passes attacker-controlled input to unserialize(). The gadget trigger and proof are in-band HTTP; no callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2024-52301',
  'slug': 'cve_2024_52301',
  'module': 'modules.cves.cve_2024_52301',
  'severity': 'Medium',
  'vuln_class': 'config_manipulation',
  'category': 'cve',
  'description': 'Environment/session manipulation via register_argc_argv',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Laravel framework in affected range: < 6.20.45, 7.x < 7.30.7, 8.x < '
                    '8.83.28, 9.x < 9.52.17, 10.x < 10.48.23, 11.x < 11.31.0',
                    'Config: PHP directive register_argc_argv=On in php.ini (causes PHP to populate '
                    "$_SERVER['argv'] from the query string on web/non-CLI requests)…",
                    'Network: Attacker must reach the HTTP(S) application with PHP register_argc_argv=On and '
                    'influence the query string. Proof is in-band environment/config manipulation, not '
                    'command execution or OOB.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2024-29291',
  'slug': 'cve_2024_29291',
  'module': 'modules.cves.cve_2024_29291',
  'severity': 'Medium',
  'vuln_class': 'info_disclosure',
  'category': 'cve',
  'description': 'Laravel laravel.log database credential disclosure',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: disputed Laravel Framework 8 through 11 CVE record; practical '
                    'exposure is framework/deployment independent when laravel.log is web-readable.',
                    'Config: storage/logs/laravel.log or an equivalent Laravel log path is publicly '
                    'readable, and the log contains cleartext database credential material such as '
                    'DB_PASSWORD/DB_USERNAME pairs or PDO->__construct() username/password arguments.',
                    'Network: Attacker must reach the exposed log path over HTTP(S). Proof is read-only '
                    'credential disclosure; no command execution, callback, or OOB channel is involved. '
                    'A readable log without database credential evidence is only a generic log exposure, '
                    'not a confirmed CVE-2024-29291 finding.',
                    "Detection: Detection gates on a Laravel-log-format indicator BEFORE credential detection — the generic log_exposure scan must first see HTTP 200 at /storage/logs/laravel.log AND a Laravel log-format marker (e.g. 'local.ERROR'/'production.ERROR'); if that early-return yields nothing, the module stops without inspecting for credentials.",
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2021-43617',
  'slug': 'cve_2021_43617',
  'module': 'modules.cves.cve_2021_43617',
  'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Upload validation bypass (.phar / executable PHP)',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Laravel Framework through 8.70.2 (<= 8.70.2)',
                    'Config: Upload endpoint validates uploads with the framework `mimes:jpg,jpeg,png,gif` rule and stores accepted files under their original client filename in a web-served, .phar-executing directory. NVD root cause: on laravel/framework <= 8.70.2, validateMimes()->shouldBlockPhpUpload() blocks php/php3/php4/php5/phtml but omits `.phar`, so a GIF-polyglot .phar (guessExtension()==\'gif\') passes the image validation, is stored under its .phar name, and executes where Apache/Debian maps .phar -> application/x-httpd-php.',
                    'Network: Attacker must reach the HTTP(S) upload endpoint and then request the web-served uploaded file path for proof. No separate callback, listener, or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2024-21546',
  'slug': 'cve_2024_21546',
  'module': 'modules.cves.cve_2024_21546',
  'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'UniSharp laravel-filemanager upload RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': ('admin', 'admin'),
  'preconditions': ['Auth: Unauthenticated by CVE class; the unauth package harness exposes the sink without '
                    'credentials, while the S-Cart and Badaso app labs auth-gate the sink with seeded creds. '
                    'No APP_KEY required.',
                    'Affected version: App embeds unisharp/laravel-filemanager < 2.9.1 (fixed in 2.9.1). '
                    'Unauth package harness and S-Cart auth lab pin 2.8.1; Badaso app lab pins 2.6.x.',
                    "Config: Uploads are stored under a PHP-executing web path, but the upload-serving URL prefix differs per lab: /storage (via storage:link) for the unauth package harness and the Badaso app lab, and /data for the S-Cart auth lab (S-Cart's LFM 'uploads' disk root is public_path('data')).",
                    'Network: Attacker must reach the laravel-filemanager upload HTTP(S) endpoint and then '
                    'request the uploaded PHP path for readback. The lab may require seeded credentials, but '
                    'no callback or OOB channel is required.',
                    'Lab rebuild: unauth package harness '
                    '`vuln-labs/third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_unauth-filemanager-upload-rce_35002-36002` '
                    '(php:8.2-apache, no creds, ports 35002/36002); auth lab '
                    '`vuln-labs/third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_auth-filemanager-upload-rce_35001-36001` '
                    '(php:8.1-apache, creds admin/admin, ports 35001/36001); Badaso app lab '
                    '`cve-2024-21546_auth-filemanager-upload-rce_41013-42013` '
                    '(creds admin@badaso.test/Password123!, ports 41013/42013).',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2022-2870',
  'slug': 'cve_2022_2870',
  'module': 'modules.cves.cve_2022_2870',
  'severity': 'Low',
  'vuln_class': 'disputed_app_deser_pattern',
  'category': 'cve',
  'description': '[DISPUTED non-framework CVE (VulDB). Synthetic /deserialize sink plus lab-authored gadget; not reproducible on stock Laravel.] Laravel 5.1 synthetic app-level deserialization lab (disputed CVE)',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated in the synthetic lab; no APP_KEY required. The real CVE remains '
                    'a disputed/app-level unsafe unserialize row, not a confirmed framework-owned sink.',
                    'Affected version: Laravel version in the 5.1.0-5.1.46 range as named by the CVE '
                    '(incidental - no framework code is involved and there is no framework patch/fixed '
                    'version).',
                    'Config: The reproducible lab deliberately adds an app-owned GET/POST /deserialize '
                    'route that base64-decodes every request parameter and calls unserialize() on the '
                    'decoded value. The hardened twin keeps the route but uses allowed_classes=false so '
                    'objects are not instantiated.',
                    'Network: Attacker must reach the synthetic /deserialize endpoint. The module injects '
                    'a lab-local serialized marker gadget by default and a lab-local command gadget when '
                    '--command is supplied; no callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2025-27515',
  'slug': 'cve_2025_27515',
  'module': 'modules.cves.cve_2025_27515',
  'severity': 'Medium',
  'vuln_class': 'file_validation_bypass',
  'category': 'cve',
  'description': '[Advisory: file-validation bypass, not directly RCE. Lab RCE depends on app storing uploads under original name on a public PHP-exec disk.] Wildcard file/image validation bypass',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Affected: Laravel 10.0.0-10.48.28, 11.0.0-11.44.0 and 12.0.0-12.1.0',
                    "Config: A wildcard `files.*` validation rule using the FLUENT File rule object (Illuminate\\Validation\\Rules\\File, e.g. File::types([...])) is present. Plain string rules ('image' / 'mimes:...') are NOT bypassable here because they additionally route through shouldBlockPhpUpload(); only the fluent File rule object on a `files.*` wildcard is exploitable.",
                    'Network: Attacker must reach the vulnerable HTTP(S) validation endpoint accepting '
                    'nested files.* upload data. Proof is direct HTTP-triggered execution through the '
                    'validation path; no callback or OOB channel is required.',
                    'Detection: Detection is version-only and never touches the upload route — it requires a web-reachable Laravel version source (an HTML 3-part version leak, an exposed /.env or /_debugbar, or an exposed /composer.lock) to read the framework version and compare it against the affected ranges.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2016-10074',
  'slug': 'cve_2016_10074',
  'module': 'modules.cves.cve_2016_10074',
  'severity': 'Critical',
  'vuln_class': 'swiftmailer_dependency_rce',
  'category': 'cve',
  'description': '[SwiftMailer package CVE (<5.4.5), NOT Laravel core. Needs old Laravel with sendmail transport plus attacker-controlled From. No lab present.] SwiftMailer sendmail argument-injection RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: SwiftMailer <= 5.4.4 when Laravel or another PHP app uses the '
                    'vulnerable sendmail/mail transport.',
                    'Config: A reachable mail-sending endpoint passes attacker-controlled '
                    'From/Sender/Return-Path data into SwiftMailer sendmail transport.',
                    'Network: Attacker must reach the HTTP(S) mail-send proof endpoint. Exploitation injects '
                    'sendmail arguments through the email reverse-path and reads the written proof file over '
                    'HTTP; no APP_KEY, callback, or external OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2020-19316',
  'slug': 'cve_2020_19316',
  'module': 'modules.cves.cve_2020_19316',
  'severity': 'High',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Filesystem::link() command injection',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Laravel framework < 5.8.17 (upstream framework fix adds escapeshellarg() to both link() arguments; ref commit 44c3feb604944599ad1c782a9942981c3991fa31). NOTE: this affected-version field describes the historical framework CVE; the reproducible labs do NOT pin < 5.8.17 — they re-create the command-injection CLASS (see Config) and the detector/exploit are version-agnostic, keying on reflected shell output rather than a version banner.',
                    "Config: The DEFAULT reproducible lab (ports 39000/40000, what run.sh builds and the module exploit() proves against) models the command-injection class on LINUX: a public GET /storage/link route concatenates the attacker-controlled `target`/`link` query params straight into a shell `ln -s <target> <link> 2>&1` via shell_exec on php:8.2-apache, with no escaping, and reflects the combined stdout+stderr. The original CVE's `mklink` Windows-only framework branch is reproduced only by the OPTIONAL Windows sub-lab (raw PHP 7.3.33 + router.php running `cmd.exe /C mklink`), which requires Docker in Windows containers mode. The lab's hardened twin does NOT add escapeshellarg(); it replaces the shell invocation with PHP's native symlink() plus an allowlist that rejects shell metacharacters and '..' traversal and returns a fixed sanitized status (no reflected OS output) — same approach on the Windows hardened path.",
                    'Network: Attacker must reach the HTTP(S) route that invokes the vulnerable storage-link sink. The command sink is local shell execution with a direct HTTP trigger/proof (Linux `ln -s` in the default lab, Windows `mklink` in the optional sub-lab); no callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2022-2886',
  'slug': 'cve_2022_2886',
  'module': 'modules.cves.cve_2022_2886',
  'severity': 'Low',
  'vuln_class': 'disputed_app_deser_pattern',
  'category': 'cve',
  'description': '[DISPUTED non-framework CVE (VulDB). Duplicate of CVE-2022-2870 (identical lab/gadget). Synthetic sink; not reproducible on stock Laravel.] Laravel 5.1 synthetic app-level deserialization lab (disputed CVE)',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated in the synthetic lab; no APP_KEY required. The real CVE remains '
                    'a disputed/app-level unsafe unserialize row, not a confirmed framework-owned sink.',
                    'Affected version: Laravel 5.1.0 through 5.1.46 (per NVD/VulDB).',
                    'Config: The reproducible lab deliberately adds an app-owned GET/POST /deserialize '
                    'route that base64-decodes every request parameter and calls unserialize() on the '
                    'decoded value. The hardened twin keeps the route but uses allowed_classes=false so '
                    'objects are not instantiated.',
                    'Network: Attacker must reach the synthetic /deserialize endpoint. The module injects '
                    'a lab-local serialized marker gadget by default and a lab-local command gadget when '
                    '--command is supplied; no callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2024-55661',
  'slug': 'cve_2024_55661',
  'module': 'modules.cves.cve_2024_55661',
  'severity': 'High',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Laravel Pulse authenticated Livewire remember() RCE',
  'command_capable': True,
  'auth': {'scan_required': True, 'scan_enhanced_by_auth': False, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': ['app_key'],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': True,
  'lab_default_creds': ('admin@example.com', 'LabAdmin123!'),
  'preconditions': ['Auth: Authenticated; no APP_KEY required.',
                    'Affected version: Laravel Pulse < 1.3.1 installed (lab models Pulse 1.2.0 vulnerable / '
                    '1.3.1 mitigated in a minimal php:8.2-apache package-behavior harness).',
                    'Config: Pulse dashboard/card uses RemembersQueries::remember() and attacker can '
                    'influence the remembered query key or Livewire state.',
                    'Network: Attacker must authenticate to the Pulse HTTP(S) endpoint and reach the '
                    'follow-on decrypt/unserialize sink used after APP_KEY disclosure. Proof is in-band via '
                    'the lab endpoints and does not require a separate OOB listener.',
                    'Lab rebuild: '
                    '`vuln-labs/first-party/pulse/1.2.0/cve-2024-55661_auth-livewire-remember-rce_37003-38003/run.sh`; '
                    'minimal php:8.2-apache Pulse package-behavior harness; creds admin@example.com/LabAdmin123!; '
                    'ports 37003/38003.',
                    'Flags:',
                    '- Requires Auth (detect): Yes',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2022-25838',
  'slug': 'cve_2022_25838',
  'module': 'modules.cves.cve_2022_25838',
  'severity': 'High',
  'vuln_class': 'totp_replay',
  'category': 'cve',
  'description': 'Fortify TOTP reuse (2FA timing) — self-fetches the seeded secret, no auth required '
                 '(matches exploit_registry auth_required=False)',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Affected: laravel/fortify < 1.11.1',
                    'Config: Fortify 2FA enabled for target account (two-factor TOTP authentication enabled '
                    'on the victim account)',
                    'Network: Attacker must reach the Fortify two-factor challenge HTTP(S) flow for a target '
                    'account with TOTP enabled. Proof is replay/timing behavior in-band; there is no command '
                    'execution and no callback or OOB channel.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2020-24940',
  'slug': 'cve_2020_24940',
  'module': 'modules.cves.cve_2020_24940',
  'severity': 'Medium',
  'vuln_class': 'mass_assignment',
  'category': 'cve',
  'description': 'Eloquent mass-assignment unsafe create/update',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: laravel/framework < 6.18.34 and 7.x < 7.23.2 (NVD CVSS 3.1 = 7.5 High; this catalog rates it Medium because the demonstrated over-post has narrow real impact — see Config/Mechanism).',
                    "Mechanism: CVE-2020-24940 is Eloquent table-name stripping, NOT a generic over-post or a $guarded bypass. On Laravel < 6.18.34 / < 7.23.2, Model::fill()'s removeTableFromKey() strips a table prefix from a mass-assignment key (`users.is_admin` -> `is_admin`) BEFORE the fillable/guarded check; fixed in 6.18.34 / 7.23.2 (stops stripping + isFillable() rejects any key containing '.').",
                    'Config: The application defends a sensitive column with an APPLICATION-LAYER bare-name input filter (lab: app_filter() unsets a plain `is_admin` key before Model::create()). The exploit defeats that filter via a TABLE-QUALIFIED key `users.is_admin`: the bare-name filter does not match it, and the vulnerable framework then strips `users.` and writes is_admin=1. This is table-name stripping defeating the app filter; it is NOT an Eloquent $guarded bypass (a dotted key cannot reach a $guarded column on either version).',
                    'Network: Attacker must reach the HTTP(S) mass-assignment route that feeds request input into create()/update()/fill()/save(). Proof is a direct in-band privilege-field write (is_admin read back true), with a control showing the bare `is_admin` key is blocked. No callback or OOB channel.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2020-24941',
  'slug': 'cve_2020_24941',
  'module': 'modules.cves.cve_2020_24941',
  'severity': 'Medium',
  'vuln_class': 'mass_assignment',
  'category': 'cve',
  'description': 'Eloquent guarded JSON/nested mass-assignment bypass',
  'command_capable': False,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': False, 'exploit_required': False},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': False,
  'requires_auth': False,
  'lab_default_creds': None,
  'preconditions': ['Auth: Unauthenticated; no APP_KEY required.',
                    'Affected version: Laravel before 6.18.35 or 7.x before 7.24.0 (laravel/framework; '
                    'patched in 6.18.35 and 7.24.0)',
                    'Config: Eloquent model uses the $guarded property (NOT $fillable, which is immune and '
                    'Laravel-recommended) AND lists individual columns',
                    'Network: Attacker must reach a developer-provided HTTP(S) mass-assignment sink on a '
                    'model using guarded JSON-path attributes. Proof is direct in-band state change; no '
                    'callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: No',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2024-22836',
  'slug': 'cve_2024_22836',
  'module': 'modules.cves.cve_2024_22836',
  'severity': 'Critical',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Akaunting authenticated locale OS command-injection RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': ('admin@example.com', 'LabAdmin123!'),
  'preconditions': ['Auth: Detection can run unauthenticated as an Akaunting fingerprint/version gate; credentials enhance version/guard confirmation. Exploit requires an authenticated admin/company-manager session; no APP_KEY required.',
                    'Affected version: Akaunting <= 3.1.3.',
                    'Config: Two distinct routes are involved. (1) Injection point: POST /{company_id}/wizard/companies — Wizard\\Company::rules() validates only `logo`/`api_key` and declares NO rule for `locale`, so a poisoned `locale` is stored verbatim (the settings company-update path DOES validate `locale`; that asymmetry is the bug). (2) Detonation sink: POST /{company_id}/apps/install — the stored `locale` is concatenated unquoted into the `module:install {alias} {company_id} {locale}` shell command run via Symfony Process::fromShellCommandline(). Both routes must be reachable, a locally-present module alias is needed so the install path reaches the shell command, and a seeded Akaunting marketplace API key (setting `apps.api_key`) must be present so the apps/install marketplace workflow is reachable (the lab seeds `apps.api_key`).',
                    'Network: Detection must reach the public Akaunting login surface, and confirmation needs either a public version leak or authenticated version/guard proof. Exploitation must authenticate to Akaunting, poison company `locale` with shell metacharacters at the wizard company-update route (POST /{company_id}/wizard/companies), then trigger the marketplace/module install route (POST /{company_id}/apps/install) to detonate it. Command output is returned in-band through the application path (reflected via the ProcessFailedException Output: section); no callback or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2023-46865',
  'slug': 'cve_2023_46865',
  'module': 'modules.cves.cve_2023_46865',
  'severity': 'High',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'Crater authenticated upload-logo code-injection RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': ('admin@craterapp.com', 'crater@123'),
  'preconditions': ["Auth: Public Crater fingerprint/version detection is unauthenticated; scan() resolves the version from the unauth /api/v1/app/version route and (when it reads) reaches 'version_applicable', else 'surface_present'. Credentials are optional and only opportunistically enhance the authoritative version read; they are never required to detect. The upload-logo exploit itself requires a superadmin Sanctum bearer. No APP_KEY is required.",
                    'Affected version: Crater <= 6.0.6.',
                    'Config: /storage media path web-served + PHP-executable.',
                    'Network: Attacker must authenticate to the Crater upload/logo HTTP(S) endpoint and then request the web-served uploaded file path for proof. No separate callback, listener, or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No for fingerprint/version; Yes for upload-logo exploit',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']},
 {'cve': 'CVE-2020-5256',
  'slug': 'cve_2020_5256',
  'module': 'modules.cves.cve_2020_5256',
  'severity': 'High',
  'vuln_class': 'rce',
  'category': 'cve',
  'description': 'BookStack authenticated image-upload (is_image mime-only bypass) RCE',
  'command_capable': True,
  'auth': {'scan_required': False, 'scan_enhanced_by_auth': True, 'exploit_required': True},
  'app_key': {'required_for_exploit': False,
              'consumes': [],
              'provides_on_scan': [],
              'provides_on_exploit': [],
              'lab_default': None},
  'requires_component': None,
  'scope': 'generic',
  'pass_creds': True,
  'requires_auth': False,
  'lab_default_creds': ('admin@admin.com', 'password'),
  'preconditions': ['Auth: Public BookStack fingerprint/version detection is unauthenticated; scan() multi-signal fingerprints BookStack and best-effort reads a public version token without credentials, and never requires auth. Credentials are optional and only opportunistically enhance the authoritative version read; they are never required to detect. The image-upload exploit itself requires an authenticated session with the image-create-all permission. No APP_KEY is required.',
                    'Affected version: BookStack <= 0.25.2.',
                    'Network: Attacker must authenticate to the BookStack image-upload HTTP(S) endpoint and '
                    'then request the web-served uploaded file path for proof. No separate callback, '
                    'listener, or OOB channel is required.',
                    'Flags:',
                    '- Requires Auth (detect): No for fingerprint/version; Yes for image-upload exploit',
                    '- Command Capable: Yes',
                    '- APP_KEY Required: No']}]

_LAB_REBUILD_PRECONDITIONS = {
    "CVE-2017-14775": "Lab rebuild: `bash vuln-labs/framework/laravel/5.5.9/cve-2017-14775_remember-me-timing-rce_39013-40013/run.sh`; module `modules/cves/cve_2017_14775.py`; vuln profile is Laravel 5.5.9 on php:7.2-apache; hardened profile runs patched laravel/framework 5.5.10 (closes the timing oracle at the source) on nginx AND blocks /uploads/*.php; seeded admin `admin@lab.local` / `password`; vulnerable/hardened HTTP ports 39013/40013.",
    "CVE-2017-16894": "Lab rebuild: `bash vuln-labs/framework/laravel/5.5.x/cve-2017-16894_env-disclosure_39001-40001/run.sh`; module `modules/cves/cve_2017_16894.py`; Laravel 5.5 app whose Apache DocumentRoot stays at the correct public/ subdirectory while the vulnerable profile makes /.env web-reachable via an explicit `Alias /.env` + permissive `<Files \".env\">` block (the hardened profile denies dotfiles so GET /.env returns 403/404); php:7.2-apache; vulnerable/hardened HTTP ports 39001/40001.",
    "CVE-2018-15133": "Lab rebuild: `bash vuln-labs/framework/laravel/5.6.x/cve-2018-15133_xsrf-deserialize-rce_39002-40002/run.sh`; module `modules/cves/cve_2018_15133.py`; Laravel 5.6.29 on php:7.2-apache with a REAL random APP_KEY (php artisan key:generate) leaked via a web-reachable /.env (Alias) — the scanner recovers the real key from the leak (no --app-key needed), then forges the encrypted X-XSRF-TOKEN phpggc gadget at the decrypt sink; the X-XSRF-TOKEN decrypt route is a lab-provided app sink (the framework ships no such HTTP route). vulnerable/hardened HTTP ports 39002/40002.",
    "CVE-2020-19316": "Lab rebuild: Linux minimal app-owned command harness `bash vuln-labs/framework/laravel/11.x/cve-2020-19316_filesystem-link-cmdi_39000-40000/run.sh`; Windows command-path harness `powershell -ExecutionPolicy Bypass -File vuln-labs/framework/laravel/11.x/cve-2020-19316_filesystem-link-cmdi_39000-40000/windows/run.ps1` or `windows/run.bat`; module `modules/cves/cve_2020_19316.py`; Linux proof is a custom link-command route, while true `mklink` proof requires Docker in Windows containers mode; vulnerable/hardened HTTP ports 39000/40000. HONESTY/LIMITATION: CVE-2020-19316 is a WINDOWS-ONLY `mklink` command injection in Filesystem::link() (<5.8.17). The Linux twin is a command-injection-CLASS harness (a lab route running `ln` via shell) — NOT the real framework code path; the real CVE is not reproducible on this Linux Docker host. Faithful mklink proof needs Windows containers (the windows/ harness).",
    "CVE-2020-24940": "Lab rebuild: `bash vuln-labs/framework/laravel/6.x/cve-2020-24940_mass-assignment_39007-40007/run.sh`; module `modules/cves/cve_2020_24940.py`; the VULNERABLE profile pins Laravel 6.18.33 (last affected) and the HARDENED twin pins 6.18.34 (the genuine upstream fix) via the LARAVEL_FRAMEWORK_VERSION build-arg; same app code on both (a POST /register whose app_filter() blocks the bare `is_admin` key) so the only differentiator is the real framework version; php:7.4-apache; vulnerable/hardened HTTP ports 39007/40007. mitigate.sh applies the genuine 6.18.34 upgrade in-place (revert downgrades to 6.18.33). VERIFIED FAITHFUL: `users.is_admin` defeats the app's bare-name input filter and writes the is_admin privilege column (confirmed via the emitted SQL INSERT: `insert into users (is_admin,...) values (1,...)`), while a plain `is_admin` is correctly blocked — a genuine table-name-stripping privilege escalation matching the advisory (CWE-20). The app_filter() models a realistic naive key-name input defense (the exact context the CVE defeats), NOT a strawman. Distinct from CVE-2020-24941, where the model uses $guarded and the guard genuinely holds.",
    "CVE-2020-24941": "Lab rebuild: `bash vuln-labs/framework/laravel/6.18.34/cve-2020-24941_guarded-mass-assignment_39009-40009/run.sh`; module `modules/cves/cve_2020_24941.py`; Laravel 6.18.34 model with $guarded=['id','is_admin'] and a reachable Setting::create($request->all()) sink; php:7.4-apache; ports 39009/40009. HONESTY/LIMITATION: empirically the framework guard HOLDS on 6.18.34 — JSON-path (is_admin->x), nested (is_admin->a->b), and table-prefix (settings.is_admin) keys all leave is_admin=false. The advisory's guarded-column bypass is NOT reproducible here; the demonstrated write lands only in a NON-guarded JSON column (data->marker) = benign over-post / data-integrity, NOT privilege escalation. Reported as detection of the mass-assignment surface, not a proven guarded bypass.",
    "CVE-2020-5256": "Lab rebuild: `bash vuln-labs/apps/bookstack/0.25.2/cve-2020-5256_upload-rce_41012-42012/run.sh`; module `modules/cves/cve_2020_5256.py`; BookStack 0.25.2 image-upload sink on php:7.4-apache; seeded admin `admin@admin.com` / `password`; vulnerable/hardened HTTP ports 41012/42012.",
    "CVE-2021-28254": "Lab rebuild: `bash vuln-labs/framework/laravel/8.5.9/cve-2021-28254_pendingbroadcast-deser_39008-40008/run.sh`; module `modules/cves/cve_2021_28254.py`; minimal gadget/app-sink harness for the PendingBroadcast POP chain with an intentionally reachable unserialize sink; not a stock exact-version app; php:7.4-apache; vulnerable/hardened HTTP ports 39008/40008. NOTE: the /deserialize unserialize sink is INHERENT to this CVE — CVE-2021-28254 is a laravel/framework POP gadget chain that only fires when the APPLICATION calls unserialize() on attacker input; the framework exposes no such HTTP sink itself. The gadget is a genuine phpggc PendingBroadcast chain (real, not fabricated), so this is faithful for the bug class; the lab-supplied app sink is a necessary condition of the vulnerability, not a shortcut.",
    "CVE-2021-3129": "Lab rebuild: `bash vuln-labs/framework/laravel/8.4.x/cve-2021-3129_ignition-rce_39003-40003/run.sh`; module `modules/cves/cve_2021_3129.py`; facade/ignition vulnerable execute-solution surface with APP_DEBUG-style debug exposure; php:7.4-apache; vulnerable/hardened HTTP ports 39003/40003.",
    "CVE-2021-43617": "Lab rebuild: `bash vuln-labs/framework/laravel/8.70.2/cve-2021-43617_upload-rce_39004-40004/run.sh`; module `modules/cves/cve_2021_43617.py`; FAITHFUL: runs laravel/framework 8.70.2 (last affected) on php:8.0-apache; the /upload route validates with the real framework `mimes:jpg,jpeg,png,gif` rule, which in 8.70.2 (validateMimes -> shouldBlockPhpUpload) fails to block `.phar`; a GIF-polyglot .phar (guessExtension()=='gif') passes validation, is stored under its original name, and executes via the Apache .phar handler; an L8 App\\Http\\Middleware\\VerifyCsrfToken excepts /upload (harness route-wiring, not authentication); hardened twin adds phar to the blocklist (the real 8.70.3+ fix -> 422); vulnerable/hardened HTTP ports 39004/40004.",
    "CVE-2022-25838": "Lab rebuild: `bash vuln-labs/first-party/fortify/1.10.0/cve-2022-25838_totp-reuse_37004-38004/run.sh`; module `modules/cves/cve_2022_25838.py`; minimal Fortify-behavior harness exposes `/two-factor-secret` with seeded secret `JBSWY3DPEHPK3PXP` and `/two-factor-challenge`; not a stock Fortify session app; php:8.2-apache; vulnerable/hardened HTTP ports 37004/38004.",
    "CVE-2022-2870": "Lab rebuild: `bash vuln-labs/framework/laravel/5.1.x/cve-2022-2870_laravel51-deser-catalog_39010-40010/run.sh`; module `modules/cves/cve_2022_2870.py`; synthetic app-owned /deserialize unserialize sink for the disputed Laravel 5.1 catalog row. The vulnerable profile builds `composer create-project laravel/laravel:5.1.*`, sets LAB_HARDENED=0, and deserializes base64 request parameters. The hardened twin builds `laravel/laravel:5.5.*`, sets LAB_HARDENED=1, and uses unserialize(..., ['allowed_classes' => false]). Vulnerable/hardened HTTP ports 39010/40010.",
    "CVE-2022-2886": "Lab rebuild: `bash vuln-labs/framework/laravel/5.1.x/cve-2022-2886_laravel51-deser-catalog_39011-40011/run.sh`; module `modules/cves/cve_2022_2886.py`; synthetic app-owned /deserialize unserialize sink for the disputed Laravel 5.1 catalog row. The vulnerable profile builds `composer create-project laravel/laravel:5.1.*`, sets LAB_HARDENED=0, and deserializes base64 request parameters. The hardened twin builds `laravel/laravel:5.5.*`, sets LAB_HARDENED=1, and uses unserialize(..., ['allowed_classes' => false]). Vulnerable/hardened HTTP ports 39011/40011.",
    "CVE-2023-43661": "Lab rebuild: `bash vuln-labs/apps/cachet/2.3.18/cve-2023-43661_authed-twig-ssti-config-disclosure_41009-42009/run.sh`; module `modules/cves/cve_2023_43661.py`; Cachet 2.3.18 on php:7.1-apache with seeded admin credentials `admin@cachet.test` / `Password123`; module logs into `/auth/login`, extracts the displayed user API key from `/dashboard/user`, then uses incident template slug `poc` to leak APP_KEY; exploit chains the leaked key into Laravel 5.2 X-XSRF-TOKEN decrypt/unserialize RCE via Guzzle/RCE1 at `/auth/login`; vulnerable/hardened HTTP ports 41009/42009.",
    "CVE-2023-46865": "Lab rebuild: `bash vuln-labs/apps/crater/6.0.6/cve-2023-46865_authed-upload-logo-rce_41011-42011/run.sh`; module `modules/cves/cve_2023_46865.py`; Crater 6.0.6 upload-logo sink on php:8.1-apache; seeded superadmin `admin@craterapp.com` / `crater@123`; vulnerable/hardened HTTP ports 41011/42011.",
    "CVE-2024-21546": "Lab rebuild: unauth package harness `bash vuln-labs/third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_unauth-filemanager-upload-rce_35002-36002/run.sh` with no credentials; auth package/S-Cart lab `bash vuln-labs/third-party/unisharp-laravel-filemanager/2.8.1/cve-2024-21546_auth-filemanager-upload-rce_35001-36001/run.sh` with seeded `admin` / `admin`; Badaso app lab `bash vuln-labs/apps/badaso/2.9.10/cve-2024-21546_auth-filemanager-upload-rce_41013-42013/run.sh` with seeded `admin@badaso.test` / `Password123!`; module `modules/cves/cve_2024_21546.py`; unisharp/laravel-filemanager <2.9.1 with PHP-executing public storage; vulnerable/hardened HTTP ports 35002/36002, 35001/36001, and 41013/42013.",
    "CVE-2024-22836": "Lab rebuild: `bash vuln-labs/apps/akaunting/3.1.3/cve-2024-22836_authed-locale-cmdi-rce_41010-42010/run.sh`; module `modules/cves/cve_2024_22836.py`; Akaunting 3.1.3 marketplace/module-install path with locale command injection; seeded admin `admin@example.com` / `LabAdmin123!`; vulnerable/hardened HTTP ports 41010/42010.",
    "CVE-2024-47823": "Lab rebuild: `bash vuln-labs/first-party/livewire/2.12.5/cve-2024-47823_unauth-upload-rce_37001-38001/run.sh`; module `modules/cves/cve_2024_47823.py`; real ERPSAAS 1.x OSS app (full Filament v2 admin panel + Vite build, migrations, seeded admin) where livewire/livewire v2.12.5 is a transitive dependency of filament/filament v2.17.52, plus a small public /upload Livewire overlay component storing the original client filename under public storage as the unauthenticated CVE-2024-47823 proof surface; vulnerable/hardened HTTP ports 37001/38001.",
    "CVE-2024-48987": "Lab rebuild: `bash vuln-labs/apps/snipe-it/7.0.9/cve-2024-48987_unauth-cookie-deserialize-rce_41003-42003/run.sh`; module `modules/cves/cve_2024_48987.py`; Snipe-IT v7.0.9 on php:8.2-apache with lab APP_KEY `base64:3ilviXqB9u6DX1NRcyWGJ+sjySF+H18CPDGb3+IVwMQ=`; optional creds `admin` / `Password123!`; vulnerable/hardened HTTP ports 41003/42003.",
    "CVE-2024-52301": "Lab rebuild: `bash vuln-labs/framework/laravel/11.30.0/cve-2024-52301_env-argv-flip_39006-40006/run.sh`; module `modules/cves/cve_2024_52301.py`; Laravel env/session manipulation proof with `register_argc_argv=On` and proof URL `/?--env=local`; php:8.2-apache; vulnerable/hardened HTTP ports 39006/40006.",
    "CVE-2024-55555": "Lab rebuild: `bash vuln-labs/apps/invoice-ninja/5.10.10/cve-2024-55555_unauth-route-deserialize-rce_41002-42002/run.sh`; module `modules/cves/cve_2024_55555.py`; Invoice Ninja 5.10.10 route/hash deserialization lab with baked APP_KEY `base64:RR++yx2rJ9kdxbdh3+AmbHLDQu+Q76i++co9Y8ybbno=`; vulnerable/hardened HTTP ports 41002/42002.",
    "CVE-2024-55556": "Lab rebuild: `bash vuln-labs/apps/invoice-shelf/1.3.0/cve-2024-55556_unauth-cookie-deserialize-rce_41001-42001/run.sh`; module `modules/cves/cve_2024_55556.py`; InvoiceShelf 1.3.0 / Crater lineage on php:8.2-apache with `SESSION_DRIVER=cookie` and APP_KEY `base64:kgk/4DW1vEVy7aEvet5FPp5un6PIGe/so8H0mvoUtW0=`; vulnerable/hardened HTTP ports 41001/42001.",
    "CVE-2024-55661": "Lab rebuild: `bash vuln-labs/first-party/pulse/1.2.0/cve-2024-55661_auth-livewire-remember-rce_37003-38003/run.sh`; module `modules/cves/cve_2024_55661.py`; minimal Pulse/Livewire behavior harness for the authenticated `remember()` chain on php:8.2-apache; seeded admin `admin@example.com` / `LabAdmin123!`; vulnerable/hardened HTTP ports 37003/38003.",
    "CVE-2025-14894": "Lab rebuild: `bash vuln-labs/third-party/livewire-filemanager/1.0.4/cve-2025-14894_upload-rce_35000-36000/run.sh`; module `modules/cves/cve_2025_14894.py`; minimal Laravel package-behavior harness with `livewire-filemanager/filemanager` 1.0.4, `storage:link`, and PHP-executing public uploads; php:8.2-apache vulnerable / php:8.2-fpm nginx hardened; vulnerable/hardened HTTP ports 35000/36000.",
    "CVE-2025-27515": "Lab rebuild: `bash vuln-labs/framework/laravel/11.44.0/cve-2025-27515_wildcard-upload-rce_39005-40005/run.sh`; module `modules/cves/cve_2025_27515.py`; Laravel wildcard file/image validation bypass with web-served PHP uploads; php:8.2-apache; vulnerable/hardened HTTP ports 39005/40005.",
    "CVE-2025-49132": "Lab rebuild: `bash vuln-labs/apps/pterodactyl/1.11.10/cve-2025-49132_unauth-locale-lfi-appkey-disclosure_41008-42008/run.sh`; module `modules/cves/cve_2025_49132.py`; Pterodactyl Panel 1.11.10 with unauthenticated `/locales/locale.json` traversal into PEAR/pearcmd include behavior; vulnerable/hardened HTTP ports 41008/42008.",
    "CVE-2025-54068": "Lab rebuild: `bash vuln-labs/apps/snipe-it/8.1.18/cve-2025-54068_auth-deserialize-rce_41004-42004/run.sh`; module `modules/cves/cve_2025_54068.py`; Snipe-IT 8.1.18 with vulnerable Livewire v3 component on php:8.2-apache; seeded admin `admin` / `Password123!` (optional, for the authed fallback path); vulnerable/hardened HTTP ports 41004/42004.",
    "CVE-2026-23524": "Lab rebuild: `bash vuln-labs/first-party/reverb/1.6.3/cve-2026-23524_redis-scaling-deserialize-rce_37002-38002/run.sh`; module `modules/cves/cve_2026_23524.py`; FAITHFUL: real Laravel 11 app running the genuine vulnerable laravel/reverb 1.6.3 via `php artisan reverb:start` with REVERB_SCALING_ENABLED=true, subscribed to Redis pub/sub channel 'reverb'. The real PusherPubSubIncomingMessageHandler::handle() runs unserialize() (no allowed_classes) on each message's 'application' field; publishing {\"application\":\"<real phpggc laravel/rce9 gadget>\"} to Redis detonates in the Reverb worker (root RCE), proven out-of-band via a /reverb-oob callback collector. Hardened twin runs reverb 1.7.0 (the allowed_classes fix) -> gadget neutralized. HTTP 37002/38002; Redis 6379 vuln / 6380 hardened; php:8.2-apache + redis:7-alpine.",
}


def _inject_lab_rebuild_preconditions(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        rebuild = _LAB_REBUILD_PRECONDITIONS.get(row["cve"])
        if not rebuild:
            continue
        preconditions = [
            line
            for line in (row.get("preconditions") or [])
            if not str(line).startswith("Lab rebuild:")
        ]
        try:
            flags_index = preconditions.index("Flags:")
        except ValueError:
            flags_index = len(preconditions)
        preconditions.insert(flags_index, rebuild)
        row["preconditions"] = preconditions


# ---------------------------------------------------------------------------
# Canonical exploit-preconditions (single source for the docs/laravel_cves.csv
# "Exploit Pre-conditions" column). The verbose per-row prose above and the
# _LAB_REBUILD_* data are retained as internal reference, but the CSV/report
# field is generated from this compact, controlled-vocabulary schema so it is
# uniform and interpretable. Six fixed fields per CVE:
#
#   Auth             exploit-time auth requirement (controlled phrase)
#   APP_KEY          required | not required        (derived from structured metadata)
#   Affected         package + version range
#   Trigger          the target-side condition(s) that must hold to fire it
#   Command-capable  yes | no                       (derived from structured metadata)
#   Scenario         realism tag: realistic | config-dependent | app-sink-required
#                    | lab-unauth/prod-auth | disputed | disputed (synthetic sink)
#                    | partial
#
# APP_KEY and Command-capable are DERIVED from the structured fields (never hand
# typed) and the Auth phrase is cross-checked against auth.exploit_required, so
# this text can never silently contradict the scanner's real gating.
_CANON: Dict[str, Dict[str, str]] = {
    # ---- Critical (NVD) ----
    "CVE-2016-10074": {
        "auth": "none (unauthenticated)",
        "affected": "SwiftMailer <= 5.4.4 (as used by a PHP/Laravel mail transport)",
        "trigger": "a reachable mail-send endpoint passes attacker-controlled From/Sender/Return-Path into the SwiftMailer sendmail transport",
        "scenario": "app-sink-required",
    },
    "CVE-2021-28254": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework <= 8.5.9 (provides the PendingBroadcast __destruct POP gadget)",
        "trigger": "the application calls unserialize() on attacker-controlled input at a reachable route",
        "scenario": "app-sink-required",
    },
    "CVE-2021-3129": {
        "auth": "none (unauthenticated)",
        "affected": "facade/ignition <= 2.5.1 (shipped by Laravel < 8.4.2)",
        "trigger": "APP_ENV != production AND APP_DEBUG=true (registers POST /_ignition/execute-solution)",
        "scenario": "config-dependent",
    },
    "CVE-2021-43617": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework <= 8.70.2",
        "trigger": "upload endpoint uses the mimes:jpg,jpeg,png,gif rule and stores accepted files under their original name in a web-served, .phar-executing directory",
        "scenario": "config-dependent",
    },
    "CVE-2024-21546": {
        "auth": "none (unauthenticated) by CVE class; the S-Cart/Badaso app labs gate the upload behind auth",
        "affected": "unisharp/laravel-filemanager < 2.9.1",
        "trigger": "laravel-filemanager upload reachable and uploads stored under a PHP-executing web path (/storage or /data)",
        "scenario": "config-dependent",
    },
    "CVE-2024-22836": {
        "auth": "authenticated (admin / company-manager)",
        "affected": "Akaunting <= 3.1.3",
        "trigger": "poison company `locale` with shell metacharacters via POST /{company}/wizard/companies, then detonate via POST /{company}/apps/install",
        "scenario": "realistic",
    },
    "CVE-2024-55556": {
        "auth": "none (unauthenticated)",
        "affected": "InvoiceShelf <= 1.3.0 (patched 2.0.0); Crater <= 6.0.6",
        "trigger": "SESSION_DRIVER=cookie (encrypted session carries serialized PHP) and a valid APP_KEY is known/recovered; OOB HTTP callback used for command proof",
        "scenario": "config-dependent",
    },
    "CVE-2025-14894": {
        "auth": "none (unauthenticated)",
        "affected": "livewire-filemanager/filemanager <= 1.0.4 (third-party package, not Laravel core)",
        "trigger": "`php artisan storage:link` in place so uploads are web-served under /storage; filemanager upload reachable",
        "scenario": "config-dependent",
    },
    "CVE-2025-49132": {
        "auth": "none (unauthenticated)",
        "affected": "Pterodactyl Panel <= 1.11.10",
        "trigger": "reach /locales/locale.json traversal; command path additionally needs a reachable PEAR pearcmd.php and register_argc_argv=On",
        "scenario": "config-dependent",
    },
    "CVE-2025-54068": {
        "auth": "authenticated (staff) for the real Snipe-IT sink; unauthenticated by Livewire CVE class",
        "affected": "Livewire v3, 3.0.0-beta.1 through 3.6.3 (fixed 3.6.4)",
        "trigger": "reach a Livewire v3 component exposing an untyped/weakly-typed public property (hydration type juggling)",
        "scenario": "realistic",
    },
    "CVE-2026-23524": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/reverb <= 1.6.3 (fixed 1.7.0)",
        "trigger": "Redis horizontal scaling enabled (REVERB_SCALING_ENABLED=true) and attacker can publish a serialized message to the Redis scaling channel",
        "scenario": "config-dependent",
    },
    # ---- High (NVD) ----
    "CVE-2017-16894": {
        "auth": "none (unauthenticated)",
        "affected": "Laravel 5.5.x deploy/permissions misconfiguration (version-agnostic on the line)",
        "trigger": "web server serves .env / backup env files (docroot is the project root, or dotfiles are served)",
        "scenario": "config-dependent",
    },
    "CVE-2018-15133": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework <= 5.5.40 or 5.6.x <= 5.6.29",
        "trigger": "a known/leaked APP_KEY and a reachable endpoint that decrypts X-XSRF-TOKEN/cookie (Encrypter::decrypt -> unserialize)",
        "scenario": "config-dependent",
    },
    "CVE-2020-19316": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework < 5.8.17 (labs reproduce the command-injection class; detector is version-agnostic)",
        "trigger": "a reachable route concatenates attacker input into a shell ln -s (Linux) / mklink (Windows) call without escaping",
        "scenario": "app-sink-required",
    },
    "CVE-2020-5256": {
        "auth": "authenticated (image-create permission)",
        "affected": "BookStack <= 0.25.2",
        "trigger": "reach the authenticated image-upload endpoint; uploads web-served and PHP-executable",
        "scenario": "realistic",
    },
    "CVE-2022-25838": {
        "auth": "none (unauthenticated); victim account has TOTP enabled",
        "affected": "laravel/fortify < 1.11.1",
        "trigger": "Fortify 2FA enabled on the target account; reach the two-factor challenge flow (TOTP capture-replay)",
        "scenario": "realistic",
    },
    "CVE-2023-43661": {
        "auth": "authenticated (dashboard user able to render incident templates)",
        "affected": "Cachet <= 2.3.18",
        "trigger": "render an incident template (Twig SSTI) to disclose APP_KEY, then forge an X-XSRF-TOKEN deserialization gadget at a CSRF-verified route",
        "scenario": "realistic",
    },
    "CVE-2023-46865": {
        "auth": "authenticated (superadmin, Sanctum)",
        "affected": "Crater <= 6.0.6",
        "trigger": "reach the authenticated logo/upload endpoint; /storage media path web-served and PHP-executable",
        "scenario": "realistic",
    },
    "CVE-2024-47823": {
        "auth": "authenticated (low-privilege) per advisory; the lab exposes an unauth /upload for reproduction",
        "affected": "Livewire < 2.12.7 or v3 < 3.5.2",
        "trigger": "app stores uploads under the original client filename (not Livewire's randomized name) and the upload component is reachable",
        "scenario": "lab-unauth/prod-auth",
    },
    "CVE-2024-48987": {
        "auth": "none (unauthenticated)",
        "affected": "Snipe-IT < 7.0.10",
        "trigger": "Passport cookie serialization + EncryptCookies serialize=true (XSRF-TOKEN plaintext -> unserialize) and a valid APP_KEY to forge the cookie",
        "scenario": "config-dependent",
    },
    "CVE-2024-55555": {
        "auth": "none (unauthenticated)",
        "affected": "Invoice Ninja < 5.10.43 (validated exploitable 5.8.22-5.10.10)",
        "trigger": "reach the route/hash endpoint that accepts encrypted Laravel payloads and a valid APP_KEY to forge the payload",
        "scenario": "config-dependent",
    },
    "CVE-2024-55661": {
        "auth": "authenticated",
        "affected": "Laravel Pulse < 1.3.1",
        "trigger": "reach the Pulse dashboard and influence the remembered query key / Livewire state into the decrypt/unserialize sink",
        "scenario": "config-dependent",
    },
    # ---- Medium (NVD) ----
    "CVE-2017-14775": {
        "auth": "operator-supplied credentials or remember-me token material (no built-in default)",
        "affected": "laravel/framework < 5.5.10",
        "trigger": "app uses DB remember-me tokens and exposes a post-auth upload sink; reach /login + the upload path",
        "scenario": "partial",
    },
    # ---- High (NVD) / Medium (independent) ----
    "CVE-2020-24940": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework < 6.18.34 or 7.x < 7.23.2",
        "trigger": "a mass-assignment route with an app-layer bare-name input filter on a sensitive column; a table-qualified key (users.is_admin) defeats the filter (table-name stripping)",
        "scenario": "realistic",
    },
    "CVE-2020-24941": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework < 6.18.35 or 7.x < 7.24.0",
        "trigger": "an Eloquent model uses $guarded (not $fillable) listing individual columns; reach a mass-assignment sink",
        "scenario": "disputed",
    },
    "CVE-2024-52301": {
        "auth": "none (unauthenticated)",
        "affected": "laravel/framework < 6.20.45 / 7.30.7 / 8.83.28 / 9.52.17 / 10.48.23 / 11.31.0",
        "trigger": "PHP register_argc_argv=On and attacker can influence the query string (overrides the resolved Laravel environment)",
        "scenario": "config-dependent",
    },
    "CVE-2024-29291": {
        "auth": "none (unauthenticated)",
        "affected": "disputed record (Laravel 8-11); exposure is deploy-dependent, not version-specific",
        "trigger": "storage/logs/laravel.log (or equivalent) is web-readable AND contains cleartext DB credentials",
        "scenario": "disputed",
    },
    "CVE-2025-27515": {
        "auth": "none (unauthenticated)",
        "affected": "Laravel 10.0.0-10.48.28, 11.0.0-11.44.0, 12.0.0-12.1.0",
        "trigger": "a wildcard files.* validation rule built from the fluent File rule object (File::types([...])); reach that endpoint",
        "scenario": "config-dependent",
    },
    # ---- Low (independent) ----
    "CVE-2022-2870": {
        "auth": "none (unauthenticated)",
        "affected": "Laravel 5.1.0-5.1.46 (incidental; no framework code path or patch)",
        "trigger": "an app-provided unserialize() sink on attacker input (the lab adds a synthetic /deserialize route)",
        "scenario": "disputed (synthetic sink)",
    },
    "CVE-2022-2886": {
        "auth": "none (unauthenticated)",
        "affected": "Laravel 5.1.0-5.1.46 (per NVD/VulDB; duplicate of CVE-2022-2870)",
        "trigger": "an app-provided unserialize() sink on attacker input (the lab adds a synthetic /deserialize route)",
        "scenario": "disputed (synthetic sink)",
    },
}

_SCENARIO_VOCAB = {
    "realistic", "config-dependent", "app-sink-required",
    "lab-unauth/prod-auth", "disputed", "disputed (synthetic sink)", "partial",
}


def _canonical_preconditions(row: Dict[str, Any]) -> list[str]:
    """Build the compact canonical precondition block for one CVE row.

    APP_KEY and Command-capable are derived from the structured fields; the Auth
    phrase is cross-checked against auth.exploit_required so the doc text can
    never silently contradict the scanner's real gating.
    """
    cve = row["cve"]
    c = _CANON[cve]
    app_key_required = bool(row["app_key"].get("required_for_exploit"))
    command_capable = bool(row["command_capable"])
    exploit_auth = bool(row["auth"].get("exploit_required"))
    if c["scenario"] not in _SCENARIO_VOCAB:
        raise ValueError(f"{cve}: unknown Scenario tag {c['scenario']!r}")
    if exploit_auth and c["auth"].startswith("none"):
        raise ValueError(
            f"{cve}: auth.exploit_required=True but canonical Auth says 'none' — fix the contradiction"
        )
    return [
        f"Auth: {c['auth']}",
        f"APP_KEY: {'required' if app_key_required else 'not required'}",
        f"Affected: {c['affected']}",
        f"Trigger: {c['trigger']}",
        f"Command-capable: {'yes' if command_capable else 'no'}",
        f"Scenario: {c['scenario']}",
    ]


for _row in _CVE_ROWS:
    _row["preconditions"] = _canonical_preconditions(_row)

CVE_METADATA: Dict[str, CveMetadata] = {row["cve"]: CveMetadata(**row) for row in _CVE_ROWS}
CVE_META = {cve: meta.cve_meta_tuple for cve, meta in CVE_METADATA.items()}

LAB_DEFAULT_CREDS = {
    cve: meta.lab_default_creds
    for cve, meta in CVE_METADATA.items()
    if meta.lab_default_creds
}
LAB_DEFAULT_APP_KEYS = {
    cve: meta.app_key.get("lab_default")
    for cve, meta in CVE_METADATA.items()
    if meta.app_key.get("lab_default")
}
CVE_SCOPE: Dict[str, str] = {
    "app_ckfinder_upload": "generic",
    "app_ci_role_privesc": "app-specific",
    "app_ci_blind_sqli": "generic",
}
CVE_SCOPE.update({cve: meta.scope for cve, meta in CVE_METADATA.items() if meta.scope != "generic"})
APP_KEY_PRODUCERS = tuple(
    cve for cve, meta in CVE_METADATA.items() if meta.app_key.get("provides_on_exploit")
)


# Framework-version applicability gates. Conservative: only opt-in CVEs suppress.
AFFECTED_VERSION: Dict[str, Callable[[int, int, int], bool]] = {
    "CVE-2018-15133": lambda M, m, p: (
        (M < 5)
        or (M == 5 and m < 5)
        or (M == 5 and m == 5 and p <= 40)
        or (M == 5 and m == 6 and p <= 29)
    ),
    "CVE-2021-28254": lambda M, m, p: (M, m, p) <= (8, 5, 9),
    # CVE-2021-43617: laravel/framework upload MIME/.phar allowlist gap, affected <= 8.70.2.
    # Consumed by cve_2021_43617.scan as a FAIL-OPEN gate: a patched real host that leaks its
    # framework version (composer.lock / HTML / _debugbar) is no longer reported vulnerable.
    "CVE-2021-43617": lambda M, m, p: (M, m, p) <= (8, 70, 2),
}


def slug_for(cve: str) -> str:
    return "cve_" + cve.replace("CVE-", "").replace("-", "_")


def all_cves() -> list[str]:
    return list(CVE_METADATA)


def all_slugs() -> list[str]:
    return [meta.slug for meta in CVE_METADATA.values()]


def metadata_for(cve: str) -> CveMetadata:
    return CVE_METADATA[cve]


def metadata_dict_for(cve: str) -> Dict[str, Any]:
    return asdict(metadata_for(cve))


def module_path_for(cve: str) -> str:
    return metadata_for(cve).module


def detector_spec_for(cve: str) -> Dict[str, Any]:
    return metadata_for(cve).detector_spec()


def detector_specs_for(cves: Iterable[str]) -> list[Dict[str, Any]]:
    return [detector_spec_for(cve) for cve in cves]


def import_cve_module(cve: str):
    return importlib.import_module(module_path_for(cve))


def import_scan(cve: str):
    return getattr(import_cve_module(cve), "scan")


def import_exploit(cve: str):
    return getattr(import_cve_module(cve), "exploit")


def cves_by_criticality() -> list[str]:
    return sorted(CVE_META, key=lambda c: (SEV_RANK.get(CVE_META[c][0], 4), c))


def lab_default_creds_for(cve: str):
    return LAB_DEFAULT_CREDS.get(cve)


def lab_default_app_key_for(cve: str):
    return LAB_DEFAULT_APP_KEYS.get(cve)


def scope_of(cve: str) -> str:
    return CVE_SCOPE.get(cve, "generic")


def force_requested(options: Optional[Dict[str, Any]] = None, **kwargs: Any) -> bool:
    options = options or {}
    return bool(
        options.get("force")
        or kwargs.get("force")
        or str(options.get("exploit_policy") or "").lower() == "forced"
        or str(kwargs.get("exploit_policy") or "").lower() == "forced"
    )


def requires_component_map() -> Dict[str, str]:
    return {
        cve: meta.requires_component
        for cve, meta in CVE_METADATA.items()
        if meta.requires_component
    }


def _parse_framework_version(raw):
    if not raw or not isinstance(raw, str):
        return None
    import re
    match = re.match(r"\s*v?(\d+)\.(\d+)\.(\d+)", raw)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_suppresses(cve, framework_version_raw):
    pred = AFFECTED_VERSION.get(cve)
    if pred is None:
        return None
    ver = _parse_framework_version(framework_version_raw)
    if ver is None:
        return None
    try:
        if pred(*ver):
            return None
    except Exception:
        return None
    M, m, p = ver
    return f"{cve} suppressed: target Laravel {M}.{m}.{p} outside affected range"

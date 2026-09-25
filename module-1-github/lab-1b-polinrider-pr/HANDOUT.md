# Lab 1b — Upstream injection with PolinRider: `naymHdev/Taskmate-server`

## Time: 35 minutes
## Ecosystem: GitHub (upstream injection)
## Campaign: PolinRider (DPRK — marker `A10-010`)
## Sample: still online at [github.com/naymHdev/Taskmate-server](https://github.com/naymHdev/Taskmate-server); also mirrored at `compromised-assets/taskmate-server/`

---

## The Scenario

> In Lab 1a you sanity-checked a small, one-actor GitHub repo (`ShamratX/AI-Banking`) and found a simple base64 + `atob` + `eval` payload alongside a `.vscode/tasks.json` shell drop. That was the **entry-level version** of a much bigger operation.
>
> This lab is the deeper version. **Rowan** on your team is evaluating a repo they found while looking at task-tracker starter projects: `naymHdev/Taskmate-server`. It presents as an ordinary MERN-stack (MongoDB + Express + React + Node) side project. They've cloned it to a scratch directory and haven't merged anything.
>
> Rowan asks the same question Jordan did: *"is this safe?"* The answer is again *no*, but this time the malware is more sophisticated — encrypted stages, blockchain-based C2 lookup, and campaign markers that pin it to a specific, actively-tracked operation called **PolinRider**.
>
> Your job: prove the repo is compromised, identify how PolinRider gets executed, decode the encrypted boot stage, extract the on-chain dead-drops, and prep a disclosure for the maintainer.

⚠ Do **not** clone this repo into a directory you'd open in VS Code / Cursor. `.vscode/tasks.json` is armed. All analysis in this lab uses either a git clone in a sandbox VM **without** opening in an IDE, or `gh api` file reads.

---

## Background — What is PolinRider? (5 minutes)

![PolinRider Banner](../../images/PolinRider-banner-image-smaller.jpg)

*A short read before you touch the sample. The lab is easier once you know what you're looking at.*

### PolinRider in one paragraph

**PolinRider** is a supply-chain attack campaign publicly tracked since January, 2026, attributed by multiple researchers (OpenSourceMalware.com, Socket, ReversingLabs and others) to a DPRK-linked actor cluster. The distinctive move: instead of publishing standalone malicious packages the way its sibling campaign *Contagious Interview* does, PolinRider **injects payloads into legitimate-looking projects — forks, pull requests against real open-source projects, and template repositories developers copy from**. The compromised repo looks normal at a glance; the payload lives in files that run when a developer opens the project in an IDE or runs a build.

If you want to read all about PolinRider, I have blogged about it extensively on the [OpenSourceMalware blog](https://opensourcemalware.com/blog?q=polinrider)

### Two campaigns, side by side

You'll hear both names all workshop. They come from the same operator cluster but attack in different directions:

| | **Contagious Interview** | **PolinRider** |
|---|---|---|
| Target model | Compromise **the developer** | Compromise **the project the developer uses** |
| Delivery | Lure repo + LinkedIn recruiter offer; malicious npm typosquat | Fork/PR against real projects; template repos with malicious defaults |
| First contact | Dev clones a "take-home assignment" | Dev clones a legitimate-looking side project or template |
| Payload host | JSONKeeper, Vercel, Socket.IO C2 | On-chain (TRON / Aptos / BNB) dead-drops; obfuscated blobs in the repo itself |
| Signature files | `.vscode/tasks.json`, npm `main` entries, `.woff2` "fonts" | `.vscode/tasks.json`, `.babelrc`, `babel.config.cjs`, `postcss.config.mjs`, `.woff2` under `.vscode/` or `public/fonts/` |
| Scale (public reporting) | Hundreds of packages per year | 670+ compromised repos, 347+ attacker accounts documented |

Lab 1a's `ShamratX/AI-Banking` sits closer to the Contagious Interview shape (simple loader in a build-config JS + shell drop in `tasks.json`). This lab's `naymHdev/Taskmate-server` is a full PolinRider sample.

### How upstream injection works (mechanically)

1. **The attacker forks a legitimate open-source project** — or seeds a template-style repo that developers are likely to clone as a starter.
2. **They inject payloads into files that get executed at IDE-open or build-time** — the same primitive family as Lab 1a, but a wider set of triggers: `.vscode/tasks.json`, `.babelrc`, `babel.config.cjs`, `postcss.config.mjs`, `.prettierrc`, plus files under `.vscode/` and `public/fonts/` that get loaded by the build or IDE.
3. **The immediate payload is a small loader.** It usually XOR-decrypts a second stage that lives elsewhere in the repo, often disguised as a font file with the wrong magic bytes.
4. **The decrypted stage does not carry a hardcoded C2.** Instead it makes RPC calls to public blockchain endpoints (TRON, Aptos, BNB) and reads specific fields — a wallet address, an on-chain memo, a transfer amount — and decodes those into an IPv4 or hostname. This is called *blockchain-C2* or an *on-chain dead-drop*.
5. **The developer is compromised** the moment they either open the repo in VS Code (task fires) or run a build (config file evaluated).

The blockchain step is where the sophistication compounds. A hardcoded C2 can be blacklisted. A blockchain read is a legitimate-looking request to a public endpoint that can be updated by whoever controls the wallet, without touching the repo or any hostname a defender is watching.

### The fingerprints you'll hunt for

Public research on PolinRider has surfaced a small set of constants and identifiers that reappear across samples. When you see any of these in a repo, you're looking at PolinRider (or someone deliberately copying it):

| Marker | What it is |
|---|---|
| `rmcej` | Recurring identifier string in loader code — origin unclear, probably a build-tool artifact |
| `_$_1e42` | Constant appearing inside the obfuscated stage |
| `sfL` | Name of the permutation function used to unpack the payload |
| `2667686` | Seed passed to the `sfL` permutation |
| `global['!']` | Global-object hijack — the payload attaches itself to `globalThis['!']` |
| `A<N>-<M>` (e.g. `A9-8018-1`, `A10-010`) | Campaign identifier the payload sends back to the operator on first beacon |
| RPC calls to `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, BSC RPC endpoints | Blockchain-C2 primitive |

[`references/POLINRIDER-QUERIES.md`](../../references/POLINRIDER-QUERIES.md) has a full query set built from these markers. You'll use it in Part 1.

### Why we picked this specific sample

`naymHdev/Taskmate-server` is a real repo, still online, owned by an established developer (`naymHdev` has 111 public repos, account created 2023). This isn't a throwaway account — it's a **developer whose environment got compromised** and now silently ships PolinRider primitives into their own commits. You'll surface that pattern in Part 3 and prove it decisively in Lab 1c (Timeline forensics), which reuses the same repo.

---

## Part 1 — Search for PolinRider signatures (8 minutes)

### Step 1.1 — Set up

```bash
# Clone into a directory that will NOT be opened in an IDE.
git clone https://github.com/naymHdev/Taskmate-server ~/sandbox/taskmate-server
cd ~/sandbox/taskmate-server

# OR use the local mirror if internet is flaky:
# cd compromised-assets/taskmate-server
```

⚠ Do **not** `code .`, `cursor .`, or run any script from this directory. Read-only forensics only.

### Step 1.2 — Apply the PolinRider query set

Open [`references/POLINRIDER-QUERIES.md`](../../references/POLINRIDER-QUERIES.md) in a second window. That file is a catalog of hunting queries built from the fingerprints you read about in Background. Right now we're running them against **one repo** — but the exact same queries work against `gh search code` for all of GitHub (that's what you did briefly at the end of Lab 1a).

Run the Tier-1 exact-signature queries locally:

```bash
# Note: bash treats `!` inside double quotes as history expansion.
# Use single quotes on the outside and \x27 for the literal single quote.
rg -n 'rmcej' .
rg -n '_\$_1e42' .
rg -n 'global\[\x27!\x27\]|global\.\[\x27!\x27\]' .
rg -n '2667686' .                       # sfL seed
rg -n 'sfL\s*[=(]' .                    # sfL function definition
rg -n 'A10-010|A9-|A[0-9]+-[0-9]+' .    # campaign markers
```

**Answer as you go:**
- Which files carry which markers?
- Are the hits clustered in one or two files, or spread out?
- Any hits in files whose **names** don't feel like they should contain code (e.g. `.woff2`, `.dict`, `.png`)?

### Step 1.3 — List the known injection points

PolinRider uses a small, consistent set of injection files. Check each one:

```bash
for f in .vscode/tasks.json .vscode/*.dict .vscode/*.woff2 \
         .babelrc babel.config.cjs babel.config.js \
         postcss.config.mjs postcss.config.js .prettierrc \
         public/fonts/*.woff2; do
  [ -f "$f" ] && echo "=== $f ===" && head -60 "$f"
done
```

**Answer:** which injection points exist in this repo, and what does each contain? Contrast to Lab 1a — which primitives are the same, and which are new?

Expected in this sample: `.vscode/tasks.json`, `.vscode/spellright.dict`, and several `public/fonts/*.woff2` files that are **not actually fonts** (missing WOFF2 magic).

---

## Part 2 — Decode the boot stage (10 minutes)

The task in `.vscode/tasks.json` doesn't run the full payload directly — that would be too visible to a code reviewer. Instead it runs a small loader that opens one of the "font" files, XOR-decrypts it, and executes the result. Your job is to trace that boot stage all the way through the blockchain lookup.

### Step 2.1 — Confirm the fake fonts

Real WOFF2 files start with the magic bytes `77 4F 46 32` (`wOF2` in ASCII). If a `.woff2` starts with anything else, it's not a font.

```bash
for f in public/fonts/*.woff2 .vscode/*.woff2; do
  [ -f "$f" ] || continue
  printf '%-50s ' "$f"
  head -c 4 "$f" | xxd -p
done
```

Files that don't show `77 4F 46 32` are your candidates for encrypted stages.

### Step 2.2 — Find the encrypted blob

Some PolinRider variants XOR-encrypt into raw binary; others base64-encode the ciphertext and hide it inside a legit-looking string. Check both:

```bash
# Long base64 runs (200+ chars) — typical inline encoding
rg -n --binary '(?:[A-Za-z0-9+/]{200,}={0,2})' .

# Suspicious mid-size text files — loader stages are usually 10–500 KB
find . -type f -size +10k -size -500k -exec file {} \; | rg -i 'ascii|utf-8' | head
```

### Step 2.3 — XOR-decrypt

XOR is the simplest reversible encryption: `plaintext XOR key = ciphertext`, and `ciphertext XOR key = plaintext`. If you know the key, decrypting is one function.

PolinRider's XOR keys are usually 4–16 bytes. Common candidates to try:

- A short constant string in `.vscode/tasks.json` (e.g. the campaign marker itself)
- The first 4–16 bytes of the encrypted file (a common "key = file header prefix" pattern)
- The string `PolinRider`, `sfL`, or a small dictionary word

Save this helper as `~/sandbox/xor.py`:

```python
# xor.py — XOR decrypt with a candidate key.
# Usage: python3 xor.py <encrypted-file> <key>
import sys, itertools
data = open(sys.argv[1], 'rb').read()
key = sys.argv[2].encode()
out = bytes(b ^ k for b, k in zip(data, itertools.cycle(key)))
open(sys.argv[1] + '.dec', 'wb').write(out)
# Preview
print(out[:400])
```

Try candidate keys until the output starts to look like JavaScript (curly braces, `function`, `require`, `const`):

```bash
python3 ~/sandbox/xor.py public/fonts/fa-solid-400.woff2 A10-010
python3 ~/sandbox/xor.py public/fonts/fa-solid-400.woff2 sfL
python3 ~/sandbox/xor.py public/fonts/fa-solid-400.woff2 rmcej
```

**Success signal:** the first ~200 bytes read as recognizable JavaScript.

### Step 2.4 — Read the decrypted stage — the multi-chain dead-drop

The decrypted stage is what really does the work. Read it end-to-end. You are looking for **three RPC calls** to public blockchain endpoints:

- **TRON** — usually `https://api.trongrid.io/v1/accounts/<address>` or `/wallet/getaccount`
- **Aptos** — usually `https://fullnode.mainnet.aptoslabs.com/v1/accounts/<address>`
- **BNB Chain** — usually a BSC RPC endpoint (`https://bsc-dataseed.binance.org/`) with a specific contract read

For each, the payload reads a field — a recipient address, an on-chain memo, or a transfer amount — and **decodes it into a C2 IPv4 or hostname**. A 4-byte value hex-encoded as an address maps neatly to an IPv4; a memo can carry a hostname string.

**Answer:**
- Which three on-chain addresses does this sample query?
- Which one resolves fastest (primary) and which are fallbacks?
- What is the final C2 endpoint the payload beacons to?
- What is the campaign marker it sends on the first beacon? (Expected: `A10-010`.)

### Step 2.5 — Why blockchain-C2 exists (stop and think for 30 seconds)

You should understand *why* the attacker put this much effort into blockchain lookup:

- **Rotation without touching the repo.** The attacker updates the on-chain field (a memo, a new transaction) whenever they need to move the C2. The repo stays untouched, so takedown pressure on the repo doesn't affect delivery.
- **Legit-looking traffic.** Requests to `api.trongrid.io` or `fullnode.mainnet.aptoslabs.com` look like normal Web3-developer traffic, not obviously malicious.
- **Distributed resilience.** Blocking one chain doesn't kill the primitive — the payload tries multiple chains.
- **Attribution decoupling.** The operator's real C2 IP never appears in code committed to the repo, so a defender searching public code for the IP finds nothing.

---

## Part 3 — Timeline the compromise (6 minutes)

You know the repo is compromised. Now: **when** did the injection land, and does the account look like an attacker or a victim?

**Browser:**
- Repo: https://github.com/naymHdev/Taskmate-server
- Account: https://github.com/naymHdev

```bash
# Server-side events for the repo — unspoofable
gh api /repos/naymHdev/Taskmate-server/events --paginate \
  | jq -r '.[] | [.created_at, .type, .actor.login] | @tsv'

# Server-side events for the account
gh api /users/naymHdev/events --paginate \
  | jq -r '.[] | select(.type=="PushEvent") | [.created_at, .repo.name, .payload.size, .payload.head[0:7]] | @tsv'

# Account metadata
gh api /users/naymHdev \
  | jq '{login, created_at, public_repos, followers}'
```

**Answer:**
- When was the account created? (Expected: **2023-06-02** — a real 3+ year old developer, 111 repos.)
- When was the repo created?
- Which commit added `.vscode/tasks.json` and the fake `.woff2` files? What was the commit message?
- Is this a fresh attacker account, or a legitimate developer whose environment is compromised?

Also review local git history:

```bash
git log --stat --all
git log -S 'sfL' --all -p
git log -S 'rmcej' --all -p
git reflog show --all
```

You're looking for the specific commit(s) that added the injection primitives. In this sample, the injection lands via a single commit with a benign-sounding message; the diff includes `.vscode/*` and fake `.woff2` files that a code review would probably wave through.

> **This is where Lab 1c (Timeline forensics) picks up** — same repo, deeper investigation, cross-repo prevalence. Note anything unusual for the next lab.

---

## Part 4 — Draft the maintainer disclosure (6 minutes)

The disclosure question here is more delicate than in Lab 1a. In Lab 1a, `ShamratX` was almost certainly the attacker — you were disclosing to warn other developers. Here, `naymHdev` is likely the **victim** — a real developer whose dev environment is silently injecting PolinRider primitives into every repo they push. Your disclosure has to help them understand they're compromised, not accuse them of running malware.

### Step 4.1 — Fill the report template

Copy [`references/REPORT-TEMPLATE.md`](../../references/REPORT-TEMPLATE.md) to `~/reports/taskmate-server.md`. Fill:

- **Summary:** one paragraph — what you found, why it matters, recommended action.
- **Sample identifiers:** repo URL, injection commit SHA, affected file paths.
- **Attack surface & delivery:** how a downstream developer becomes a victim.
- **Execution:** IDE-open task + build-time config eval + blockchain-resolved C2.
- **Payload:** each stage in order.
- **IOCs:** on-chain addresses, C2 endpoint, campaign marker `A10-010`, XOR key.
- **Attribution:** PolinRider — cite the primitive markers you found.
- **Disclosure plan:** private notification to `naymHdev` first, embargoed public writeup after N days.

### Step 4.2 — Draft the private disclosure message

Save at `~/disclosures/taskmate-server-issue.md`:

```markdown
### Hi @naymHdev — I think your dev environment may be compromised

Hi @naymHdev,

I run threat intel on supply-chain attacks. I noticed a few files in your
`Taskmate-server` repo that match a known campaign called PolinRider. Before
publishing anything I want to give you a chance to check.

**Files of concern in this repo:**
- `.vscode/tasks.json` — runs on VS Code folder open, launches an encrypted loader
- `.vscode/spellright.dict` — carries a second-stage loader (not a real spellcheck dictionary)
- `public/fonts/*.woff2` — several files have the wrong magic bytes (not actually fonts)

**Campaign fingerprints I found:**
- Campaign ID `A10-010` embedded in the decrypted stage
- Function `sfL` with seed `2667686`
- On-chain dead-drops to TRON / Aptos / BNB addresses

**Why I think this may be your environment, not a targeted attack on this repo:**
The account (`naymHdev`, created 2023-06-02, 111 public repos) has a long
history of normal work. But the primitives above also appear in `<other repo
of yours>` and `<other repo of yours>` — the pattern is repo-independent, which
strongly suggests something on your local dev machine is silently injecting
these files into every project you push. Common cause: opening a compromised
"take-home assignment" repo in VS Code in the past 12 months (Contagious
Interview campaign — DPRK-attributed).

**What I'd recommend:**
1. Rotate any credentials and tokens accessible from your dev machine.
2. Audit browser and wallet extensions.
3. Reinstall your OS if practical; at minimum, uninstall and reinstall VS Code
   / Cursor, wipe `~/.vscode` and `~/.cursor`, and check `~/.zshrc`,
   `~/.bashrc`, and any shell init for unfamiliar additions.
4. Alert any downstream users who cloned any of your affected repos.

I'll wait <N> days before publishing anything. Happy to jump on a call.

— <your name / handle>
```

**Do not file this issue as part of this lab.** Draft only.

### Step 4.3 — Where this goes

- **Lab 1c** reuses `naymHdev/Taskmate-server` for a full timeline forensics pass, proving the developer-environment-compromise hypothesis with GitHub events data across the account's whole repo portfolio.
- **Lab 5c** picks up your report template and walks through the community-disclosure step (community threat DB submission).
- **The CTF finale** includes candidate repos where you'll need to distinguish "attacker" from "compromised victim" the same way.

---

## Debrief prompts

- Between Lab 1a's `ShamratX/AI-Banking` and this repo, which was harder to attribute — the attacker's own repo, or the compromised developer's repo? Which does more damage?
- Why does PolinRider layer XOR + blockchain-C2 when Lab 1a's operator used plain base64 + JSONKeeper? What does each add to survivability?
- What's the smallest signature that would catch **any** PolinRider variant — even one you've never seen before? What are you giving up to get that coverage?
- If GitHub added a UI warning "this repo contains a `.vscode/tasks.json` with `runOn: folderOpen`", how many false positives per day would that generate? Would you still ship it?

## MITRE ATT&CK mapping

- Initial Access — T1195.001 (Compromise Software Dependencies and Development Tools)
- Execution — T1059.007 (Command and Scripting Interpreter: JavaScript), T1204.002
- Defense Evasion — T1027.010 (Obfuscated Files or Information), T1027.013 (Encrypted/Encoded File), T1036.008 (Masquerade File Type)
- Command and Control — T1071.001, T1090.004 (multi-hop / blockchain-C2)

## Sources

- `open-source-malware-dad50544/public/intel-posts/taskmate-server-github-polinrider-etherhiding-v2.md`
- `open-source-malware-dad50544/public/blog-posts/polinrider-jumps-github-to-go-npm-packagist.md`
- `references/POLINRIDER-QUERIES.md`
- `references/DPRK-TAXONOMY.md`

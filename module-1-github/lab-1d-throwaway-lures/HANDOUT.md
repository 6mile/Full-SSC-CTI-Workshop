# Lab 1d — Throwaway lures: DPRK vs commodity

## Time: 25 minutes
## Ecosystem: GitHub
## Campaigns: Contagious Interview (Funtico) + commodity throwaway (TongSherbet)
## Samples:
- `compromised-assets/funtico-tech-assestment/` (DPRK-attributed LinkedIn lure)
- Remote lookup only: `TongSherbet` GitHub account (commodity popunder / Wisp proxy)

---

## The Scenario

> Two disclosures land in your inbox on the same morning:
>
> 1. **Alex** on your team fell for a LinkedIn recruiter and cloned `JuanMantica123/funtico-tech-assestment` on their work laptop. The recruiter offered $350K for a senior role. This is the sample from the DEF CON version of this workshop.
> 2. A student researcher pings you about `TongSherbet` — a GitHub account 6 months old, three repos in a 48-hour burst, all serving jsDelivr `/gh/`-hosted popunders and Wisp proxies. Not DPRK. Not stealing wallets. But definitely operating a throwaway installer campaign.
>
> Both are **throwaway account lure operations**. Your job: contrast them, and by end of lab produce a **DPRK-vs-commodity indicator table** you can hand to a defender.

---

## Part 1 — The Contagious Interview lure (10 minutes)

### Step 1.1 — Read the DEF CON T1 handout

The full walkthrough for the Funtico lure is preserved from the DEF CON workshop. Read it at:

```bash
less /Users/paulmccarty_1/projects/Workshop-Adversary-Village/task-1-linkedin-job-offer/HANDOUT.md
```

Everything in that document is still valid. The three-part story:

1. **Lure repo triage** — `JuanMantica123/funtico-tech-assestment` — commit history, `.vscode/tasks.json` autoexec, Vercel C2 liveness
2. **Second backdoor** — `errorHandler.js` with `new Function.constructor`, base64-decoded `config.js` publicKey → `api.npoint.io` dead drop
3. **Attribution** — `andrew@funtico.finance`, `latoriastrangevp14476@hotmail.com`, campaign infra pivot

Confirm the DPRK indicators:

- LinkedIn recruiter persona with too-good-to-be-true comp
- Take-home repo in Node / React / Solidity ecosystem (crypto-adjacent target)
- `.vscode/tasks.json` weaponization → **specific to Contagious Interview**
- Base64/whitespace-padded second backdoor in an innocuous-looking file
- On-chain / api.npoint.io dead-drop

### Step 1.2 — Score the recruiter persona

Apply the **reputation heuristic** (`TOOLING.md` §4) to the GitHub account `JuanMantica123`:

```bash
<reputation-tool> github-user JuanMantica123
```

**Answer:**
- Account age, followers, commit history?
- Are the other repos on this account also lures, or is this a stolen/rented account with legitimate history?

---

## Part 2 — The TongSherbet commodity operator (10 minutes)

### Step 2.1 — Enumerate the account

**Browser:** https://github.com/TongSherbet

```bash
gh api /users/TongSherbet > tongsherbet.json
jq '{login, created_at, bio, followers, public_repos}' tongsherbet.json

gh api /users/TongSherbet/repos --paginate \
  | jq -r '.[] | [.created_at, .name, .stargazers_count, .description] | @tsv'

gh api /users/TongSherbet/events --paginate \
  | jq -r '.[] | [.created_at, .type, .repo.name] | @tsv' | sort
```

**Answer:**
- Account creation date? (Expected: ~6 months old.)
- Bio contains anything giveaway? (Expected: something like "CEO @ Amazon" — a fake corporate signal.)
- How many repos in the first 48 hours after creation vs total?

### Step 2.2 — Read one of the payloads

Pick one of TongSherbet's repos (whichever hosts the popunder / Wisp proxy). Read the payload — commodity JS, non-obfuscated or lightly minified.

**Contrast with Funtico:**
- Obfuscation depth: commodity is shallow; Funtico is layered
- Delivery: commodity uses jsDelivr `/gh/` mutable-payload; Funtico uses direct `.vscode/tasks.json`
- Target: commodity monetizes ad views; Funtico steals wallets/creds

### Step 2.3 — Timeline both accounts

Apply the **GitHub events API extractor** (`TOOLING.md` §2) to each. Both should show throwaway patterns; the *shape* differs.

---

## Part 3 — Produce the DPRK-vs-commodity indicator table (5 minutes)

Fill this in:

| Indicator | DPRK / Contagious Interview | Commodity / TongSherbet |
|---|---|---|
| Account age at attack | 3 days–3 months | 3–6 months |
| Bio content | Blank or plausible dev | Grandiose (fake CEO, fake company) |
| Repo count in burst | 1–3 (lure + covers) | 3–10 (many mutable payloads) |
| Payload delivery | `.vscode/tasks.json`, `.woff2`, `.babelrc` | jsDelivr `/gh/`, plain script tag |
| Obfuscation | Multi-layer, campaign-marked | Shallow to none |
| C2 shape | Socket.IO, JSONKeeper, blockchain-C2 | HTTP GET / plain webhook |
| Monetization | Wallet drain, cred theft, RAT | Ad revenue, popunder, proxy resale |
| Attribution signal | Campaign ID, JSONKeeper URL | Payload host, wallet paid-to |

---

## Debrief prompts

- The two operations share the "throwaway account" primitive but differ in every other axis. What does that tell you about the DPRK operators' operational discipline vs commodity crews?
- Which of the two would a downstream registry / marketplace filter catch first — and why?
- If you were writing a detection rule, would you rather catch DPRK or commodity? What's the false-positive cost of each?

## MITRE ATT&CK mapping

- Initial Access — T1566.001 (Spearphishing Attachment — the lure repo)
- Reconnaissance — T1591.004
- Resource Development — T1585.003, T1608.006 (SEO Poisoning — commodity uses this)

## Sources

- `open-source-malware-dad50544/public/intel-posts/tongsherbet-github-popunder-injection-timeline.md`
- `/Users/paulmccarty_1/projects/Workshop-Adversary-Village/task-1-linkedin-job-offer/HANDOUT.md` (DEF CON T1)
- `compromised-assets/funtico-tech-assestment/`

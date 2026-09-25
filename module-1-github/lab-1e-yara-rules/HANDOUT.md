# Lab 1e — Creating YARA rules from what we've learned this section

## Time: 18 minutes
## Ecosystem: GitHub
## Skill: turn primitives you extracted in Labs 1a–1d into runnable YARA rules

---

## Why we do this

You just spent 80 minutes analyzing GitHub-hosted samples and extracting primitives — `atob + fetch + eval` chains, `.vscode/tasks.json` with hidden-presentation folderOpen tasks, PolinRider markers, throwaway account shapes. The knowledge in your head is not scalable. **The same knowledge as a YARA rule is.** A rule you write here can run against 100k repos overnight and surface every lookalike.

YARA is the industry-standard signature format for exactly this. It's pattern matching + boolean logic in a simple DSL — you'll write your first rule in the next 60 seconds.

**Runner:** we use **YARA-X** (VirusTotal's Rust reimplementation) — see `references/TOOLING.md` §13 for install. Syntax is identical to classic YARA.

---

## Part 1 — YARA in one page (4 minutes)

The minimum viable rule:

```yara
rule Hello_Yara
{
    strings:
        $a = "hello world"
    condition:
        $a
}
```

Save that as `hello.yar`, then:

```bash
echo "hello world" > /tmp/greeting.txt
yr scan hello.yar /tmp/greeting.txt
# Expected: Hello_Yara /tmp/greeting.txt
```

Three sections attendees actually use:

| Section | What it does |
|---|---|
| `meta:` | Free-form metadata — author, description, references, severity |
| `strings:` | Patterns to search. `$name = "text"` for literals, `$name = /regex/` for regex, `$name = { hex bytes }` for binary |
| `condition:` | Boolean expression. `$a and $b`, `2 of them`, `#name > 3` (count), `$magic at 0` (offset) |

String modifiers you'll use today:

- `ascii` — match ASCII (default)
- `nocase` — case-insensitive
- `wide` — match UTF-16LE (common in Windows / .NET)

Common condition patterns:

```yara
condition: all of them            // every string matches
condition: any of them            // one or more
condition: 2 of ($a, $b, $c)      // any 2 of the named list
condition: #a > 3                 // string $a matches more than 3 times
condition: filesize < 200KB and $a
condition: $magic at 0            // string $magic appears at byte offset 0
```

That's 80% of what you need for this lab.

---

## Part 2 — Write four rules from Lab 1a–1d primitives (8 minutes)

For each rule below, **write it from scratch in a file called `module1.yar`** based on your Lab notes. Then compare to the reference in [`references/YARA-STARTER-RULES.md`](../../references/YARA-STARTER-RULES.md).

### Rule 1 — `SupplyChain_JS_AtobFetchEval_Chain`

From Lab 1a `frontend/tailwind.config.js`. Triggers on any JS file combining three primitives: `atob("<base64>")`, `fetch(`, `eval(`.

- What size ceiling makes sense? (Real Tailwind configs are small.)
- Should the base64 pattern require a minimum length?
- Should you require **all three** primitives, or **any two**?

Draft, then check `YARA-STARTER-RULES.md` §GitHub.

### Rule 2 — `VSCode_TasksJson_FolderOpen_Hidden`

From Lab 1a and Lab 1d (Funtico). Triggers when a `.vscode/tasks.json` has `runOn: folderOpen` **and** its `presentation` block hides output.

- What are the distinctive JSON keys?
- Are you willing to false-positive on legitimate tasks that use `runOn: folderOpen` but *don't* hide their output? Or the reverse?
- Should you require `"type": "shell"`?

### Rule 3 — `Malware_PolinRider_Markers`

From Lab 1b (`naymHdev/Taskmate-server`). Triggers on any file that carries **two or more** PolinRider fingerprints: `rmcej`, `_$_1e42`, `sfL`, seed `2667686`, `global['!']`, `A<N>-<M>` campaign IDs.

- These constants are essentially unique to PolinRider. Precision will be very high.
- Regex or literal for `global['!']`? (Careful: `!` inside a shell string caused you grief earlier — YARA is fine with it.)

### Rule 4 — `GitHub_JSONKeeper_DeadDrop`

From Lab 1a. Triggers on any file mentioning `jsonkeeper.com/b/` — the paste-bin URL Contagious Interview reuses across samples.

- Simple literal or regex?
- `nocase`?

---

## Part 3 — Test the rules against samples (3 minutes)

Point YARA-X at `compromised-assets/` and see what hits:

```bash
yr scan module1.yar /Users/paulmccarty_1/projects/Canberra-BSides-Workshop/compromised-assets/
```

**Answer:**
- Which rules fired against `funtico-tech-assestment/`?
- Which fired against `tailwind-minanimated/`?
- Any false positives on files that should be benign (README, LICENSE)?
- If you have a benign npm project checked out locally, run the same rules against it — how noisy are they?

---

## Part 4 — What YARA is good for, and what it isn't (3 minutes)

Read this before Lab 2e. You just wrote rules and saw them work. That's real value — but be honest about the shape of that value. YARA can be useful as one layer, especially for known malware families, but it has some fundamental weaknesses for detecting malicious NPM packages or GitHub repositories.

**Three fundamental weaknesses**

1. **It mostly detects artifacts, not malicious behavior.** YARA is strongest when you already know what byte/string/code patterns to look for. But malicious packages are often identifiable by *what the code does*: reading environment variables, accessing `~/.npmrc`, spawning a child process, making an outbound request, modifying another package, etc. Each individual operation can be completely legitimate. The maliciousness emerges from the sequence and context, which is difficult to express reliably with YARA.

2. **Tiny mutations can defeat signatures.** JavaScript is exceptionally easy to mutate while preserving identical behavior. An attacker can rename variables, change strings to Base64/hex/Unicode, split strings, switch `require()` to dynamic `import()`, construct property names dynamically, change formatting, or wrap code in another function. A rule looking for something like `child_process + exec + a known URL` may disappear after a trivial rewrite. Especially relevant for rapidly changing NPM campaigns where payloads are regenerated frequently.

3. **Making YARA broad enough creates enormous false-positive problems.** Suppose you want to detect a package that reads credentials and sends them over HTTP. You could search for combinations such as `process.env`, `axios`, `fetch`, `http.request`, `child_process`, `os.homedir()`, or `.npmrc`. Unfortunately, thousands of legitimate packages contain exactly those constructs. Tightening the rule reduces false positives but makes evasion easier; broadening it catches more malware but makes results operationally unusable.

**What else YARA doesn't understand**

- **JavaScript semantics or package context.** It doesn't inherently know that code executes from `postinstall`, that a dependency was newly introduced, that a package suddenly added an install hook in version 1.4.7, or that an NPM package claiming to be a React utility has no plausible reason to enumerate cryptocurrency wallets.
- **Multi-stage attacks.** A package can contain a perfectly innocuous-looking loader that downloads or retrieves the actual payload at runtime. Static YARA scanning sees only the loader. The interesting behavior may exist behind an API, dead-drop, blockchain transaction, GitHub gist, dynamically imported module, or encrypted blob.
- **Repository-level signals.** Suspicious commit provenance, a compromised maintainer, an unexpected workflow modification, a malicious PR, dependency substitution, or code inserted into a generated/minified file — often much more informative than whether any individual file matches a YARA signature.

**The detection hierarchy, roughly**

```
YARA                         →  useful IOC / signature layer
AST / static semantic        →  understands what JavaScript is doing
package / repository context →  understands whether that behavior makes sense
behavioral / sandboxing      →  observes what actually happens
provenance / change analysis →  identifies why this version/commit is different
```

**Bottom line for PolinRider-style hunting**

For the campaigns we've been investigating — especially PolinRider-style appended JavaScript — YARA can actually be very effective for retrospective hunting because markers such as campaign identifiers or distinctive code fragments make strong signatures. The danger is confusing *"YARA finds today's PolinRider specimens extremely well"* with *"YARA is a good general malicious-package detector."* Those are very different claims.

Keep this in mind when you build the next rule packs (Labs 2e, 3c, 4c). YARA is one layer of a stack. Every workshop primitive that fits its shape belongs in a rule. Every one that doesn't — timeline anomalies, cross-repo prevalence, dependency-injection semantics — needs a different tool. TOOLING.md §8 (`gh-fake-analyzer`), §9 (`commit-audit`), and §1b (`Packj` dynamic mode) are where those live.

---

## Deliverable

- `module1.yar` file with your four rules
- One paragraph in your notes: for each rule, what its precision/recall trade-off is on the samples you tested against

You'll add more rules in Labs 2e, 3c, 4c — same skill, new primitives. By end of day you'll have a rule pack you can take back to work Monday.

## Debrief prompts

- Which rule was hardest to write? Was that because the primitive is genuinely subtle, or because you weren't sure how to express it in YARA?
- If GitHub added YARA-rule support to their code search UI, which of your four would you deploy first?
- What primitive from Labs 1a–1d **can't** be captured by YARA well? (Hint: think about relational signals like "committer identity doesn't match a real GitHub user" — that requires the events API, not a file scan.)

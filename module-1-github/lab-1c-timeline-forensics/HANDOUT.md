# Lab 1c — Timeline forensics: proving developer-environment compromise on `naymHdev/Taskmate-server`

## Time: 30 minutes
## Ecosystem: GitHub
## Campaign: PolinRider (developer-environment compromise, cross-repo spread)
## Sample: still online — analyzed live via `gh api` (same repo as Lab 1b)

---

## The Scenario

> You analyzed `naymHdev/Taskmate-server` in Lab 1b and found PolinRider payloads in `.vscode/tasks.json`, `.vscode/spellright.dict`, and the `public/fonts/*.woff2` files. Good.
>
> Now the harder question: **who committed them, and when, and did the account owner know?**
>
> The account `naymHdev` is not a throwaway. It's **three years old**, has **111 repos**, and shows a normal MERN-stack developer's activity pattern. If a fresh attacker account had pushed the injection, this would be easy. But there are **zero PRs** on this repo. Every malicious commit is signed with the real developer's email.
>
> Your job: figure out whether `naymHdev` is complicit, compromised, or a victim of a compromise that runs through **their local dev environment** — and prove it from unspoofable evidence.

This is the pattern hunters call **developer-environment compromise**: a legit dev's laptop is infected (typically from opening a lure repo earlier), and their infected dev tools inject PolinRider primitives into every future commit they make. Detection lives in the timeline.

⚠ The repo is live. Anything you observe may look different by workshop day. That's authentic hunting.

---

## Part 1 — Establish the account is real (7 minutes)

If `naymHdev` is a throwaway, this is easy. If they're a real dev, everything downstream matters more.

### Step 1.1 — Account metadata

**Browser:** https://github.com/naymHdev

```bash
mkdir -p ~/timeline/naymHdev && cd ~/timeline/naymHdev

gh api /users/naymHdev --jq '{login, created_at, public_repos, followers, following, updated_at, bio, company, location}' > user.json
# equivalent:
# gh api /users/naymHdev | jq '{login, created_at, public_repos, followers, following, updated_at, bio, company, location}' > user.json
cat user.json

# Portfolio sample
gh api /users/naymHdev/repos --paginate --jq '.[] | [.created_at, .name, .language // "-", .description // "-"] | @tsv' > repos.tsv
# equivalent (needs -r for @tsv raw output):
# gh api /users/naymHdev/repos --paginate | jq -r '.[] | [.created_at, .name, .language // "-", .description // "-"] | @tsv' > repos.tsv
wc -l repos.tsv
head -10 repos.tsv
tail -10 repos.tsv
```

**Answer:**
- Account creation date? (Expected: **2023-06-02**. Three-plus years old.)
- Public repos? (Expected: **~111**.)
- Recent update time?
- Look at the tail of the portfolio — is this the shape of a real dev (varied languages, side projects, tutorial follow-alongs) or a throwaway (single-purpose, all created the same day)?

Now the throwaway checklist inverted: **which of these say "real developer"?**

- Repo names include tutorial-style projects (`dsa-practice`, `custom-hooks-forms`)
- A profile repo (`naymHdev/naymHdev`) exists — throwaways rarely bother
- Commit tempo shows work across months, not a single burst
- Followers > 0 (real relationships)

### Step 1.2 — Real-dev commit tempo

```bash
gh api /users/naymHdev/events --paginate 2>/dev/null > user-events.json
jq -r '.[] | select(.type=="PushEvent") | [.created_at, .repo.name, .payload.size, .payload.head[0:7]] | @tsv' user-events.json | sort > push-events.tsv
wc -l push-events.tsv
head -20 push-events.tsv
```

Look at push cadence per day-of-week / hour-of-day. A working-hours pattern is a real-dev signal.

```bash
jq -r '.[] | select(.type=="PushEvent") | .created_at[11:13]' user-events.json | sort | uniq -c
```

**Conclusion:** naymHdev is a real developer. That means the malicious content in `Taskmate-server` did **not** come from a throwaway PR. Different threat model.

---

## Part 2 — Locate the injection commit (8 minutes)

If there's no PR, the injection had to arrive via a push from `naymHdev`'s own credentials. The question becomes: **when did the malicious files first appear, and what was the commit message?**

### Step 2.1 — Commit-history archaeology

**Browser:** https://github.com/naymHdev/Taskmate-server/commits/main

```bash
gh api /repos/naymHdev/Taskmate-server/commits --paginate 2>/dev/null \
  | jq -r '.[] | [.commit.author.date, .commit.author.email, (.author.login // "NULL"), .sha[0:7], .commit.message] | @tsv' \
  > commits.tsv
cat commits.tsv
```

**Answer:**
- How many total commits? (Expected: **9**.)
- Do they all share one email? (Expected: **`naym100m@gmail.com`**, mapping to GH login `naymHdev`.)
- What is the commit date range?

### Step 2.2 — Which commit added the PolinRider primitives?

```bash
# The specific commit that added .vscode/tasks.json
gh api "/repos/naymHdev/Taskmate-server/commits?path=.vscode/tasks.json" --paginate 2>/dev/null \
  | jq -r '.[] | [.commit.author.date, .commit.author.email, .sha[0:7], .commit.message] | @tsv'

# The commit that added .vscode/spellright.dict
gh api "/repos/naymHdev/Taskmate-server/commits?path=.vscode/spellright.dict" --paginate 2>/dev/null \
  | jq -r '.[] | [.commit.author.date, .commit.author.email, .sha[0:7], .commit.message] | @tsv'

# One of the .woff2 files
gh api "/repos/naymHdev/Taskmate-server/commits?path=public/fonts/fa-solid-400.woff2" --paginate 2>/dev/null \
  | jq -r '.[] | [.commit.author.date, .commit.author.email, .sha[0:7], .commit.message] | @tsv'
```

**Answer:**
- What is the SHA of the injection commit? (Expected: **`60a2d4e`**, dated **2024-03-30T17:30:45Z**.)
- What was the commit message? (Expected: **" create a readme file"** — note the leading space, and note that it does **not** describe adding a `.vscode/` directory or fake fonts.)
- **This is the smoking gun.** The message claims one thing; the diff does another. Real devs sometimes bundle changes, but they generally don't ship IDE config + 7 fake woff2 fonts + a spellright dictionary in a commit called "create a readme file."

### Step 2.3 — Look at the diff for `60a2d4e`

```bash
# Browser: https://github.com/naymHdev/Taskmate-server/commit/60a2d4e
gh api /repos/naymHdev/Taskmate-server/commits/60a2d4e --jq '.files[] | {filename, status, additions, deletions}' 2>/dev/null
# equivalent:
# gh api /repos/naymHdev/Taskmate-server/commits/60a2d4e 2>/dev/null | jq '.files[] | {filename, status, additions, deletions}'
```

**Answer:**
- How many files did this "create a readme file" commit touch?
- What percentage of them are actually the README versus PolinRider primitives?
- Note the file paths — anything under `.vscode/` and `public/fonts/*.woff2` is the injection.

---

## Part 3 — Prove it's a developer-environment compromise (10 minutes)

If **only** `Taskmate-server` had the injection, this could be a targeted compromise of that one project. If **multiple** naymHdev repos carry the same primitive, then their **local environment is compromised** and re-injects on every new repo they create.

### Step 3.1 — Check other naymHdev repos for the same primitive

**Browser:** https://github.com/naymHdev?tab=repositories

```bash
# Iterate through the developer's portfolio looking for .vscode/tasks.json + spellright.dict
for repo in $(gh api /users/naymHdev/repos --paginate --jq '.[].name'); do
# equivalent: for repo in $(gh api /users/naymHdev/repos --paginate | jq -r '.[].name'); do
  primitives=$(gh api "/repos/naymHdev/$repo/git/trees/main?recursive=1" 2>/dev/null \
    | jq -r '.tree[]?.path' 2>/dev/null \
    | grep -Ec '(\.vscode/(tasks\.json|spellright\.dict)|public/fonts/.*\.woff2)$' 2>/dev/null || echo 0)
  if [ "$primitives" -gt 0 ]; then
    echo "$repo: $primitives primitive files"
  fi
done
```

**Answer:** which repos have the primitives? (Expected: **`Taskmate-server`, `dsa-practice`, `naymHdev/naymHdev` (the profile repo)** at minimum. There will be more.)

### Step 3.2 — Correlate injection dates

For each infected repo, find the injection commit date:

```bash
for repo in Taskmate-server dsa-practice naymHdev; do
  echo "=== $repo ==="
  gh api "/repos/naymHdev/$repo/commits?path=.vscode/tasks.json" --paginate 2>/dev/null \
    | jq -r '.[-1] | [.commit.author.date, .sha[0:7], .commit.message] | @tsv'
done
```

**Answer:**
- Do the injection dates cluster? (If they span multiple months but every affected repo has the primitive from **its first meaningful commit**, that's the tell — the compromise is in the local dev environment, not the repo.)
- What was naymHdev's environment doing that would insert these files silently? (Hint: read the Lab 1b decoded payload — one primitive of PolinRider is to modify the local `~/.vscode/` and `~/.local/share/*` defaults so that VS Code auto-creates the malicious files in every new project.)

### Step 3.3 — What the developer probably doesn't know

- Every repo they've created since the compromise date carries the PolinRider primitives
- Every downstream user who cloned any of these repos and opened them in VS Code is at risk
- Fixing `Taskmate-server` alone doesn't fix `naymHdev`'s laptop
- naymHdev may not know they're infected

This is why disclosure matters more here than in a throwaway-account case.

---

## Part 4 — Build the timeline artifact + disclosure plan (5 minutes)

Save your reconciled timeline:

| Time (UTC) | Server event / API row | Local commit SHA | Author email | Files touched | Signal |
|---|---|---|---|---|---|
| `2023-06-02T18:00:10Z` | Account created | — | — | — | real dev, 3+ years old |
| `2024-03-27T12:58:44Z` | First commit to Taskmate-server | `5931491` | `naym100m@gmail.com` | index.js | legit dev work |
| `2024-03-30T17:30:45Z` | Injection commit | `60a2d4e` | `naym100m@gmail.com` | .vscode/tasks.json, .vscode/spellright.dict, public/fonts/*.woff2 (7), README.md | **message says "create a readme file" — content is PolinRider** |
| `<injection dates from other repos>` | Cross-repo spread | (various SHAs) | `naym100m@gmail.com` | .vscode/*, public/fonts/*.woff2 | **environment compromise, not per-repo** |

Save as `~/timeline/naymHdev/TIMELINE.md`. Include your `commits.tsv`, `push-events.tsv`, `user.json`, plus the primitive-scan output from Step 3.1.

### Disclosure implications

In your Lab 5c disclosure draft, this is not "we found a bad repo, please revert." It's:

> *"Your account appears to have a compromised local development environment. Multiple of your repositories (list below) contain PolinRider supply-chain injection primitives that were committed with your credentials but whose content does not match the commit messages. Please rotate credentials, reinstall your OS, and audit any downstream users of the affected repos."*

Different message. Different threat model. Same evidence chain.

---

## Debrief prompts

- What can a threat actor *not* hide from the events API, even when they've compromised a real dev's environment?
- If naymHdev's account is technically the pusher, is naymHdev "guilty" of shipping malware? What's the ethical framing when a dev is a victim?
- If you were on a red team simulating this, what's the minimum you'd need to compromise to reproduce this cross-repo injection?
- How would you write a detection for "any commit whose message is `create a readme file` but which touches more than one non-README file"?

## MITRE ATT&CK mapping

- Initial Access — T1195.001 (Compromise Software Dependencies and Development Tools)
- Persistence — T1554 (Compromise Client Software Binary) — via developer environment
- Defense Evasion — T1036 (Masquerading) — commit message vs. content divergence

## Sources

- `open-source-malware-dad50544/public/intel-posts/taskmate-server-github-polinrider-etherhiding-v2.md` (Lab 1b's primary source, reused here for context on the payload chain)
- `references/TIMELINE-FORENSICS-CHEATSHEET.md`
- `references/POLINRIDER-QUERIES.md`

## Instructor note — if the target changes

If naymHdev cleans up any of the affected repos before the workshop, the timeline still works — GitHub's events API and commits API both preserve the historical record even after files are deleted. If the account itself goes offline, fall back to the intel post's captured evidence or swap in a comparable PolinRider case (`codedthemes/berry-free-react-admin-template` is another documented developer-environment compromise; check availability the week of).

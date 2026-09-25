# Setup — before you arrive

Follow these steps on a **fresh VM, container, or throwaway user account**. Do not run this workshop's samples on a machine that touches production credentials.

## 1. Base OS

Ubuntu 22.04 or 24.04 LTS in a VM works well. macOS-in-VM, Fedora, and Debian all fine. Windows via WSL2 is acceptable if you're comfortable with it.

## 2. Baseline CLI

Read [`references/BASELINE-CLI.md`](references/BASELINE-CLI.md) before the workshop. It walks through each tool below — what it does, why the workshop uses it, and typical commands. Below is the install-only checklist.


```bash
sudo apt-get update
sudo apt-get install -y git curl jq unzip zip file build-essential python3 python3-pip nodejs npm ripgrep fd-find

# GitHub CLI
type -p curl >/dev/null || sudo apt-get install -y curl
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update && sudo apt-get install -y gh

gh auth login   # follow the prompts
```

macOS with Homebrew:

```bash
brew install git gh jq curl python@3.13 node ripgrep fd file yara-x
```

Ubuntu — add YARA-X via cargo (Ubuntu doesn't ship it):

```bash
cargo install yara-x-cli
```

## 3. Open-source hunting tools

Install the tools listed in [`references/TOOLING.md`](references/TOOLING.md). That file is the single source of truth for tool selection — every lab handout points at it. If a tool changes, only `TOOLING.md` needs to be updated.

## 4. Clone the workshop

```bash
git clone <workshop-repo-url> ~/canberra-bsides
cd ~/canberra-bsides
./setup-verify.sh
```

`setup-verify.sh` checks every dependency the labs need and reports missing pieces.

## 5. Sandbox hygiene

- Snapshot your VM **now**, before any lab. Every module ends with an implicit "revert if you're worried."
- Set the VM's network to **NAT with host-only side-channel** if possible. Some labs need internet (`gh api`, VirusTotal, Shodan); most sample execution should be blocked.
- If you use a firewall (`ufw`, `pf`), block outbound to the C2 IPs listed in `references/IOC-master-table.md` before running any sample.

## 6. Accounts

- **GitHub** with `gh` authenticated (any account is fine — no elevated permissions needed).
- **(Optional)** A community threat DB account for Module 5's submission lab. `references/TOOLING.md` names the DB and how to sign up.

## 7. Verify

```bash
./setup-verify.sh
```

If everything passes, you're ready. See you in Canberra.

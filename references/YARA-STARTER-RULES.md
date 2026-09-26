# YARA starter rules — a workshop cheat sheet

Copy/paste starter rules for the primitives attendees encounter across Modules 1–4. Each rule was drafted from IOCs the labs teach directly. Tune the strings and conditions to your own corpus before running at scale.

**Runner:** rules assume [YARA-X](https://github.com/VirusTotal/yara-x) (or classic `yara`). See `TOOLING.md` §13 for install.

**Testing convention:** every rule in this file has been sanity-tested against `compromised-assets/` and a small clean-repo control set. False-positive rates are noted per rule.

---

## GitHub / lure-repo primitives

### `SupplyChain_JS_AtobFetchEval_Chain` — Lab 1a

Catches `atob("<base64>")` followed by `fetch(...)` and `eval(...)` in the same JS file. Broad; will match legitimate uses of any two of the three primitives, but the combination of all three inside a single small config-file is a strong signal.

```yara
rule SupplyChain_JS_AtobFetchEval_Chain
{
    meta:
        author       = "BSides Canberra Workshop"
        description  = "atob-decoded URL fetched then eval'd — Contagious Interview family"
        reference    = "Lab 1a — ShamratX/AI-Banking"
        severity     = "high"
    strings:
        $atob_b64 = /atob\s*\(\s*["'][A-Za-z0-9+\/=]{20,}["']\s*\)/
        $fetch    = "fetch(" ascii
        $eval     = /eval\s*\(/
    condition:
        filesize < 200KB and all of them
}
```

### `VSCode_TasksJson_FolderOpen_Hidden` — Lab 1a, 1d, 4b

Fires on any `.vscode/tasks.json` whose task auto-runs on `folderOpen` **and** hides its terminal (`reveal: never` or a similar suppression). Low false-positive rate — legitimate tasks rarely combine both.

```yara
rule VSCode_TasksJson_FolderOpen_Hidden
{
    meta:
        description = ".vscode/tasks.json auto-runs on folder open with hidden presentation"
        reference   = "Lab 1a — ShamratX/AI-Banking, Lab 1d — Funtico"
    strings:
        $version      = "\"version\": \"2.0.0\"" ascii
        $folder_open  = "\"runOn\": \"folderOpen\"" ascii
        $reveal_never = "\"reveal\": \"never\"" ascii
        $echo_false   = "\"echo\": false" ascii
        $close_true   = "\"close\": true" ascii
    condition:
        $version and $folder_open and 2 of ($reveal_never, $echo_false, $close_true)
}
```

### `Malware_PolinRider_Markers` — Lab 1b, Lab 1c, Lab 2a

Any two PolinRider fingerprints in a single file. Very high precision — these constants are essentially unique to the campaign.

```yara
rule Malware_PolinRider_Markers
{
    meta:
        description = "PolinRider campaign markers"
        reference   = "Lab 1b — naymHdev/Taskmate-server; Lab 2a — tailwind-mainanimation"
    strings:
        $rmcej   = "rmcej" ascii
        $sig1e42 = "_$_1e42" ascii
        $sfL_fn  = /sfL\s*[=(]/ ascii
        $seed    = "2667686" ascii
        $global  = /global\[['\x22]!['\x22]\]/ ascii
        $camp_id = /A\d{1,3}-\d{2,4}/ ascii
    condition:
        2 of ($rmcej, $sig1e42, $sfL_fn, $seed, $global) or
        ($camp_id and 1 of ($rmcej, $sig1e42, $sfL_fn, $seed, $global))
}
```

### `GitHub_JSONKeeper_DeadDrop` — Lab 1a, Lab 2b

`jsonkeeper.com/b/<id>` as a payload host. Contagious Interview reuses JSONKeeper across dozens of samples.

```yara
rule GitHub_JSONKeeper_DeadDrop
{
    meta:
        description = "JSONKeeper URL used as a payload dead-drop"
        reference   = "Lab 1a; Lab 2b — get-power"
    strings:
        $host = "jsonkeeper.com/b/" ascii nocase
    condition:
        $host
}
```

---

## NPM primitives

### `NPM_MainEntry_WhitespacePad_Loader` — Lab 2a

Detects long whitespace runs inside a JS file — the "off-screen loader" trick.

```yara
rule NPM_MainEntry_WhitespacePad_Loader
{
    meta:
        description = "Long whitespace-padded line inside main-entry JS — obfuscation tell"
        reference   = "Lab 2a — tailwind-mainanimation"
    strings:
        $long_pad = /[ \t]{400,}[^\s]/ ascii
    condition:
        filesize < 500KB and #long_pad > 0
}
```

### `NPM_Postinstall_CurlPipeShell` — Lab 2a Part 1, Lab 2d

Catches `package.json` postinstall hooks that shell out to `curl | sh`, `wget | sh`, or `curl | cmd`. Applied to `package.json` files only.

```yara
rule NPM_Postinstall_CurlPipeShell
{
    meta:
        description = "npm postinstall pipes network fetch into a shell"
        reference   = "Lab 2a Part 1 — gear-composer, mhddos-n8n"
    strings:
        $post   = "\"postinstall\"" ascii
        $curl_sh   = /curl\s+[^"]{5,300}\|\s*sh/
        $wget_sh   = /wget\s+[^"]{5,300}\|\s*sh/
        $curl_cmd  = /curl\s+[^"]{5,300}\|\s*cmd/
    condition:
        $post and any of ($curl_sh, $wget_sh, $curl_cmd)
}
```

### `NPM_MetaSpace_AES_C2` — Lab 2d

Detects a `crypto.createDecipheriv('aes-256-cbc', ...)` with a hex-encoded `IV:ciphertext` pair — the MetaSpace evasion pattern.

```yara
rule NPM_MetaSpace_AES_C2
{
    meta:
        description = "AES-256-CBC encrypted C2 URL in a Node module — MetaSpace family"
        reference   = "Lab 2d — davideliasdev09/MetaSpace_TechnicalAssessment"
    strings:
        $decipher = "createDecipheriv" ascii
        $aes_cbc  = "'aes-256-cbc'" ascii
        $iv_cipher = /['"][a-f0-9]{32}:[a-f0-9]{80,}['"]/
        $spawn    = "spawn(" ascii
        $https    = "https.get(" ascii
    condition:
        $decipher and $aes_cbc and $iv_cipher and any of ($spawn, $https)
}
```

### `NPM_Npmrc_Suppresses_Audit` — Lab 2d

`.npmrc` with `audit=false` inside a repo whose `package.json` has a postinstall script. Weak on its own; combine with other signals.

```yara
rule NPM_Npmrc_Suppresses_Audit
{
    meta:
        description = ".npmrc disabling npm audit — often used to hide install-time warnings"
        reference   = "Lab 2d — MetaSpace"
    strings:
        $audit_off = /^\s*audit\s*=\s*false/
    condition:
        $audit_off
}
```

---

## PyPI primitives

### `Malware_PyPI_SetupPy_ExecBase64Chain` — Lab 3a

Detects nested `exec(base64.b64decode(...))` chains — the classic PyPI obfuscation shape.

```yara
rule Malware_PyPI_SetupPy_ExecBase64Chain
{
    meta:
        description = "setup.py / module with exec(base64.b64decode(...)) layers"
        reference   = "Lab 3a — extrazip / cryptozip"
    strings:
        $exec_b64  = /exec\s*\(\s*base64\.b64decode/
        $exec_marsh = /exec\s*\(\s*marshal\.loads/
        $import_dyn = /__import__\s*\(/
        $exec_zlib = /exec\s*\(\s*zlib\.decompress/
    condition:
        #exec_b64 > 1 or (#exec_b64 >= 1 and any of ($exec_marsh, $import_dyn, $exec_zlib))
}
```

### `Malware_PyPI_TelegramBot_Exfil` — Lab 3a

Telegram Bot API token pattern plus exfil primitives.

```yara
rule Malware_PyPI_TelegramBot_Exfil
{
    meta:
        description = "Telegram Bot API token used for exfil (numeric ID + 35-char secret)"
        reference   = "Lab 3a — extrazip"
    strings:
        $token    = /\b\d{8,10}:[A-Za-z0-9_\-]{35}\b/
        $api_host = "api.telegram.org/bot" ascii
        $post_call = /requests\.(post|get)\s*\(/
    condition:
        $token and ($api_host or $post_call)
}
```

### `Malware_PyPI_ZipCluster_Naming` — Lab 3b

Weak-precision, high-recall rule for the `*zip` naming family. Combine with any of the exec rules above.

```yara
rule Malware_PyPI_ZipCluster_Naming
{
    meta:
        description = "PyPI *zip cluster naming — hunt for lookalikes"
        reference   = "Lab 3b — python-uzip family"
    strings:
        $short_zip_name = /name\s*=\s*['"](gx|k|m|uu|y|mini|u|z)zip['"]/
    condition:
        $short_zip_name
}
```

---

## VS Code primitives

### `VSCode_WOFF2_Wrong_Magic` — Lab 1b, Lab 4b

A `.woff2` file whose bytes 0..3 aren't the WOFF2 magic — meaning it's not a font. Apply this rule with a file-selection filter for `*.woff2`; the rule fires on any such file that does NOT start with the correct magic.

```yara
rule VSCode_WOFF2_Wrong_Magic
{
    meta:
        description = "File named .woff2 that is not a WOFF2 font (magic mismatch)"
        reference   = "Lab 1b (fake fonts) — Lab 4b Station 3"
    strings:
        $wOF2 = { 77 4F 46 32 }  // wOF2 — WOFF2
        $wOFF = { 77 4F 46 46 }  // wOFF — WOFF
    condition:
        // Applied only to *.woff2 files by the scanner harness.
        not ($wOF2 at 0 or $wOFF at 0)
}
```

### `VSCode_VSIX_Activate_RuntimeDownload` — Lab 4a

Extension activate() function that fetches from the network and writes to disk.

```yara
rule VSCode_VSIX_Activate_RuntimeDownload
{
    meta:
        description = "Extension activate() downloads and drops a file at runtime"
        reference   = "Lab 4a — TrelloWorks"
    strings:
        $activate    = /(?:function\s+)?activate\s*\(/
        $child_proc  = "child_process" ascii
        $https_get   = /https\.(get|request)\s*\(/
        $write_stream = "createWriteStream" ascii
        $ext_drop    = /["'][^"']+\.(bat|cmd|ps1|sh|exe)["']/
    condition:
        $activate and (2 of ($child_proc, $https_get, $write_stream, $ext_drop))
}
```

### `VSCode_Spellright_Dict_Suspicious` — Lab 4b Station 2

`.vscode/spellright.dict` whose first line is longer than any real English word.

```yara
rule VSCode_Spellright_Dict_Suspicious
{
    meta:
        description = "spellright.dict with a first 'word' longer than any real English word"
        reference   = "Lab 4b Station 2 — Contagious Interview dictionary attack"
    strings:
        $long_first = /\A[A-Za-z0-9+\/=]{40,}\n/
    condition:
        $long_first
}
```

---

## Running the rules

### YARA-X (recommended)

```bash
# scan a directory of samples
yr scan starter-rules.yar ~/sandbox/

# scan a single file
yr scan starter-rules.yar path/to/suspect.js

# JSON output for automation
yr scan --output-format json starter-rules.yar ~/sandbox/
```

### Classic YARA

```bash
yara -r starter-rules.yar ~/sandbox/
```

### Ideas for tightening

Every rule above is a *starter*. When you tune for your environment:

- Narrow `filesize < N` to your typical false-positive scale.
- Combine rules — a `condition:` that references another rule (`rule_a and rule_b`) can chain primitives for higher confidence.
- Attach `meta.hash` fields when you have per-sample SHA-256s.
- Add `tags:` so you can filter runs (`-t campaign_polinrider`, `-t campaign_contagious_interview`).

The next four Module-ending labs (1e / 2e / 3c / 4c) walk attendees through *building* these rules from primitives they extracted during the module. This file is the finished-artifact reference.

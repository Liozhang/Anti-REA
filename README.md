<div align="center">

# Anti-REA

### An MCP server for hardening your own software against agent-driven reverse engineering

**Audit what your shipped artifacts leak. Apply mitigations. Verify the result.**

[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#connect-your-agent)
[![Tests](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verification)

**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Deutsch](docs/readme/README_de.md) · [Français](docs/readme/README_fr.md) · [Español](docs/readme/README_es.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [Русский](docs/readme/README_ru.md) · [Italiano](docs/readme/README_it.md)

Zero-dependency Node.js. Everything runs locally. Requires Node.js 22 or newer.

[How it works](#how-it-works) · [Quick start](#quick-start-from-the-terminal) · [What the audit reports](#what-the-audit-reports) · [Measured results](#measured-results) · [Defense layers](#defense-layers) · [Known limits](#known-limits) · [FAQ](#faq) · [Verification](#verification) · [Contributing](#contributing) · [Security](#security)

</div>

---

> [!IMPORTANT]
> Install Anti-REA from npm (`anti-rea`) or clone this repository. A similarly
> named package does not establish that a download is official.
> Use it on software you own or are authorized to protect.

REA (Reverse Engineer Anything) and similar MCP-based toolchains let an AI agent inspect a
shipped binary, package, or application without its source code, explain how a feature
works, and build a version of it. That drives the cost of understanding software you ship
close to zero.

Anti-REA is the counterpart for the defender. It is an MCP server — with a command-line
interface sharing the same workflows — that hardens **your own project** before it ships:

- **audit_artifact**: what a shipped artifact exposes to the readers and engines such tools
  use, with the evidence and source range behind every fact
- **harden_artifact**: apply the mitigations the tool can apply, and report the ones that
  need external tools or an architectural change
- **verify_artifact**: confirm the mitigations hold
- **generate_notice**: truthful license and no-reverse-engineering text for your artifact's
  own README, so an investigating agent meets your terms as data at the moment it checks
  authorization
- **generate_probe_kit**: an embeddable runtime-observation detection package for your own
  code, plus a manual checklist

## How it works

Three commands run in order, and the order matters:

1. **`audit`** reads your artifact without running it and reports every fact a reader could
   extract, each with its evidence range and the reader that would consume it. It writes
   nothing to the artifact.
2. **`harden`** takes that report and applies the mitigations it can, writing a `.hardened`
   copy beside the original. Every mitigation is an equal-length overwrite or a relayout
   write, so file length and offsets stay valid. Anything that would change runtime behavior
   is reported as skipped with its reason, never silently attempted. Every entry in the
   result, applied or skipped, also states what the mitigation still leaves exposed and the
   build-time fix that removes the exposure outright — an applied measure is never reported
   as a complete one.
3. **`verify`** re-reads the hardened copy and checks the structures your users still depend
   on. The required sets are derived from the applied mitigations: what a mitigation declares
   it touches is exempted, everything else must still parse. A hardening run that breaks a
   required structure fails review, and the original is left untouched.

The same three workflows back the MCP tools and the CLI, so an agent and a terminal get
identical results and identical exit codes: 0 for a completed audit or hardening run, 1 for a
failed verification, 2 for a usage error, 3 for a refusal.

## Install

```bash
npx anti-rea --help            # run once without installing
npm install --global anti-rea  # or install both commands globally
anti-rea --help
```

Requires Node.js 22 or newer. The package has no dependencies, and everything
runs locally.

## Connect your agent

After a global install, register the server with any MCP-capable agent
(Claude Code, Cursor, Codex, and others):

```json
{
  "mcpServers": {
    "anti-rea": {
      "command": "anti-rea-mcp"
    }
  }
}
```

Working from a clone instead of the global install? Point `command` at
`node` with `args` set to the absolute path of `bin/anti-rea-mcp.js`.

Then ask your agent: *audit my app at /path/to/app and tell me what it leaks.*

## Quick start from the terminal

```bash
anti-rea audit /absolute/path/to/your/app --json
anti-rea harden /absolute/path/to/your/app --from audit.json
anti-rea verify /absolute/path/to/your/app
anti-rea notice --template license > NOTICE.md
anti-rea probe /absolute/path/to/probe-kit-output
```

The `probe` command writes an integration package for the runtime observation resistance
layer: embeddable detection snippets for observable facts, plus a manual checklist. It writes
only to the directory you name and never modifies your artifact. The same package is available
to agents as the `generate_probe_kit` tool.

## What the audit reports

| Exposure | Who reads it | What audit reports |
| --- | --- | --- |
| ELF/PE/Mach-O headers, sections, symbols, build IDs | Built-in static readers, objdump | Every fact a reader can extract, with its source range |
| Embedded Go module and build metadata | Built-in Go reader | Presence, versions, and the section that carries them |
| Embedded Rust dependency metadata (`.dep-v0`) | Built-in Rust reader | Crate names, versions, and dependency edges |
| Android DEX type descriptors, method names and string constants | Built-in DEX reader | Class names, method names, and the constant pool |
| PE certificates, imports, exports, load config | Built-in PE readers | Signer identity and declared imports |
| Model, Erlang, pyc and other container metadata | Built-in format readers | Declared metadata and totals |
| Embedded credentials | Token pattern scanner | Known credential families with public formats, with offset |

Formats outside the reader set are reported, not skipped. When the audit meets a Unity
IL2CPP `global-metadata.dat`, a .NET assembly, a JavaScript bundle, an APK signature
block, or a GPU payload container, it names the format as a capability boundary with the
reason it is out of scope and your next step, instead of returning an empty result. An
empty result is not proof of safety. An APK is read as a ZIP and then followed one level
into it: each `classes.dex` entry, stored or deflated, is handed to the DEX reader, so the
app's class names, method names, and string constants reach the report at the path
`app.apk!classes.dex`. The signature block is reported as a boundary rather than parsed.

Each finding carries its evidence, the reader that would consume it, the mitigation that
would remove it, what that mitigation still leaves exposed, and the build-time fix that
removes the exposure outright.

## Measured results

Everything below was run on real artifacts, not fixtures: a Go 1.24.4 binary built for Linux
and for Windows, and a Python 3.13 bytecode file, hardened by this tool and then read back
with REA's own static readers and by fresh agents.

| Question | Result |
| --- | --- |
| Does REA recover Go build information after hardening? | No. On both ELF and Windows PE, `inspect-go-binary` reports that no recognized Go build-info record was found. Before hardening it returned the module path, version, and six build settings. |
| Are ELF symbol tables and build IDs gone? | Yes. `.symtab` leaves the section table entirely, and the GNU build-ID descriptor is zeroed in both the PT_NOTE segment and the SHT_NOTE section, with the note structure left parseable. |
| Can plain `strings` still find the module name? | Yes. The module name, compiler version, and build settings remain in read-only data and the function name table. See Known limits. |
| Does the audit see a token hidden in Python bytecode? | Yes, as of this release. The token scanner runs over all nine formats, and the embedded credential is reported and overwritten on request. |
| Does a legal notice make an investigating agent stop? | Not in the measured sample. Four fresh agents received the same reverse-engineering task on the same binary; two saw a generated notice, two did not. All four completed the analysis. Both agents that read the notice cited it, and both volunteered that redistributing the analysis would need authorization. |
| What still leaks after hardening? | Build-machine paths from unstripped debug information, the PE import table, and every format fact the software needs to run. The audit reports these without inventing a mitigation. |

The fifth row is the honest one: the notice layer changes how an agent frames the work, not
whether it does it. Treat it as a contract and traceability measure, not a technical barrier.

## Protect your audit outputs

An audit report is a map of your artifact's exposures and the mitigations applied.
Committing it to version control, or shipping it inside the artifact, hands that map to
anyone who reads the repository. Anti-REA writes a warning to standard error when an
output path is inside a git working tree. Use `--redacted` when a report must be shared
with a contractor, an auditor, or a disclosure program: it keeps categories and counts
and omits exact paths, byte ranges, and the mitigation mapping. Generated notices
contain no reference to Anti-REA and no hint of your hardening state.

## Defense layers

| Layer | Tool | Expected effect | Residual risk |
| --- | --- | --- | --- |
| Metadata hygiene | `audit_artifact`, `harden_artifact` | Built-in readers return unknown instead of facts | A new reader can target a new format; plain string search still finds module names and versions in read-only data |
| Content protection | `harden_artifact` | Overwrites only the byte ranges you name yourself; no audit finding derives this measure | Everything outside those ranges is untouched and still readable |
| Runtime observation resistance | `generate_probe_kit` | Raises the cost of debuggers and instrumentation | Kernel-level observation is out of reach |
| Agent stop-condition induction | `generate_notice` | The agent checks authorization with the human | The agent may ignore the notice |
| Model-level truthful signals | `generate_notice` | The authorization question becomes unavoidable | Model behavior is probabilistic |
| Secret minimization | Report recommendation | The only absolute layer | Requires server-side architecture |
| Legal and operational | `generate_notice` | Contract and traceability do what bytes cannot | Enforcement is a legal process |

Two rows are not what a protection product usually means by them, and this project does
not claim otherwise.

Content protection does not obfuscate anything. It zeroes the byte ranges you supply by
hand. No reader emits a finding in that layer, so the audit-to-harden path never reaches
it: you have to name the ranges yourself.

Secret minimization is not a measure the tool applies either. It is the recommendation
that a token reachable by a pattern match should never have been compiled in. It is also
the only layer that is absolute rather than a cost increase.

## Known limits

Three limits were measured, not theorized:

- **Plain string search still works.** Equal-length overwrites destroy metadata records such as Go build information and ELF symbol tables. But the module name, compiler version, and build settings also live in read-only data and the function name table, where the Go runtime reads them. Overwriting those bytes changes runtime behavior, so Anti-REA leaves them alone, and anything that runs `strings` on a hardened binary still recovers them. The audit report names the build flags that remove them at the source for each affected finding: `-trimpath`, `-ldflags="-s -w"`, `strip`. It also states what those flags themselves cost, so the tradeoff is visible before you rebuild.
- **Not every exposure has a mitigation.** PE import tables, ELF header facts, and Python bytecode format flags are reported with no mitigation because the software needs them to run. The audit says so instead of inventing a measure.
- **Token patterns cover known formats only.** The scanner matches credential families with public formats. A token in a private format is invisible to it, and an empty result is not proof that no secrets exist.

Host coverage is a measured limit with a fix in progress. The tool is pure Node.js
with no native dependencies, but the test suite and fixtures were only ever exercised
on Windows by hand. A GitHub Actions workflow now runs the same three checks on
Ubuntu, macOS, and Windows on every push; until that workflow has completed on a
commit, treat macOS and Linux as expected to work rather than verified.

## FAQ

<details>
<summary><strong>Will hardening break my application?</strong></summary>

Mitigations are equal-length overwrites or full relayouts that re-run every format check, and `verify` fails a run that breaks a structure your users depend on. Anything that would change runtime behavior is skipped with a stated reason instead of attempted. Re-running `harden` on an already hardened artifact is a no-op that reports no change. And because no byte-level measure is a complete one, every entry in the result states what it still leaves exposed — read that line before you call a run finished.

</details>

<details>
<summary><strong>Does the tool upload my binary anywhere?</strong></summary>

No. Every read and write is a local file operation inside the process. No network requests, no child processes, no telemetry.

</details>

<details>
<summary><strong>Which agents can use it?</strong></summary>

Any agent that can register a local MCP server: Claude Code, Cursor, Codex, and others. Manual registration is the JSON block under Connect your agent.

</details>

<details>
<summary><strong>Is my audit report itself a leak?</strong></summary>

Yes, and that is why the tool warns when you write one inside a git working tree and offers `--redacted`, which keeps categories and counts and drops exact paths, byte ranges, and the mitigation mapping.

</details>

<details>
<summary><strong>What if the audit finds nothing?</strong></summary>

Then the artifact exposes nothing the readers can extract, and the report says so with its limitations. An empty result is not proof of safety: the token patterns cover known credential formats only, and a new reader can target a new format.

</details>

<details>
<summary><strong>Can it stop a determined reverse engineer?</strong></summary>

No. It raises the cost of automated readers and leaves evidence for your legal position. A skilled person with a debugger, or anyone with kernel-level access, is outside what bytes in a file can resist. Keeping secrets off the client is the only absolute layer.

</details>

<details>
<summary><strong>Does the notice really make agents stop?</strong></summary>

Not reliably, and this project does not claim otherwise. In the measured sample of four fresh agents, none stopped. Both agents that read the notice cited it and flagged that redistributing the analysis would need authorization. Treat the notice as a contract and traceability measure.

</details>

<details>
<summary><strong>I found a bug. What now?</strong></summary>

Check that you are on the latest commit, then open an issue with your Node version, target type, the command you ran, and the output. See Contributing.

</details>

## Boundaries

Anti-REA does not do the following, by design:

- **No prompt injection.** It never ships agent instruction files (`AGENT.md`, `CLAUDE.md`,
  `.cursorrules`, and similar) into your artifacts, and never writes directives addressed
  to an AI agent. Notices are statements of fact addressed to a human reader and travel
  through data channels: README, LICENSE, NOTICE, version resources.
- **No fabricated legal claims.** Every line of generated notice text is a real term or a
  real, checkable fact. Inflated threats collapse the first time someone verifies them.
- **No harm to legitimate users.** Mitigations never weaken your software's own operation.
  Runtime protections are opt-in per threat model, not defaults.

## About this repository

Anti-REA is open source by design: its audit rules are public, it holds no secrets, and it
carries no attack payloads. The tool's value is automation and evidence, not secrecy — and
the one absolute defense layer, keeping secrets off the client, is unaffected by anyone
reading this code. What must never enter the repository is user-specific audit output,
which is why the tool warns about it and offers `--redacted`.

## Verification

Every capability is covered by `node --test` with real fixture files, and the MCP surface
is smoke-tested over a standard stdio handshake:

```bash
node --test
node scripts/mcp-smoke.mjs
node tests/fixtures/build.mjs --check
```

The current suite is 592 tests, all passing, plus the fixture digest registration check.
The suite is exercised on Windows by hand and on Ubuntu, macOS, and Windows by the CI
workflow, on Node.js 22 and 24.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development
setup, the checks that gate a change, and the conventions the test suite enforces.

## Security

Report vulnerabilities in Anti-REA itself through [SECURITY.md](SECURITY.md), not in public
issues. Design limits documented under Known limits are not vulnerabilities.

## Documentation

- [简体中文说明](docs/readme/README_zh.md) and [nine other translations](docs/readme/)
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and change gates
- [SECURITY.md](SECURITY.md): how to report a vulnerability
- [LICENSE](LICENSE): MIT

## License

[MIT](LICENSE). Anti-REA is for protecting software you own or are authorized to protect.
Third-party formats keep their own specifications.

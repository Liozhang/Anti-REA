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
> Get Anti-REA from this repository only. It has no npm release yet, and a
> similarly named package does not establish that a download is official.
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
   is reported as skipped with its reason, never silently attempted.
3. **`verify`** re-reads the hardened copy and checks the structures your users still depend
   on. The required sets are derived from the applied mitigations: what a mitigation declares
   it touches is exempted, everything else must still parse. A hardening run that breaks a
   required structure fails review, and the original is left untouched.

The same three workflows back the MCP tools and the CLI, so an agent and a terminal get
identical results and identical exit codes: 0 for a completed audit or hardening run, 1 for a
failed verification, 2 for a usage error, 3 for a refusal.

## Connect your agent

Register the server with any MCP-capable agent (Claude Code, Cursor, Codex, and others):

```json
{
  "mcpServers": {
    "anti-rea": {
      "command": "node",
      "args": ["/absolute/path/to/Anti-REA/bin/anti-rea-mcp.js"]
    }
  }
}
```

Then ask your agent: *audit my app at /path/to/app and tell me what it leaks.*

## Quick start from the terminal

```bash
node bin/anti-rea.js audit /absolute/path/to/your/app --json
node bin/anti-rea.js harden /absolute/path/to/your/app --from audit.json
node bin/anti-rea.js verify /absolute/path/to/your/app
node bin/anti-rea.js notice --template license > NOTICE.md
node bin/anti-rea.js probe /absolute/path/to/probe-kit-output
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
| Unity IL2CPP metadata | Built-in IL2CPP reader | Recoverable type and method names |
| .NET metadata and CIL | Built-in managed reader | Assembly facts and member inventory |
| JavaScript source maps and module graphs | Built-in JavaScript reader | Recoverable original sources |
| PE certificates, imports, exports, load config | Built-in PE readers | Signer identity and declared imports |
| Model, SQLite, Erlang, pyc and other container metadata | Built-in format readers | Declared metadata and totals |
| Embedded credentials | Token pattern scanner | Known credential families with public formats, with offset |

Each finding carries its evidence, the reader that would consume it, and the mitigation
that removes it.

## Measured results

Everything below was run on real artifacts, not fixtures: a Go 1.24.4 binary built for Linux
and for Windows, and a Python 3.13 bytecode file, hardened by this tool and then read back
with REA's own static readers and by fresh agents.

| Question | Result |
| --- | --- |
| Does REA recover Go build information after hardening? | No. On both ELF and Windows PE, `inspect-go-binary` reports that no recognized Go build-info record was found. Before hardening it returned the module path, version, and six build settings. |
| Are ELF symbol tables and build IDs gone? | Yes. `.symtab` leaves the section table entirely, and the GNU build-ID descriptor is zeroed in both the PT_NOTE segment and the SHT_NOTE section, with the note structure left parseable. |
| Can plain `strings` still find the module name? | Yes. The module name, compiler version, and build settings remain in read-only data and the function name table. See Known limits. |
| Does the audit see a token hidden in Python bytecode? | Yes, as of this release. The token scanner runs over all eight formats, and the embedded credential is reported and overwritten on request. |
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
| Content protection | `harden_artifact` guidance | Static decompilation sees stubs, not the program | Runtime dumping recovers unpacked code |
| Runtime observation resistance | `generate_probe_kit` | Raises the cost of debuggers and instrumentation | Kernel-level observation is out of reach |
| Agent stop-condition induction | `generate_notice` | The agent checks authorization with the human | The agent may ignore the notice |
| Model-level truthful signals | `generate_notice` | The authorization question becomes unavoidable | Model behavior is probabilistic |
| Secret minimization | Report recommendation | The only absolute layer | Requires server-side architecture |
| Legal and operational | `generate_notice` | Contract and traceability do what bytes cannot | Enforcement is a legal process |

## Known limits

Three limits were measured, not theorized:

- **Plain string search still works.** Equal-length overwrites destroy metadata records such as Go build information and ELF symbol tables, but the module name, compiler version, and build settings also live in read-only data and the function name table, where the Go runtime reads them. Overwriting those bytes changes runtime behavior, so Anti-REA leaves them alone, and anything that runs `strings` on a hardened binary still recovers them. Remove them at the source with build flags (`-trimpath`, `-ldflags="-s -w"`, `strip`).
- **Not every exposure has a mitigation.** PE import tables, ELF header facts, and Python bytecode format flags are reported with no mitigation because the software needs them to run. The audit says so instead of inventing a measure.
- **Token patterns cover known formats only.** The scanner matches credential families with public formats. A token in a private format is invisible to it, and an empty result is not proof that no secrets exist.

Host coverage is also a measured limit: the tool is pure Node.js with no native
dependencies, but the test suite and fixtures have only been exercised on Windows.
macOS and Linux are expected to work and are not yet verified.

## FAQ

<details>
<summary><strong>Will hardening break my application?</strong></summary>

Mitigations are equal-length overwrites or full relayouts that re-run every format check, and `verify` fails a run that breaks a structure your users depend on. Anything that would change runtime behavior is skipped with a stated reason instead of attempted. Re-running `harden` on an already hardened artifact is a no-op that reports no change.

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

The current suite is 526 tests, all passing, plus the fixture digest registration check.
The suite runs on Windows with Node.js 22 and 24; macOS and Linux hosts have not been
exercised yet.

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

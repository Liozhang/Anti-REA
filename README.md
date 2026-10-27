<div align="center">

# Anti-REA

### An MCP server for hardening your own software against agent-driven reverse engineering

**Audit what your shipped artifacts leak. Apply mitigations. Verify the result.**

[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-5c4ee5.svg)](#connect-your-agent)
[![Tests](https://img.shields.io/badge/tests-node--test-5c4ee5.svg)](#verification)

**English** · [简体中文](docs/readme/README_zh.md)

Zero-dependency Node.js. Everything runs locally.

</div>

---

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

Use it on software you own or are authorized to protect.

> This project is under active development. The interface below is the contract the test
> suite enforces.

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

The `probe` command writes an integration package for the runtime observation
resistance layer: embeddable detection snippets for observable facts, plus a manual
checklist. It writes only to the directory you name and never modifies your artifact.
The same package is available to agents as the `generate_probe_kit` tool.

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

Each finding carries its evidence, the reader that would consume it, and the mitigation
that removes it.

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
```

## Documentation

- [简体中文说明](docs/readme/README_zh.md)

## License

[MIT](LICENSE). Anti-REA is for protecting software you own or are authorized to protect.
Third-party formats keep their own specifications.

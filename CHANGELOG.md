# Changelog

Each section header is the exact release tag; the release workflow uses the section as release notes.

## v0.1.1

Released 2026-11-17.

- **Fix:** the `_meta` key on denied calls is `ifcproxy/decision` again, as documented. v0.1.0 sent `github.com/nomaskscientist/ifcproxy/decision`, a regression from the module rename, and that key is not a valid MCP `_meta` prefix. A test now pins the key.
- **New:** `examples/trifecta-demo` plays the attack against a real proxy and prints each decision; its output is the README animation (`scripts/render_demo_gif.py`).

## v0.1.0

Released 2026-11-16. First public release.

- **Proxy.** A stdio MCP proxy that labels each agent session from tool results (`untrusted`, `private`) and decides every `tools/call` with a YAML policy before the server sees it. Labels only accumulate. Once a session holds untrusted content and private data, external sinks are blocked (the "lethal trifecta").
- **Policy.**
  - Strict YAML loader with `file:line:col` errors.
  - Undeclared tools are denied.
  - Every external sink must have a deny/ask rule for `[untrusted, private]`; a missing rule is a load error.
- **Decisions:** `allow`, `deny` and `ask` (`--ask-mode tty|deny|allow`). Denied calls return an `isError` tool result with the reason and an `ifcproxy/decision` entry in `_meta`.
- **Cross-server sessions.** `--session-file` shares labels between proxies wrapping different servers in one agent session.
- **Audit:** a JSONL audit log (`--audit`) and a `--dry-run` mode that decides and logs without blocking.
- **Hardened JSON-RPC handling.** It rejects:
  - duplicate and case-folded keys;
  - obfuscated security-relevant method names;
  - ambiguous ids.

  Server notifications and unattributable responses are labelled conservatively. MCP Tasks (2025-11-25) are supported, failing closed.
- **Process supervision:** process-group kill on shutdown, and an exit backstop for servers that leave orphaned children.
- **Example policies** for the official filesystem, fetch, memory and everything servers.
- **Performance.** `Decide` takes about 15–30 ns with 0 allocations; end-to-end overhead is about 60 µs per call.
- **Binaries** for Linux, macOS and Windows (amd64, arm64).

Known limitations are listed in [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Notably, the proxy is stdio only (no Streamable HTTP) and labels only `tools/call` results.

# Progress

## M1 — core without network: done
- `internal/taint`: `Label` bit mask, `Session` (lock-free monotone accumulation), `Store` (shared session file across proxies, fails closed).
- `internal/policy`: strict YAML parser over `yaml.Node` with `file:line:col: path` errors (all errors reported at once), compiled into flat tables; load-time sink-coverage guard.
- `internal/monitor`: `Decide` (unknown tool = deny, `max_args_bytes`, first-match rules), `Observe`/`Produces`.
- Tests: table-driven trifecta/default-deny scenarios, concurrency test, `FuzzParse` (60 s, ~755k execs, no crashes), 0-alloc test, p99 test.
- Checks: `go vet` clean; `go test -race ./...` green (run under WSL/Linux: race detector needs cgo, and this Windows host has no C compiler).
- Bench (Ryzen 5 5600, linux/amd64): Decide 10–29 ns/op, 0 B/op, 0 allocs/op; p99 51 ns.

## M2 — stdio proxy: done
- `cmd/ifcproxy`: `ifcproxy --policy p.yaml -- <server cmd>`, `--check`, `--session-file`, signal forwarding, 5 s grace then kill after client EOF, exit code of the server.
- `internal/proxy`: newline framing with a size limit (oversized client messages → error, stream stays in sync; oversized server messages streamed through after conservative tainting), strict envelope parsing (duplicate/case-folded keys, obfuscated `tools/call`, notifications, ids), id correlation with normalisation (1 ≡ 1.0) and uniqueness of in-flight ids, batches decided per element, deny → `isError` tool result with reason + `_meta`, protocol errors → JSON-RPC errors, results taint the session before delivery, server notifications/unknown responses inherit labels of pending tool calls, `notifications/cancelled` handling.
- Tests: 25 harness tests over pipes; `FuzzClientDifferential` (60 s, 2.7M execs): forwarded bytes never contain a tools/call that a lenient case-insensitive/last-wins decoder reads as a denied tool.
- Checks: vet clean, `go test -race ./...` green (WSL).
- MCP spec checked (2025-06-18 transports + tools pages): newline framing with no embedded newlines; tool errors as `isError` results.

## Next
- M3: tty asker, JSONL audit sink, `--ask-mode`, `--audit`, `--log-args`, `--dry-run`.

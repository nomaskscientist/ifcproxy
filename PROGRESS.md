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

## M3 — ask mode and audit: done
- `internal/ask`: `TTY` asker (`/dev/tty`; `CONIN$`/`CONOUT$` on Windows), serialised prompts, timeout → deny, context cancel → deny, open failure → deny; prompt escapes model-controlled values (ANSI/OSC/bidi spoofing); `Static` for `--ask-mode=allow|deny`.
- `internal/audit`: JSONL sink (one `Write` per record, mutex, write errors counted and reported at exit). Fields: time, session, event, id, tool, decision, policy_action, code, rule, rule_line, reason, labels, added, dry_run, forwarded, args (only with `--log-args`).
- CLI: `--ask-mode`, `--ask-timeout`, `--audit` (`-`/path/`off`), `--log-args`, `--dry-run` (decides and logs, forwards everything, warns on stderr).
- Checks: vet clean, `go test -race ./...` green (WSL).

## M4 — end-to-end attack tests: done
- `test/fakemcp`: deliberately lenient MCP server (case-insensitive keys, last duplicate wins, normalised names) with an execution log.
- `test/e2e`: 12 attack scenarios (A1–A12) + 8 mode/lifecycle tests through the real binary; bypass attacks include a control run against the bare server proving the attack works without the proxy. Catalogue: `docs/ATTACKS.md`.
- `docs/LIMITATIONS.md`: 17 things v1 does not stop.
- Bug found and fixed by the e2e tests: the "hung server" fixture used `select {}`, which the Go runtime aborts as a deadlock; now it sleeps.
- Checks: vet clean; `go test ./...` green on Windows; `go test -race ./...` green on Linux (WSL).

## M5 — packaging: done
- README (what it is, 3 commands, client config, example policy, flags, honest "does not guarantee"), Makefile (build, vet, test, race, bench, fuzz, check), GitHub Actions (gofmt, vet, `-race` on Linux go1.22.x/stable + macOS, Windows without race, short fuzz, bench smoke), `docs/BENCH.md`, final `docs/DESIGN.md`.
- Verified: `go vet` clean and `go test -race ./...` green with Go 1.22.12 and 1.22.2 (linux/amd64); `go test ./...` green on Windows (Go 1.27.3); README demo run by hand and its output quoted.
- Not verified: the Makefile (`make` is not installed on this machine) and the CI workflow (never run on GitHub).

## Known gaps / possible next steps
- See `docs/LIMITATIONS.md`. The biggest: unlabelled non-tool content (`tools/list` descriptions, resources, prompts), and that cross-server protection depends on `--session-file`.
- Streamable HTTP transport; `tools/list` filtering of undeclared tools; value-level tracking (out of scope for v1).

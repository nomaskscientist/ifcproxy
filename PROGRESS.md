# Progress

## M1 — core without network: done
- `internal/taint`: `Label` bit mask, `Session` (lock-free monotone accumulation), `Store` (shared session file across proxies, fails closed).
- `internal/policy`: strict YAML parser over `yaml.Node` with `file:line:col: path` errors (all errors reported at once), compiled into flat tables; load-time sink-coverage guard.
- `internal/monitor`: `Decide` (unknown tool = deny, `max_args_bytes`, first-match rules), `Observe`/`Produces`.
- Tests: table-driven trifecta/default-deny scenarios, concurrency test, `FuzzParse` (60 s, ~755k execs, no crashes), 0-alloc test, p99 test.
- Checks: `go vet` clean; `go test -race ./...` green (run under WSL/Linux: race detector needs cgo, and this Windows host has no C compiler).
- Bench (Ryzen 5 5600, linux/amd64): Decide 10–29 ns/op, 0 B/op, 0 allocs/op; p99 51 ns.

## Next
- M2: stdio proxy (framing, tools/call interception, id correlation, batch, deny responses, child process lifecycle).

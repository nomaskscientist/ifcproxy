# Benchmarks

Budget from the spec: **p99 of `Decide` < 50 µs, 0 allocations on the hot path.**

Environment: AMD Ryzen 5 5600 (6C/12T), Ubuntu on WSL2, linux/amd64, Go 1.22.2.

```
make bench   # go test -run '^$' -bench . -benchmem ./internal/monitor ./internal/proxy
```

## `monitor.Decide` (hot path)

Median of `-count=5`. The session holds `untrusted|private`. Policies are generated with N tools, about N/4 tool-specific rules, plus two wildcard rules (`benchPolicy` in `internal/monitor/monitor_test.go`). `sink-deny` falls through to the last rule.

| Policy size | Case | ns/op | B/op | allocs/op |
|---|---|---:|---:|---:|
| 8 tools | sink → deny | 30.2 | 0 | 0 |
| 8 tools | unknown tool | 11.6 | 0 | 0 |
| 8 tools | parallel (12 goroutines) | 4.7 | 0 | 0 |
| 64 tools | sink → deny | 15.4 | 0 | 0 |
| 64 tools | unknown tool | 10.9 | 0 | 0 |
| 64 tools | parallel | 2.3 | 0 | 0 |
| 256 tools | sink → deny | 13.9 | 0 | 0 |
| 256 tools | unknown tool | 10.8 | 0 | 0 |
| 256 tools | parallel | 2.2 | 0 | 0 |

The 8-tool case is slower because its sink tool gets more rules attached relative to its position. Each rule costs about 1–2 ns to scan.

**Latency distribution** (`TestDecideP99`: 200 000 individually timed calls, 256-tool policy, 3 runs):

| p50 | p99 | max |
|---:|---:|---:|
| 30 ns | 49–59 ns | 28–263 µs |

- p99 is about 1000× under the 50 µs budget.
- The max values are single samples hit by OS scheduling or GC preemption of the measuring goroutine; `Decide` itself does not allocate or block.
- The test fails if p99 ≥ 50 µs. On Windows the timer resolution is too coarse for per-call timing: it reports p50 = p99 = 0.

**Zero allocations** is asserted by `TestDecideZeroAlloc` (`testing.AllocsPerRun`) for allow, deny, rule-match and unknown-tool paths, and by `TestSessionAddZeroAlloc` for label accumulation.

## Per-message proxy overhead (not the hot path)

Full client-path cost of one `tools/call` line:
- strict envelope parse (`encoding/json` token walk with duplicate and case-fold checks);
- params parse;
- `Decide`;
- pending-table update, or deny-response encoding.

This path allocates. The zero-allocation budget applies to `Decide` only.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `ClientToolsCall/allow` | ~7 200 | 3 970 | 103 |
| `ClientToolsCall/deny-trifecta` | ~9 300 | 5 988 | 122 |
| `ServerResult` (correlate + taint) | ~3 600 | 1 777 | 52 |

About 7–10 µs per tool call: negligible next to process-to-process pipe latency and tool execution time. If it ever matters, the strict parser is the place to optimise (a hand-written scanner instead of `json.Decoder.Token`).

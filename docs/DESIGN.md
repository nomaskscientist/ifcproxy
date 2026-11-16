# ifcproxy — design decisions (v1)

**Model.** The proxy sees JSON-RPC, not the model, so taint is per session and only grows. `Label` is a `uint32` mask. `Session` updates an `atomic.Uint32` with a CAS loop (`atomic.Uint32.Or` needs Go 1.23; the target is 1.22).

**Policy.**
- Rules match in file order; the first one whose selector matches (tool name, `*`, or `sink:external`) and whose `when` labels are all in the session decides.
- Declared tool with no matching rule → allow. Undeclared tool → deny.
- **Extra load-time guard (beyond the spec):** every `sink: external` tool needs a deny/ask decision for `[untrusted, private]`, or an allow rule that names it explicitly. A forgotten rule fails at load instead of leaving a silent hole.
- Tool names are exact, case-sensitive, MCP charset. Names that differ only by case are rejected, so a lenient server can't map one name to two policy entries.
- No YAML anchors or tags (no alias bombs; what you read is what gets enforced).
- Errors come as `file:line:col: path`, all reported at once.

**Hot path.** Compiled to `map[string]int32` plus a per-tool `[]int32` of applicable rules. `Decide` is one map lookup + a mask scan, 0 allocations. The zero value of `Action` is `Deny`. Measured: about 15–30 ns, p99 about 50 ns (docs/BENCH.md).

**Parsing: refuse anything two parsers could read differently.** Client messages must be valid UTF-8 JSON. Rejected:
- duplicate keys, and keys that collide under Unicode case folding (`Method`, `NAME`, Kelvin-sign `K`), at the envelope and `params` level;
- methods that fold to `tools/call` but aren't exactly that;
- `tools/call` notifications;
- ids that aren't strings or numbers.

Allowed `tools/call` messages and all other messages are forwarded **byte-for-byte**; nothing is re-serialized except a batch with denied elements removed. *Trade-off:* strictness may reject sloppy but harmless clients; in return the parser-differential fuzz target holds.

**Correlation.**
- Every client request id is tracked. Ids are normalised (`1` ≡ `1.0`) and must be unique while in flight, so a reused id can't make one request's response pass for another's.
- A tool result adds `produces` labels **before** its bytes reach the client.
- **Conservative attribution:** a server notification or request while tool calls are pending, a response with an unknown id, and an unparseable or oversized server message all inherit the union of labels of the pending tool calls. Oversized server messages are streamed through rather than buffered.
- A cancelled tool call is tainted at cancel time (its result may race the cancellation).

**Pipelined calls.** A call is judged on the labels present *when it is sent*. Calls issued together (parallel tool calls in one model turn) can't carry data from results not yet delivered, so this is sound for the model. Checked in `README` by sending calls one at a time; a client sending a sink call in the same burst as a read is allowed by design.

**Deny representation.**
- Policy denials → a `tools/call` result with `isError: true`, a text reason and `_meta["ifcproxy/decision"]`. The model sees why and can tell the user; MCP routes execution-level failures there.
- Malformed or ambiguous input → JSON-RPC errors (−32700/−32600/−32602).

**Batches** (JSON-RPC 2.0; removed in MCP 2025-06-18 but still seen): each element is decided separately. Allowed elements are forwarded as a batch; denials come back in a separate array.

**Ask.**
- Prompts are serialised on `/dev/tty` (`CONIN$`/`CONOUT$` on Windows), because the client owns stdin/stdout.
- Timeout, context cancel, or no terminal → deny.
- Model-controlled text is escaped (`QuoteToASCII`) against ANSI/bidi spoofing.
- *Trade-off:* the client→server direction blocks while waiting; simpler, and nothing can overtake a pending decision.

**Shared sessions.** One proxy per server means a cross-server trifecta would go unseen. `--session-file` is an append-only file of 9-byte records; every proxy merges new records before each decision and appends after its labels grow. Order doesn't matter because labels only grow. A corrupt or shrunken file fails closed (all labels set).

**Audit.** JSONL, one `Write` per record. Arguments only with `--log-args`. A failing sink never blocks enforcement; losses are reported at exit.

**Environment notes.**
- MCP spec 2025-06-18 (transports, tools) was checked on the web: newline-delimited stdio messages with no embedded newlines; tool errors go in `isError` results.
- `-race` needs cgo. On this Windows host without gcc it ran under WSL/Linux; CI runs it on Linux and macOS.

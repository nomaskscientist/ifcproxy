# ifcproxy — design decisions (v1)

**Goal.** Block the "lethal trifecta" (private data + untrusted content + external channel) between an MCP client and an MCP server, deterministically, without classifiers. The proxy sees only JSON-RPC traffic, not model generation, so taint is **session-level and monotone**: labels are only ever added.

**Labels and session.** `taint.Label` is a `uint32` bit mask (`untrusted`, `private`). `Session` holds an `atomic.Uint32` updated with a CAS loop: `atomic.Uint32.Or` only exists from Go 1.23, and the target is 1.22. *Trade-off:* coarse. Once both labels are present, every external sink is blocked for the rest of the session, including harmless calls. Value-level tracking is out of scope by design.

**Policy semantics.**
- Rules are evaluated in file order; the first rule whose selector matches and whose `when` labels are *all* in the session decides.
- A selector is a tool name, `*`, or `sink:external` (every tool declared `sink: external`).
- A declared tool with no matching rule → allow. An undeclared tool → deny.
- **Load-time guard:** every external sink must have a deny/ask decision for a session tainted `[untrusted, private]`, or an allow rule that names it explicitly. Forgetting a rule is therefore a load error, not a silent hole. *Trade-off:* stricter than the spec literally asks for, but it removes the most likely misconfiguration.
- `max_args_bytes` (default 1 MiB) is checked inside `Decide`: oversized arguments → deny.
- Tool names: exact, case-sensitive, MCP character set `[A-Za-z0-9_.-/]`, 1–128 characters. Names that differ only by case are a load error, so a lenient server cannot resolve one name to two different policy entries.
- YAML anchors/aliases and explicit tags are rejected: no alias expansion bombs, and what you read is what gets enforced. All errors are reported with `file:line:col: path`.

**Hot path.** Policy compiles to a `map[string]int32` index plus, per tool, a precomputed `[]int32` of applicable rules. `Decide` = one map lookup + linear scan of a few masks, 0 allocations (`AllocsPerRun` test + `-benchmem`). `Decision` is returned by value; reason strings are pre-built at load time. `Action`'s zero value is `Deny` (fail closed).

**Shared sessions (`--session-file`).** One proxy process wraps one server, but the trifecta often spans servers (web server + filesystem server + mail server). Proxies can share one append-only file of 9-byte records (`%08x\n`). Each proxy ORs in new records before every decision and appends after its labels grow. Labels are monotone, so ordering between writers is irrelevant. A malformed or shrunken file fails closed: all labels are added.

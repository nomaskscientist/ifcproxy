# Attack scenarios covered by tests

End-to-end tests (`test/e2e`) run the real `ifcproxy` binary in front of `test/fakemcp`. That server is **deliberately lenient**:
- it matches JSON keys case-insensitively, and the last duplicate wins;
- it normalises method and tool names (case, surrounding whitespace, zero-width characters).

For the bypass attacks (A4, A5) a control sub-test runs the same messages against the bare server and checks that the attack *does* succeed there. Every test checks the server's execution log, not just the response the client receives.

Policy used: [`examples/policy.yaml`](../examples/policy.yaml).

| # | Attack | Expected result | Test |
|---|---|---|---|
| A1 | Direct trifecta: `read_file` → `fetch_url` (injection) → `send_email` | `send_email` denied with an `isError` result naming the rule; never executed | `TestA01DirectTrifecta` |
| A2 | Chain through two tools: untrusted content laundered via `echo`, secret read later, exfiltration through a *different* sink (`fetch_url` with a query string) | Denied. Labels persist across the chain, so a neutral tool can't clear them | `TestA02ChainThroughTwoTools` |
| A3 | Tool missing from the policy (`exec` exists on the server) | Denied (default deny); not executed | `TestA03UnknownTool` |
| A4 | Name obfuscation: `SEND_EMAIL`, `Send_Email`, leading/trailing whitespace, zero-width space, BOM | Denied as undeclared; not executed. Control: the bare server runs all 6 | `TestA04NameObfuscation` |
| A5 | JSON smuggling: duplicate `method`/`name`, case-variant keys (`METHOD`, `Name`, `PARAMS`), method `" Tools/Call "` | JSON-RPC error −32600/−32602; nothing forwarded. Control: the bare server runs `send_email` 6 times | `TestA05KeySmuggling` |
| A6 | Huge arguments: 100 KiB (> `max_args_bytes`) and 1 MiB (> `--max-message-bytes`) | First → policy deny; second → error without parsing. The stream stays in sync and the next call works | `TestA06HugeArguments` |
| A7 | Invalid JSON: truncated object, invalid UTF-8, two objects on one line | −32700 for each; nothing forwarded; proxy keeps working | `TestA07InvalidJSON` |
| A8 | Batch smuggling: `[echo, send_email]` after taint | Only `echo` forwarded; `send_email` denied inside a reply array | `TestA08BatchSmuggling` |
| A9 | `tools/call` as a notification (no `id`) | Dropped (the lenient server would run it) | `TestA09NotificationCall` |
| A10 | Injection delivered through a `notifications/message` log while a tool runs | Notification taints the session before delivery; the following sink call is denied | `TestA10InjectionViaNotification` |
| A11 | In-flight id reuse (`7` pending, call with `7.0`) so one response gets attributed to the wrong request | Rejected: "already in flight"; not executed | `TestA11InFlightIDReuse` |
| A12 | Trifecta spread over three servers/proxies | Denied with a shared `--session-file`. Without it, *not* detected (see LIMITATIONS) | `TestA12CrossServerTrifecta` |

Also covered end to end:
- ask modes (`TestAskModes`);
- dry run (`TestDryRunForwardsAndAudits`);
- audit contents, with no arguments logged unless `--log-args` (`TestAuditLogContents`);
- streaming of results larger than the message limit, with conservative tainting (`TestLargeResultPassesThrough`);
- exit-code propagation (`TestExitCodePropagates`);
- killing a server that ignores EOF after the 5 s grace period (`TestServerIgnoringEOFIsKilled`);
- refusing to start on an invalid policy (`TestInvalidPolicyRefusesToStart`).

Real servers (see [REAL_SERVERS.md](REAL_SERVERS.md)): a cross-server trifecta with server-filesystem and mcp-server-fetch, driven by the official Inspector CLI, is denied. The injection page's server log shows the exfiltration URL was never requested.

Unit level (`internal/proxy`):
- **MCP Tasks:**
  - a task-augmented call taints at `CreateTaskResult`;
  - `tasks/result`, `tasks/get`, `tasks/cancel` for unknown tasks fail closed;
  - `tasks/list` with an unknown task fails closed;
  - `task`/`TASK` key smuggling is rejected;
  - task-augmented sink calls are still denied (`TestTask*`).
- Kelvin-sign key folding;
- `notifications/cancelled` tainting;
- responses with unknown ids inheriting labels of pending tool calls;
- streaming of oversized server messages;
- byte-exact pass-through;
- `FuzzClientDifferential`: forwarded bytes never contain a `tools/call` that a lenient decoder reads as a denied tool.

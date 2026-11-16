# What ifcproxy v1 does not protect against

This is a list of attacks v1 does not stop, by design or by construction. Treat ifcproxy as one layer, not a sandbox.

## By design (the threat model)

1. **Over-blocking.** Taint is per session, not per value. Once a session holds `untrusted` and `private`, every external sink is blocked, including calls that carry no secret at all. There is no declassification. The only way to clear labels is a new session: restart the proxy, or delete the `--session-file`.
2. **Harm that needs no sink.** Injected instructions that delete files, corrupt data or make purchases through tools *not* marked `sink: external` are not blocked by the trifecta rule. Only per-tool rules (`when: [untrusted]` → `ask`/`deny`) can cover that, and only if you write them.
3. **The policy is the security boundary.**
   - A tool that returns attacker-controlled content without `produces: [untrusted]` is a hole.
   - So is a tool that can move data out without `sink: external`: writing into a synced folder, `git push`, an HTTP GET with a query string, a "read" tool that does a DNS lookup on its input.
   - ifcproxy trusts tool names. A malicious or buggy server can do anything inside any tool, and can exfiltrate by itself without a `tools/call`.
   - **Tools are identified by name only, not by server.** If several servers share one policy file, a server can claim another server's labels and rules by naming its tool the same (`fetch`, `read_file`). Give every server its own policy file (see `examples/servers/`).

## Content the proxy does not see or label

4. **Only `tools/call` results are labelled.** Server content from these is passed through without labels:
   - `resources/read`, `prompts/get`, `completion/complete`;
   - `initialize.instructions`;
   - tool descriptions in `tools/list` (tool poisoning).

   Server→client requests and notifications (`sampling/createMessage`, `elicitation/create`, logging) are labelled only while a tool call is pending. Then they inherit that call's labels.
5. **Content that enters through the client** is invisible: text the user pastes, files they attach, the host application's built-in tools, other MCP servers not behind an ifcproxy.
6. **Model generation is invisible.** The proxy cannot tell whether arguments were derived from tainted context. That is why taint is conservative and session-wide.

## Deployment gaps

7. **Separate proxies don't share labels by default.** With one proxy per server, a trifecta spread across servers (web server → filesystem server → mail server) is **not detected** unless every proxy gets the same `--session-file` (test A12 shows both cases). The shared file is never reset automatically.
8. **stdio only.** The Streamable HTTP transport is not supported.
9. **The client is trusted.** Anything that can start the MCP server without the proxy bypasses it. ifcproxy is not a sandbox and does not confine the server process.

## Implementation limits

10. **`ask` blocks the client→server stream** (including pings and cancellations) until the human answers or `--ask-timeout` expires. The prompt shows at most 512 bytes of arguments. Confirmation fatigue is a real risk.
11. **Windows console prompts:** after a timeout, the read on `CONIN$` may not be cancelled. A line typed later can be swallowed by the abandoned read instead of reaching the next prompt. Prefer `--ask-mode=deny|allow` for unattended use on Windows.
12. **Batches:** denied elements of a batch are answered in a separate JSON array. Strict JSON-RPC clients that expect exactly one batch response may mishandle that. MCP 2025-06-18 removed batching anyway.
13. **Oversized or unparseable server messages** are passed through. They are labelled with the union of the labels of all pending tool calls. If no tool call is pending, they get no labels.
14. **Arguments are not inspected,** apart from their size (`max_args_bytes`). No schema or value checks.
15. **Audit log:** stderr by default, not tamper-evident. A failing audit sink does not stop enforcement, and lost records are only reported at exit.
16. **`tools/list` is not filtered.** The model still sees undeclared tools and gets a denial when it calls them.
17. **MCP Tasks fail closed across sessions.** `tasks/result`, `tasks/get` and `tasks/cancel` for a task this proxy process did not see created carry every label. So does a `tasks/list` that lists one. Resuming tasks after a restart therefore taints the session fully. Tasks are experimental in the spec; only the 2025-11-25 shapes are handled.
18. **Side channels:** timing, which allowed tools get called, how many calls are made, and the fact that a call was denied are all observable. A low-bandwidth leak through them is not prevented.

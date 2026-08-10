# Appendix F — Extension Sketch: X-postgres (PostgreSQL MITM)

*Informative. Nothing here is normative for v1 (Part 10 §1). This appendix
parks the design so the exclusion is a decision with a shape, not a blank.
When X-postgres is drafted for real, it gets its own numbered part, its own
threat rows, and its own vectors — and starts from this sketch.*

## What it is

A sibling listener (Part 10's re-entry seam) speaking the PostgreSQL v3 wire
protocol. The workload connects with proxy-managed credentials; hematite
authenticates it, dials the real database with a DSN it alone holds, pins a
role on the upstream session, and rejects any client attempt to escape that
role. Paired with row-level security, this gives per-tenant data isolation
even when the application connects as one shared service account — the same
custody story as the `secrets` transform, applied to a second protocol.

## Mechanism (derived from the iron-proxy study)

1. **Handshake.** Accept the client's startup message (refusing SSLRequest /
   GSSENC upgrades in the first iteration), read the requested database name,
   and route to a configured upstream by that name. Authenticate the client
   against proxy-managed credentials — the workload never holds the real DSN.
2. **Upstream dial.** Connect using a DSN resolved from a secret source
   (the Part 04 §3.1 abstraction reused verbatim). Validate that the DSN
   names a database and that it matches the routing database, so a client
   cannot land on the wrong backend.
3. **Session setup.** Before relaying a single client byte: apply pinned
   session settings (via `set_config` with bound parameters), then inject
   `SET ROLE <role>` with a properly quoted identifier.
4. **Relay with a SQL gate.** Take over the raw socket and relay protocol
   messages bidirectionally. Every client `Query` (and `Parse`, see open
   questions) is classified by a SQL AST walk before forwarding.

## The role-escape gate

The classifier walks the parsed statement list and rejects, without
forwarding:

- `SET ROLE` / `SET SESSION AUTHORIZATION` (including `LOCAL`/`SESSION` forms)
- `RESET ROLE` / `RESET SESSION AUTHORIZATION` / `RESET ALL` (resets the pin)
- `set_config('role', …)` / `set_config('session_authorization', …)` with a
  literal first argument, anywhere in the query — including inside CTEs
- `DO $$ … $$` blocks entirely (opaque to the AST; too risky)
- `SET`/`RESET` touching any operator-pinned session variable
- Parse errors are **forwarded** — let the real server produce the error;
  the gate only needs to be sound for statements the server would accept.

Classification results are memoized (LRU on the exact SQL string), since
workloads repeat parameterized shapes.

## hematite-specific design intents

- **Typed classifier.** The gate is a pure function `SQL → Classification`
  in the kernel-purity style (INV-4): fully vectorizable, no I/O. The relay
  only forwards a `Query` by consuming a `Classified::Pass` proof — the
  INV-2 pattern applied to a second dialer.
- **Parsing dependency.** iron-proxy uses libpg_query via a Wasm binding;
  Rust has native bindings (`pg_query` crate, same underlying parser). This
  enters the Appendix E dependency budget conversation — it is the largest
  dependency the project would take, and the main cost of the feature.
- **Audit.** One record per classified statement batch under a `postgres`
  group (database, decision, rejected operation kind), same levels as Part
  08. Statement text is body-capture-grade sensitive: logged only under an
  explicit opt-in, never by default.

## Constraints and threats to carry into the real draft

- **Session pooling.** The pinned role lives on the upstream *session*. Any
  pooler between hematite and the database must run in session mode;
  transaction/statement pooling silently rebinds backends and defeats the
  pin. The draft must decide: document (iron-proxy's stance) or detect.
- **Extended protocol.** `Parse`/`Bind`/`Execute` messages carry SQL too;
  the gate must classify `Parse` payloads, not just simple `Query`.
- **TLS.** Client-side and upstream-side TLS for the Postgres leg
  (v1 sketch: refuse client SSLRequest; the real draft needs both).
- **COPY and replication modes** need explicit decisions (likely: allow
  `COPY`, refuse replication protocol).

## Why it stayed out of v1

A second wire protocol, a SQL parser dependency, and a distinct threat
model, sharing only config plumbing, secret sources, and audit with the HTTP
path. It would have doubled the v1 surface without strengthening the core
thesis demonstration.

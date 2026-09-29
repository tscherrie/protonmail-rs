# Authenticated, unattended hosting

This fork preserves all 56 mail tools. `--allow-writes` enables unattended
operations; an explicit `confirm:false` always requests a preview. The flag is
not a substitute for client authorization. Give bearer tokens only to trusted
agents: token holders can read, send and permanently delete mail.

HTTP requires `--http-token-file`, uses constant-time token comparison, and
rejects browser Origin headers. Bind the backend to loopback and publish it
through an HTTPS reverse proxy (for example Tailscale Serve). Set
`PROTON_MCP_ALLOWED_HOST` to its exact hostname and port, or a comma-separated
list of exact authorities when both private and public listeners are used.
Wildcards, URLs, user information and invalid ports are rejected.

With the operator's authorization, Tailscale Funnel can expose the bearer-protected
MCP to agents outside the tailnet. Funnel provides public HTTPS connectivity;
the MCP server still checks the bearer token on every request. Keep the backend
on loopback and retain the browser-origin and exact-host checks. Funnel supports
public ports 443, 8443 and 10000; 9443 can remain a private Serve listener.
For example, when both listeners use the same backend, configure
`PROTON_MCP_ALLOWED_HOST=node.example.ts.net:9443,node.example.ts.net:10000`.
Verify rejection of missing/incorrect tokens and authenticated MCP operation
through a public internet connection before sharing the endpoint with an agent.

`PROTON_ATTACHMENT_ROOT` confines attachment downloads. `dest_dir` is a relative
subdirectory, symlinks are rejected, and existing files are never overwritten.

The sample systemd unit runs as a dedicated `proton-mcp` account. Supply three
systemd encrypted credentials, bound to the host using `systemd-creds encrypt`:

- `store-key`: 32 random binary bytes for AES-256-GCM session storage.
- `http-token`: a cryptographically random bearer token (at least 32 characters).
- `bootstrap`: JSON with `username`, `password`, optional `totp_secret`, optional
  `mailbox_password`, and an appropriate Proton `app_version`.

No credential values belong in Git, shell arguments, logs, or a client example.
The service sees decrypted credentials only through systemd's credential mount.
Persistent session secrets are encrypted, authenticated, atomically replaced,
and restricted to the service account. Root access to the host remains trusted.

Normal token expiration uses Proton's refresh endpoint. An absent or revoked
session can trigger a fresh SRP login and TOTP from the bootstrap credential.
Recovery is rate-limited to one login attempt per ten minutes, persisted across process restarts. Provider account-protection, CAPTCHA and authentication failures persist a
stop flag in `PROTON_RECOVERY_STATE_FILE`; clear it only after resolving the
restriction. An
in-flight authentication failure invalidates the cached client; the next tool
call recovers automatically. Network failures do not trigger fresh login loops.
CAPTCHA, changed account credentials, disabled accounts and incompatible Proton
API changes can still require intervention. No software can promise permanent
unattended access against those provider-side changes.

The client sends a descriptive `protonmail-rs/<version>` User-Agent by default.
Authentication uses the canonical `/auth/v4/info`, `/auth/v4`, and
`/auth/v4/2fa` sequence used by Proton's Go library, without a preliminary
anonymous session. Authentication errors record only presence flags for
verification metadata; tokens and raw response bodies are not logged.
An error from one client alone does not establish an account-wide restriction.

For an explicit renewal check, `protonmail-cli --profile PROFILE --json
refresh-session` resumes the saved session and renews its tokens without
password login or recovery. Run it with the same encrypted-store configuration
and service account, while the MCP service is stopped: concurrent processes
must not independently rotate the same profile's refresh token. Restart the
service afterward and verify a mailbox read to test persisted-session resume.

The search index is **plaintext SQLite**, not encrypted. For hosted deployment,
mount its directory as a private `tmpfs` with `noswap`; disable process swapping
and core dumps, as in the sample unit. The index must be rebuilt after restart.
Attachment files intentionally persist in the service's private state directory.

Build with Rust 1.96 and Go 1.27.1. The fork uses Proton's GopenPGP backend rather
than the Rust OpenPGP backend. `vendor/gopenpgp-sys` is Proton's MIT-licensed
0.3.7 crate, with its Go dependency lock and vendored modules updated. Build with
`cargo build --release --workspace --locked`. Dependency updates are explicit;
do not automatically deploy a moving branch.

## MCP clients

HTTP-capable clients can connect to `https://YOUR_PRIVATE_HOST:PORT/mcp` with
`Authorization: Bearer <token>`. Keep the token out of shared configuration.
For clients needing stdio, `stdio-proxy.py --url https://.../mcp --token-file /private/path`
provides a dependency-free serial adapter. It does not follow HTTP redirects and
does not expose the token in process arguments. This server does not use MCP
sampling or elicitation callbacks; the adapter is intended for this service.
If the server discards an MCP transport session (HTTP 404), the adapter repeats
the initialization handshake and retries that rejected request once. This does
not log into Proton again. Authorization failures, timeouts and other server
errors are not retried, so an uncertain send is never automatically repeated.
Run `python3 -m unittest discover -s deploy -p 'test_stdio_proxy.py'` to check
session recovery and the no-retry conditions.

The MCP server can start and advertise tools before Proton authentication is
available. A successful initialize/tools-list exchange is not a mailbox health
check. Verify a read operation separately. No installation should be called
fully operational until a real mailbox read and session-resume test succeed.

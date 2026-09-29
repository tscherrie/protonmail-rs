# Private, unattended hosting

This fork preserves all 56 mail tools. `--allow-writes` enables unattended
operations; an explicit `confirm:false` always requests a preview. The flag is
not a substitute for client authorization. Give bearer tokens only to trusted
agents: token holders can read, send and permanently delete mail.

HTTP requires `--http-token-file`, uses constant-time token comparison, and
rejects browser Origin headers. Bind the backend to loopback and publish it
through a private HTTPS reverse proxy (for example Tailscale Serve). Set
`PROTON_MCP_ALLOWED_HOST` to its exact hostname and port. Do not use
an unauthenticated public proxy or Tailscale Funnel for this service.

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

The MCP server can start and advertise tools before Proton authentication is
available. A successful initialize/tools-list exchange is not a mailbox health
check. Verify a read operation separately. No installation should be called
fully operational until a real mailbox read and session-resume test succeed.

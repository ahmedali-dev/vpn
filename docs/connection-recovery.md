# Connection recovery (steps 1–3)

SSH+TLS and Xray/V2Ray share the same recovery controller in proxy and full-device modes.

- Each attempt refreshes upstream/proxy DNS, discovers the TLS certificate when required, then starts and verifies the transport. Discovery has a 45-second overall deadline. The session certificate pin and SSH first-use key remain fixed across retries.
- Transient failures retry with exponential delays of approximately 2, 4, 8, 16 and 30 seconds (20% jitter, capped at 30 seconds). Six consecutive failures stop the session. At least 60 seconds of connected service restores the failure budget; time spent connecting or cleaning up does not count.
- Rejected SSH/proxy credentials, changed or untrusted certificates/SSH keys, missing cores, invalid TUN configuration and permanent local I/O errors stop retries. Transport timeouts and connection loss remain retryable. External cores do not expose typed remote authentication failures; their generic startup exits remain bounded by the retry budget.
- Startup still requires a successful HTTPS check. Running sessions probe every 30 seconds, marking health degraded on a failed cycle and restarting after three consecutive failed cycles. A successful cycle clears the failure count. In TUN mode both proxy and system routes are checked.
- Only one probe cycle runs at a time. Core/SSH liveness checks continue every second during slow probes. Cancellation aborts and joins probe tasks before networking cleanup.

Saved session logs contain stage durations, attempt durations, connected time, retry delays and recovery timing. Authenticated status and diagnostics exports include bounded recovery metadata and the last failure, with credentials redacted. Existing logging file rotation and retention apply.

Tests use local TLS/SSH servers and simulated health/liveness failures. Live Windows/Linux TUN routing, network switching, and suspend/resume need platform validation. Network-change detection, endpoint failover and protocol/MTU tuning are later work.

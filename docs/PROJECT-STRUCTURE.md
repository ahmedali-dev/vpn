# TunnelNest feature and service guide

Start with this guide when you want to change a feature. Each source file begins with a short comment explaining its responsibility. Public root exports in `src/lib.rs` keep existing integrations working while implementations live in the folders below.

```text
src/
  main.rs                         CLI and native-app entry point
  lib.rs                          Public exports and compatibility aliases
  features/                       Application behavior and business rules
    configuration/
      mod.rs                      CLI/profile option validation
      protocols.rs                VMess/VLESS/Trojan/SS link parsing and SNI rules
    connections/
      mod.rs                      Feature exports
      session.rs                  Start, stop, cancellation and task ownership
      preparation.rs              Resolve upstreams and prepare exclusions
      orchestrator.rs             Retry loop and network-change handling
      attempt.rs                  One SSH/Xray/TUN attempt and cleanup
      health.rs                   HTTPS/DNS readiness and ongoing health checks
      forwarding.rs               SSH SOCKS TCP forwarding
      core_logs.rs                Capture and classify external-core output
      status.rs                   Session state, reporting and redaction
      pac.rs                      Proxy auto-configuration feature
      tests.rs                    Recovery/startup/forwarding regression tests
    profiles/
      model.rs                    Saved profile fields and serialization contract
      service.rs                  Pure save validation and credential omission rules
      sharing.rs                  Portable code/file sharing and password protection
      mod.rs                      Profile feature exports
    routing.rs                    Ordered direct/proxy/block policy
    recovery.rs                   Retry, backoff and permanent-failure policy
    tun.rs                        Validated virtual addresses and stack settings
    traffic.rs                    Independent upstream-failure tracking
    diagnostics.rs                Read-only profile checks and sanitized reports
    notifications.rs              Preferences and deduplicated notification policy
  infrastructure/                 Storage, crypto, OS and external-core services
    persistence.rs                Encrypted SQLite repository and vault access
    cryptography.rs               Randomness, key derivation and AES-GCM
    logging.rs                    Private bounded log files and credential redaction
    network.rs                    Read-only physical/TUN/route observations
    privileges.rs                 OS privilege query
    hostname.rs                   TLS/HTTP initial-packet hostname recovery
    cores/
      xray.rs                     Generate proxy-core configuration
      tun.rs                      Generate sing-box capture/DNS/routing configuration
      process.rs                  Core validation, launch, stop and lifecycle
      mod.rs                      Binary discovery and core-service exports
    transport/
      tls.rs                      Certificate policy, handshakes and pins
      http_proxy.rs               Custom payloads and HTTP CONNECT responses
      ssh.rs                      Upstream transport, host-key checks and authentication
      mod.rs                      Shared stream type and transport exports
  interfaces/                     Entry adapters, not profile business rules
    control/
      mod.rs                      Shared control state and public interface
      service.rs                  Session and elevated-helper coordination
      http.rs                     Request DTOs, authentication and origin/host guards
      api.rs                      Map API requests to application operations
      helper.rs                   Authenticated helper client and log mirroring
      assets.rs                   Explicit bundled-file allowlist
      server.rs                   Listener, helper leases and ready-file lifecycle
      diagnostics.rs              Safe status projection
      tests.rs                    Authentication and helper regression tests
    desktop.rs                    Tauri window, validated IPC and OS dialogs
    macos_notifications.rs        Native macOS notification adapter

desktop/ui/
  app.js                          Startup only; loads after feature controllers
  script-manifest.json            Ordered application script list used by tests
  shared/state.js                 Shared page state and control API adapter
  features/
    profile-editor.js             Import/display/reset profile form values
    profile-library.js            Saved rows, selection and profile actions
    profile-arguments.js          Map form values to canonical CLI arguments
    connection.js                 Start, stop and native elevation requests
    activity.js                   Poll/render live connection activity
    saved-logs.js                 Persisted log viewer
    diagnostics.js                Diagnostic dialogs and exports
    notifications.js              Native notification settings
    sharing.js                    Code/file/QR sharing and import
    vault.js                      Vault unlock controller
    trust.js                      Trust labels and verified-fingerprint workflow
    dashboard.js                  Connection summary presenter
    navigation.js                 Sidebar, menus and drop targets
  profile-options.js              Pure argument/routing/link editing utilities
  profile-input.js                Bounded imported-content classification
  dropdowns.js                    Shared custom-select widget
```

## Where a change belongs

Change application decisions in `features/`: validation, SNI interpretation, retry policy, routing order, health criteria and notification transitions. Use `infrastructure/` for database queries, cryptography, network inspection, TLS/SSH IO and external process operations. Use `interfaces/` for HTTP/IPC authorization, request/response mapping and OS integration. UI controllers render state and request operations through `api()`; backend validation remains authoritative.

For example, adding a new profile option usually touches configuration validation, its UI form/argument controller, and portable sharing if the flag should be exported. A connection recovery change belongs in the connection feature and recovery policy, rather than in the window controller. A database column change belongs in persistence and the profile serialization contract.

This is a pragmatic module structure: orchestration calls technical services directly. It does not introduce a dependency-injection framework. Each extracted Rust service declares its imports explicitly; sibling helpers stay private to their feature.

## Comments you can extend

Use a file header like this for a new service:

```rust
//! Profile verification service.
//!
//! Purpose: validate a profile before any network operation.
//! Inputs: validated profile options. Output: a verification result.
//! Side effects: none. Called by the control API and tests.
```

Add comments beside decisions that explain *why* the rule exists: for example, why a changed SSH key is rejected or why a direct routing rule permits a different system exit IP. Avoid comments that merely repeat a function name. Keep schema, encryption AAD, control authentication, host-key verification, route ownership and cancellation/cleanup rules unchanged during organizational edits.

## UI module loading

Application controllers are strict classic scripts sharing the existing page state; they are not independent ES modules. Keep their declared order when changing dependencies. Add a new controller to all three places: `script-manifest.json`, the script tags in `index.html`, and the explicit allowlist in `src/interfaces/control/assets.rs`. `app.js` must remain last. The manifest/HTML order test, separate-script VM test and HTTP asset test cover this contract. QR vendor files retain their licenses and remain separate from application controllers.

## Compatibility

Existing paths such as `tunnelnest::runtime::Session`, `tunnelnest::config::Config`, `tunnelnest::store::Store` and `tunnelnest::transport::connect_ssh` remain exported from `src/lib.rs`. The refactor does not rename CLI flags, API routes, serialized profile fields, share-code formats, SQLite tables or OS configuration directories.

## Verification

Run `cargo fmt --all --check`, strict Clippy and `cargo test --profile ci --locked --features desktop`. Run the desktop Node tests and Python tooling suite as before. Native Windows/Linux/macOS authorization and live full-device routing still require real-device acceptance testing; a source refactor and local fixtures do not certify those behaviors.

## Optional shared library and updates

- `src/features/updates.rs`: manual GitHub release comparison and fixed release URLs.
- `src/infrastructure/mongo_library.rs`: MongoDB TLS, encrypted records, passphrase verification and keychain settings.
- `src/interfaces/control/library.rs`: shared-library API use cases and bounded network waits.
- `desktop/ui/features/cloud-library.js` and `updates.js`: independent settings and update dialogs.
- `tests/mongo_library.rs`: isolated driver wire fixture; no external database credentials.

# Shared connection library and updates

Open **Shared library** in Connection library. Provide your MongoDB URI, database, collection, library ID and a library passphrase of at least 12 characters. Use the exact same settings on each device. Database, collection and library IDs accept letters, digits, hyphens and underscores. The MongoDB account needs find, update/upsert and delete permission in the selected collection.

Remote databases require verified TLS (`mongodb+srv://` normally enables it; for `mongodb://`, add `tls=true`). Invalid-certificate options are rejected. Plaintext is permitted only for loopback development servers. TunnelNest does not provision a database or change its access rules.

Settings last for the app session by default. **Remember** saves the URI and passphrase only to the operating system keychain; there is no plaintext fallback. **Load saved settings** explicitly reads that keychain on another session. **Forget saved settings** removes the remembered configuration; disconnect separately to drop the current library session. Losing the passphrase means losing access to encrypted shared profiles.

To upload a connection, select **Also save this profile to the encrypted MongoDB shared library** while saving the profile. **Remember credentials** must be enabled: session-only passwords are never uploaded. The local SQLite save happens first, and a remote failure leaves that local profile available. Retrying the same local profile updates its stable shared record rather than creating duplicates. The upload checkbox resets for each editor session.

On another device, connect to the library, press **Refresh**, then **Save locally** for each wanted profile. Import validates the profile and saves it in the local encrypted vault without starting a connection. An unlocked local vault is required. Each import makes a local copy; changes propagate only when explicitly saved to MongoDB. The last successful shared save wins. There is no background synchronization or conflict merging.

Local deletion does not delete shared records. **Delete shared** asks before removing a record for all devices and leaves existing local copies intact. A later explicit upload of a local copy can restore the shared record.

Names, credentials and complete profile configuration use AES-256-GCM authenticated encryption before upload. A scrypt-derived library key is separate from every device's local vault key. Scope and record identity are authenticated; an encrypted verifier detects a wrong passphrase. The database sees random record IDs, library scope hashes, timestamps and ciphertext sizes. Use a unique strong passphrase and restrict database access. MongoDB is not a substitute for a trusted library passphrase.

Operations have a bounded UI wait. A timed-out write may still finish on the server; refresh or retry the same profile to resolve uncertain delivery. Driver errors are sanitized to avoid exposing URI credentials.

**Check for updates** sends a manual request to this project's public GitHub latest-release API. It compares stable numeric versions, displays release notes as text and opens the fixed project release page in your system browser when a newer version exists. It never downloads or installs executables automatically.

Validation includes an isolated local MongoDB wire-protocol fixture with the official driver. It checks cross-device decryption, wrong-passphrase rejection, repeated uploads and local imports. This fixture does not certify Atlas, authentication or replica-set behavior; validate those against your own MongoDB deployment.

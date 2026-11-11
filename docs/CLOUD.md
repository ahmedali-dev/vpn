# Public cloud library

No cloud account or sign-in is required. All users share one public list and may download its credentials, add/edit records or delete records. Upload only server accounts intended for public sharing.

## App buttons

- **Refresh from cloud** downloads the public servers into the encrypted local profile vault. Unlock the local vault first; this local password protects your device and is unrelated to cloud access.
- **Upload to cloud** (↑ on a profile) publishes its credentials after a destination/public-sharing confirmation. Retrying updates the same cloud record.
- **Delete from cloud** (☁ × on a profile) deletes the shared record for everyone and retains the local copy.
- **Cloud library** lets you change the public API URL. No username or password is requested.

Refresh skips profiles with unsynced local edits. Upload explicitly to replace the shared copy. Local deletion does not delete cloud records, and cloud deletion does not erase local copies. Refresh never starts a VPN. Unsupported local-file references must be removed before upload; core executable paths are omitted from portable codes. SSH private-key-only records are unsupported by this tunnel engine.

## Builds and deployment

Set the TunnelNest repository **variable** `CLOUD_API_URL` to the deployed management origin, e.g. `https://management.example.com`. GitHub Actions passes it to `TUNNEL_CLOUD_URL`, which is embedded in desktop builds. For a local build, export `TUNNEL_CLOUD_URL` before running the macOS build script. If unset, the local development default is `http://127.0.0.1:3000`.

Remote origins require verified HTTPS. Loopback HTTP is allowed for development. Redirects are refused. The desktop never needs or receives `MONGODB_URI`.

ManagementServer reads `MONGODB_URI` and its credential encryption key at runtime. Put these in the host's secret manager. The backend repository's manual **Check configured MongoDB** Action reads the `production` environment secret `MONGODB_URI` and performs only a connection ping. Do not put the database URI into desktop build variables, Rust source, image build arguments, or distributable files.

The management website remains owner-only. Anonymous API calls are restricted to records explicitly marked public; old private server records are never automatically published. New servers created on the management site are public. Configure and redeploy the updated ManagementServer before distributing the app's API URL.

Cloud credentials are encrypted in MongoDB but deliberately downloadable through the public API. Anyone can remove public records. Keep local copies or backups and use only accounts intended for public access.

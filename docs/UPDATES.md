# Check for updates

Choose **Check for updates** in Connection library to manually check the latest stable TunnelNest release on GitHub. The app compares numeric versions, displays release notes as plain text and offers to open the project release page in your system browser when a newer version is available.

Updates are downloaded and installed manually. A failed check leaves local profiles and connections available.

Connection profiles are stored in the local encrypted SQLite vault. MongoDB integration has been removed. Existing local profiles and manual QR/code/file sharing remain available; no MongoDB URL is required in GitHub Actions.

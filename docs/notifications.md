# Desktop notifications

Open **Notifications** in the sidebar, enable notifications, and save preferences. Notifications are disabled by default. Use **Send test notification** to check delivery. Choose connection updates, problems/reconnects, and whether notifications should appear only while the app is in the background. Preferences persist in the user configuration directory beside the profile database as `notifications.json`.

The native Rust watcher runs while the desktop app is open, including when minimized. It observes the same authenticated connection status as the dashboard. It announces verified connection/recovery, manual disconnecting and completed disconnection, the first reconnect or degraded health in an outage, terminal failures, unexpected disconnection, and three consecutive local control-service failures. Retry notifications are deduplicated; repeated event types have a cooldown. Initial status is a baseline, so restarting the app does not replay old events. User-requested disconnect emits progress and completion alerts under connection updates; application shutdown is quiet; a cleanup error can still produce a terminal failure alert.

All messages use fixed generic text. Profile names, server addresses, credentials, raw errors and logs never enter notification bodies. Delivery failure does not interrupt the VPN. The test response confirms submission only: notification services can suppress banners because of system preferences or Do Not Disturb.

## Platforms

- **Windows:** the app registers its own `org.tunnelnest.rust` AppUserModelID with display name and a cached icon under `HKEY_CURRENT_USER\Software\Classes\AppUserModelId` when notifications are enabled. This supports the portable Windows distribution without administrator access. System notifications must be enabled for the app. Registry identity remains after disabling notifications; the application stops sending them.
- **macOS:** a native `UNUserNotificationCenter` bridge checks real authorization, requests permission when enabling/testing, reports scheduling errors, and presents banners while the app is focused. Use the app bundle whose identifier matches `org.tunnelnest.rust`. Check System Settings → Notifications. Standalone executables report a missing app identity; launch `TunnelNest.app` to request permission and deliver notifications. If permission was denied earlier, enable TunnelNest in System Settings → Notifications and retry the test.
- **GNOME and KDE Plasma:** notification delivery uses the session D-Bus `org.freedesktop.Notifications` service provided by the desktop.
- **Hyprland and niri:** run a notification daemon such as mako, dunst or swaync in the user session. Avoid running competing notification servers. The app does not install or change the compositor's startup configuration. For Hyprland, a typical existing-session configuration is `exec-once = mako`; for niri, `spawn-at-startup "mako"`. Use the daemon you already selected for your desktop.

This adds notification support to the macOS source build; release CI continues to build Windows and Linux only. The browser control page does not provide native notifications.

## Acceptance testing

On Windows, macOS, GNOME, KDE, Hyprland and niri:

1. Enable and save notifications, send a test, and verify the app name/icon and native banner. Confirm system notification history if a banner is suppressed.
2. Reopen settings and restart the app; preferences should persist without replaying old status.
3. Connect a working profile and verify one connected notification. Interrupt the network and verify one reconnect/problem alert per outage, followed by recovery when connectivity passes. Retry attempts should not create a notification flood.
4. Trigger a terminal connection failure and verify a generic failure message without the profile name, server address or raw error.
5. Disconnect normally: verify disconnecting and disconnected alerts without an unexpected-disconnect warning. Close the app and verify shutdown stays quiet. Quick recovery should produce a reconnected alert even when the intermediate retry state is too brief for a status poll.
6. Disable connection updates and then problems separately, and verify filtering. Test background-only both with the main window focused and minimized.
7. Disable all notifications and verify quiet operation while connection controls still work. On Linux, stop the notification daemon and verify VPN operation continues; restart it and use the test button again.

Automated tests cover event transitions, deduplication, rate limits, privacy, preference persistence, failed persistence, bridge commands and UI settings. Native display, OS policy, Windows registration and compositor behavior need the manual checks above on their actual platforms.

References: [Tauri notification plugin](https://v2.tauri.app/plugin/notification/), [freedesktop notification specification](https://specifications.freedesktop.org/notification/latest-single/), [Hyprland notification daemon](https://wiki.hypr.land/Useful-Utilities/Must-have/), [niri important software](https://github.com/niri-wm/niri/wiki/Important-Software).

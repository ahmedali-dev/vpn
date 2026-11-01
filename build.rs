fn main() {
    #[cfg(feature = "desktop")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/macos_notifications.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=11.0")
            .compile("tunnelnest_notifications");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=UserNotifications");
        println!("cargo:rerun-if-changed=native/macos_notifications.m");
    }
    #[cfg(feature = "desktop")]
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&[
                "control_request",
                "connect_full_device",
                "save_shared_profile",
                "notification_preferences",
                "test_notification",
            ]))
            .windows_attributes(
                tauri_build::WindowsAttributes::new()
                    .window_icon_path("desktop/assets/tunnelnest.ico"),
            ),
    )
    .expect("build Tauri desktop configuration");
}

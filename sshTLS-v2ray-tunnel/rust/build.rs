fn main() {
    #[cfg(feature = "desktop")]
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&[
                "control_request",
                "connect_full_device",
                "save_shared_profile",
            ]))
            .windows_attributes(
                tauri_build::WindowsAttributes::new()
                    .window_icon_path("desktop/assets/tunnelnest.ico"),
            ),
    )
    .expect("build Tauri desktop configuration");
}

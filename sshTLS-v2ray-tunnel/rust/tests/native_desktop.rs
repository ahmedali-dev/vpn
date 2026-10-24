#![cfg(feature = "desktop")]
use serde_json::json;
use tunnelnest::desktop::share_file_bytes;
#[test]
fn native_exports_validate_content_and_sanitize_names() {
    let (name, extension, data) =
        share_file_bytes(&json!({"name":"a/b","format":"profile","code":"TN2.ABC_xyz"})).unwrap();
    assert_eq!(name, "TunnelNest-a-b.tnprofile");
    assert_eq!(extension, "tnprofile");
    assert_eq!(data, b"TN2.ABC_xyz\n");
    for value in [
        json!({"format":"profile","code":"file:///tmp/secret"}),
        json!({"format":"qr","image":"data:text/plain;base64,AAAA"}),
        json!({"format":"qr","image":"data:image/png;base64,AAAA"}),
        json!({"format":"bad"}),
    ] {
        assert!(share_file_bytes(&value).is_err());
    }
}

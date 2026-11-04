//! macOS notification adapter.
//!
//! Bridges private notification requests to the native macOS notification service.

//! Apple's permission and delivery callbacks, bridged without blocking the UI thread.
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    time::Duration,
};
use tokio::sync::oneshot;

type Sender = oneshot::Sender<std::result::Result<i32, String>>;
type Callback = unsafe extern "C" fn(*mut c_void, c_int, *const c_char);
unsafe extern "C" {
    fn tn_notification_authorization(request: c_int, context: *mut c_void, callback: Callback);
    fn tn_notification_send(
        title: *const c_char,
        body: *const c_char,
        context: *mut c_void,
        callback: Callback,
    );
}
unsafe extern "C" fn completion(context: *mut c_void, status: c_int, error: *const c_char) {
    // The native bridge takes ownership of one boxed sender and calls exactly once.
    let sender = unsafe { Box::from_raw(context.cast::<Sender>()) };
    let result = if status < 0 {
        let message = if error.is_null() {
            "macOS notification request failed".into()
        } else {
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        Err(message)
    } else {
        Ok(status)
    };
    let _ = sender.send(result);
}
async fn response(receiver: oneshot::Receiver<std::result::Result<i32, String>>) -> Result<i32> {
    // The callback owns its sender even if the requester times out or closes the dialog.
    tokio::time::timeout(Duration::from_secs(60), receiver)
        .await
        .context(
            "macOS notification request timed out; check the permission dialog and System Settings",
        )?
        .context("macOS notification callback was closed")?
        .map_err(anyhow::Error::msg)
}
pub async fn authorization(request: bool) -> Result<&'static str> {
    let (sender, receiver) = oneshot::channel();
    unsafe {
        tn_notification_authorization(
            i32::from(request),
            Box::into_raw(Box::new(sender)).cast(),
            completion,
        );
    }
    Ok(match response(receiver).await? {
        0 => "not_determined",
        1 => "denied",
        2 => "authorized",
        3 => "provisional",
        _ => "unknown",
    })
}
pub async fn request_permission() -> Result<()> {
    let state = authorization(true).await?;
    if !matches!(state, "authorized" | "provisional") {
        bail!(
            "macOS notifications are {state}. Enable TunnelNest in System Settings > Notifications, then save again."
        );
    }
    Ok(())
}
pub async fn send(title: &str, body: &str) -> Result<()> {
    let title = CString::new(title)?;
    let body = CString::new(body)?;
    let (sender, receiver) = oneshot::channel();
    // Native code copies both UTF-8 strings before this call returns.
    unsafe {
        tn_notification_send(
            title.as_ptr(),
            body.as_ptr(),
            Box::into_raw(Box::new(sender)).cast(),
            completion,
        );
    }
    response(receiver).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn standalone_executables_report_missing_identity_without_prompting() {
        let error = authorization(false).await.unwrap_err().to_string();
        assert!(error.contains("TunnelNest.app"), "{error}");
        let error = send(
            "Test",
            "No native banner should be requested from a unit test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("app identity"), "{error}");
    }
}

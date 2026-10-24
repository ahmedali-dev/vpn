use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tunnelnest::{
    config::{BOOL_FLAGS, Config, VALUE_FLAGS},
    control,
    runtime::Session,
};

fn main() {
    #[cfg(feature = "desktop")]
    if std::env::args().len() == 1 || std::env::args().nth(1).as_deref() == Some("--desktop") {
        if let Err(e) = tunnelnest::desktop::run() {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    let runtime = tokio::runtime::Runtime::new().expect("create async runtime");
    runtime.block_on(async {
        if let Err(e) = entry().await {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    });
}
async fn entry() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .iter()
        .any(|s| ["-h", "--help", "-help"].contains(&s.as_str()))
    {
        println!(
            "TunnelNest {} (Rust)\n\nUsage: tunnel -ui\n       tunnel -mode ssh -H HOST -P PORT -u USER -p PASSWORD [-S SNI]\n       tunnel -mode xray -v2ray-link LINK\n\nAccepts the original single-dash options and double-dash aliases.\n\nValue options:",
            env!("CARGO_PKG_VERSION")
        );
        for flag in VALUE_FLAGS {
            println!("  -{flag} VALUE");
        }
        println!("\nBoolean options:");
        for flag in BOOL_FLAGS {
            println!("  -{flag}");
        }
        return Ok(());
    }
    if args == ["--version"] || args == ["-version"] {
        println!("TunnelNest {} (Rust)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let cfg = Config::parse(&args)?;
    #[cfg(unix)]
    if cfg.boolean("ui") && !cfg.boolean("ui-helper") && tunnelnest::runtime::is_admin() {
        if let Ok(uid) = std::env::var("SUDO_UID")
            && uid != "0"
            && uid.parse::<u32>().is_ok()
        {
            let status = tokio::process::Command::new("sudo")
                .args(["-u", &format!("#{uid}"), "-H", "--"])
                .arg(std::env::current_exe()?)
                .args(&args)
                .env_remove("XDG_CONFIG_HOME")
                .kill_on_drop(true)
                .status()
                .await?;
            anyhow::ensure!(status.success(), "user interface exited with {status}");
            return Ok(());
        }
        anyhow::bail!(
            "start the desktop interface as your normal user; use -ui-helper for the elevated networking helper"
        )
    }
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    tokio::spawn(async move {
        wait_signal().await;
        shutdown.cancel();
    });
    if cfg.boolean("ui") {
        control::serve(cfg, cancel).await
    } else {
        let mut session = Session::start(cfg);
        let mut previous = String::new();
        loop {
            tokio::select! {_=cancel.cancelled()=>{session.stop().await;break},_=tokio::time::sleep(std::time::Duration::from_millis(250))=>{
                let status=session.report.snapshot();let log=status["logs"].as_str().unwrap_or("");if log!=previous{if let Some(new)=log.strip_prefix(&previous){eprint!("{new}");}else{eprint!("{log}");}previous=log.into();}
                if !session.active(){anyhow::ensure!(status["state"]!="error","{}",status["error"].as_str().unwrap_or("connection failed"));break;}
            }}
        }
        Ok(())
    }
}
async fn wait_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>(),_=term.recv()=>()}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

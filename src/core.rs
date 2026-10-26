use crate::config::{Config, Protocol};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{io::Write, path::PathBuf};
use tempfile::NamedTempFile;
use tokio::process::{Child, Command};

pub fn find_core(explicit: &str, names: &[&str]) -> Result<PathBuf> {
    if !explicit.is_empty() {
        return Ok(PathBuf::from(explicit));
    }
    let exe = std::env::current_exe()?;
    let parent = exe.parent().context("no executable directory")?;
    for name in names {
        let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        for dir in [parent.join("cores"), parent.into()] {
            let path = dir.join(&filename);
            if path.is_file() {
                return Ok(path);
            }
        }
        if let Some(paths) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&paths) {
                let path = dir.join(&filename);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    bail!(
        "required core {} not found; set its binary path or put it in cores/ beside tunnel",
        names.join("/")
    )
}
pub fn xray_config(c: &Config, p: &Protocol, pin: Option<&str>) -> Value {
    let addr = c.get("dial-address", &p.address);
    let settings = match p.protocol.as_str() {
        "vmess" => {
            json!({"vnext":[{"address":addr,"port":p.port,"users":[{"id":p.uuid,"alterId":0,"security":p.cipher}]}]})
        }
        "vless" => {
            json!({"vnext":[{"address":addr,"port":p.port,"users":[{"id":p.uuid,"encryption":"none","flow":p.flow}]}]})
        }
        "trojan" => json!({"servers":[{"address":addr,"port":p.port,"password":p.uuid}]}),
        _ => {
            json!({"servers":[{"address":addr,"port":p.port,"password":p.uuid,"method":"aes-256-gcm"}]})
        }
    };
    let mut stream = json!({"network":p.network,"security":p.security});
    match p.network.as_str() {
        "ws" => {
            stream["wsSettings"] = json!({"path":p.path});
            if !p.host.is_empty() {
                stream["wsSettings"]["headers"] = json!({"Host":p.host});
            }
        }
        "grpc" => stream["grpcSettings"] = json!({"serviceName":p.service_name,"multiMode":false}),
        "http" | "h2" => {
            stream["httpSettings"] = json!({"path":p.path});
            if !p.host.is_empty() {
                stream["httpSettings"]["host"] = json!([p.host]);
            }
        }
        "httpupgrade" => stream["httpupgradeSettings"] = json!({"host":p.host,"path":p.path}),
        "xhttp" => stream["xhttpSettings"] = json!({"host":p.host,"path":p.path}),
        _ => stream["tcpSettings"] = json!({"header":{"type":"none"}}),
    }
    if p.security == "tls" {
        let mut tls = json!({"serverName":p.sni});
        if let Some(pin) = pin {
            tls["pinnedPeerCertSha256"] = json!(pin);
        }
        if !p.fingerprint.is_empty() && p.fingerprint != "none" {
            tls["fingerprint"] = json!(p.fingerprint);
        }
        if !p.alpn.is_empty() {
            tls["alpn"] = json!(p.alpn);
        }
        if let Some(v) = match c.get("tls-version", "auto") {
            "tls1.2" => Some("1.2"),
            "tls1.3" => Some("1.3"),
            _ => None,
        } {
            tls["minVersion"] = json!(v);
            tls["maxVersion"] = json!(v);
        }
        stream["tlsSettings"] = tls;
    } else if p.security == "reality" {
        stream["realitySettings"] = json!({"serverName":p.sni,"fingerprint":if p.fingerprint.is_empty(){"chrome"}else{&p.fingerprint},"password":p.reality_public_key,"shortId":p.reality_short_id,"show":false});
    }
    json!({"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":c.socks_port(),"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":p.protocol,"settings":settings,"streamSettings":stream},{"protocol":"freedom","tag":"direct"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","outboundTag":"direct","domain":["geosite:private"]}]}})
}
pub fn tun_config(c: &Config, excluded: &[String], platform: &str) -> Value {
    let ssh = c.mode() == "ssh";
    let ipv4 = ssh && c.boolean("ssh-ipv4-only");
    let mut inbound = json!({"type":"tun","tag":"device","address":["172.30.111.1/30","fdfe:dcba:9876::1/126"],"mtu":1500,"auto_route":true,"strict_route":true,"route_exclude_address":excluded});
    if platform == "linux" {
        inbound["auto_redirect"] = json!(true);
    }
    let mut outbound = json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":c.socks_port(),"version":"5"});
    let mut rules = vec![json!({"port":53,"action":"hijack-dns"})];
    if ssh {
        outbound["network"] = json!("tcp");
        rules.push(json!({"network":"udp","action":"reject"}));
    }
    // HTTPS/SVCB records can contain IPv6 hints even when AAAA is filtered.
    // Empty successful answers let clients fall back to ordinary IPv4 DNS.
    let dns_rules = if ipv4 {
        vec![json!({"query_type":["AAAA","HTTPS","SVCB"],"action":"predefined","rcode":"NOERROR"})]
    } else {
        vec![]
    };
    json!({"log":{"level":"info","timestamp":true},"inbounds":[inbound],"outbounds":[outbound],"dns":{"servers":[{"type":"tcp","tag":"tunnel-dns","server":"1.1.1.1","detour":"proxy"}],"rules":dns_rules,"final":"tunnel-dns","strategy":if ipv4{"ipv4_only"}else{"prefer_ipv4"}},"route":{"auto_detect_interface":true,"rules":rules,"final":"proxy"}})
}
pub struct CoreProcess {
    child: Option<Child>,
    _config: Option<NamedTempFile>,
}
impl CoreProcess {
    pub async fn start(
        binary: PathBuf,
        config: Option<Value>,
        custom: &str,
        sing_box: bool,
    ) -> Result<Self> {
        let file = if let Some(config) = config {
            let mut f = tempfile::Builder::new()
                .prefix("tunnelnest-")
                .suffix(".json")
                .tempfile()?;
            f.write_all(&serde_json::to_vec_pretty(&config)?)?;
            f.flush()?;
            Some(f)
        } else {
            None
        };
        let path = file
            .as_ref()
            .map(|f| f.path())
            .unwrap_or_else(|| std::path::Path::new(custom));
        if sing_box {
            let out = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                Command::new(&binary)
                    .args(["check", "-c"])
                    .arg(path)
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            ensure!(
                out.status.success(),
                "TUN config validation failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let mut cmd = Command::new(binary);
        cmd.arg("run")
            .arg(if sing_box { "-c" } else { "-config" })
            .arg(path)
            .kill_on_drop(false)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        Ok(Self {
            child: Some(cmd.spawn()?),
            _config: file,
        })
    }
    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("live core child")
    }
    pub async fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            stop_child(child).await;
        }
    }
}
async fn stop_child(mut child: Child) {
    #[cfg(unix)]
    if let Some(id) = child.id() {
        unsafe {
            libc::kill(id as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.start_kill();
    }
    if tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}
impl Drop for CoreProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let config = self._config.take();
                runtime.spawn(async move {
                    stop_child(child).await;
                    drop(config);
                });
            } else {
                let mut child = child;
                let _ = child.start_kill();
            }
        }
    }
}

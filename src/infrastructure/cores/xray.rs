//! Networking core xray service.
//!
//! Generates Xray transport/TLS/protocol settings from validated connection data.

use crate::config::Config;
use crate::config::Protocol;
use serde_json::Value;
use serde_json::json;

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
            json!({"servers":[{"address":addr,"port":p.port,"password":p.uuid,"method":p.cipher}]})
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
        "xhttp" => {
            stream["xhttpSettings"] = json!({"host":p.host,"path":p.path,"mode":p.xhttp_mode});
            if !p.xhttp_extra.is_null() {
                stream["xhttpSettings"]["extra"] = p.xhttp_extra.clone();
            }
        }
        _ => stream["tcpSettings"] = json!({"header":{"type":"none"}}),
    }
    if p.security == "tls" {
        let mut tls = json!({"serverName":p.effective_sni});
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
        stream["realitySettings"] = json!({"serverName":p.effective_sni,"fingerprint":if p.fingerprint.is_empty(){"chrome"}else{&p.fingerprint},"password":p.reality_public_key,"shortId":p.reality_short_id,"spiderX":p.reality_spider_x,"show":false});
    }
    let mut config = json!({"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":c.socks_port(),"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":p.protocol,"settings":settings,"streamSettings":stream},{"protocol":"freedom","tag":"direct"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","outboundTag":"direct","domain":["geosite:private"]}]}});
    if c.boolean("block-quic") {
        config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"protocol":"blackhole","tag":"block-quic"}));
        config["routing"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({"type":"field","network":"udp","port":"443","outboundTag":"block-quic"}),
        );
    }
    config
}

//! Public HTTPS cloud client. MongoDB credentials never enter the app.
use crate::{config::Config, sharing, store::Profile};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    pub url: String,
}
pub struct Cloud {
    client: reqwest::Client,
    base: url::Url,
    pub scope: String,
}
pub fn default_url() -> String {
    option_env!("TUNNEL_CLOUD_URL")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("http://127.0.0.1:3000")
        .to_owned()
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub private_key: String,
    pub link: String,
    pub profile_code: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub protocol: String,
    #[serde(default)]
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u32,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub notes: String,
    pub credentials: Credentials,
}
fn default_port() -> u32 {
    443
}
pub fn base_url(raw: &str) -> Result<url::Url> {
    let u = url::Url::parse(raw).context("Enter the management server URL")?;
    let local = u.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        u.scheme() == "https" || (u.scheme() == "http" && local),
        "Cloud requires HTTPS; HTTP is allowed only for local development"
    );
    ensure!(
        u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/",
        "Enter only the server origin, without credentials or a path"
    );
    Ok(u)
}
async fn response(mut r: reqwest::Response) -> Result<Value> {
    let status = r.status();
    ensure!(
        status.is_success(),
        "{}",
        if status == reqwest::StatusCode::UNAUTHORIZED {
            "Cloud access was rejected by the server."
        } else {
            "Cloud request failed. Check the server configuration and account access."
        }
    );
    let mut bytes = vec![];
    while let Some(chunk) = r.chunk().await.context("Cloud response interrupted")? {
        ensure!(
            bytes.len() + chunk.len() <= 2 * 1024 * 1024,
            "Cloud response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("Invalid cloud response")
}
impl Cloud {
    pub async fn connect(input: Connect) -> Result<Self> {
        let base = base_url(&input.url)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?;
        let status = response(
            client
                .get(base.join("api/public/status")?)
                .send()
                .await
                .map_err(|_| {
                    anyhow::anyhow!("Cannot reach the public cloud. Check its URL and connection.")
                })?,
        )
        .await?;
        ensure!(
            status["public"] == true,
            "This server does not provide a public cloud library"
        );
        use sha2::{Digest, Sha256};
        let scope = hex::encode(Sha256::digest(format!(
            "{}:public",
            base.origin().ascii_serialization()
        )));
        Ok(Self {
            client,
            base,
            scope,
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self
            .client
            .request(method, self.base.join(path)?)
            .header("Origin", self.base.origin().ascii_serialization()))
    }
    pub async fn upload(&self, id: &str, p: &Profile) -> Result<()> {
        ensure!(
            !p.session_only,
            "Enable Remember credentials before uploading this profile"
        );
        ensure!(
            id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid cloud server ID"
        );
        let server = from_profile(p.clone())?;
        let mut value = serde_json::to_value(server)?;
        value.as_object_mut().unwrap().remove("id");
        response(
            self.request(reqwest::Method::PUT, &format!("api/public/servers/{id}"))?
                .json(&value)
                .send()
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Cloud upload failed. Retry the same profile; local data is unchanged."
                    )
                })?,
        )
        .await?;
        Ok(())
    }
    pub async fn download(&self) -> Result<Vec<Server>> {
        let mut out = vec![];
        let mut path = "api/public/servers".to_owned();
        for _ in 0..20 {
            let data = response(
                self.request(reqwest::Method::GET, &path)?
                    .send()
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("Cloud refresh failed. Local profiles are unchanged.")
                    })?,
            )
            .await?;
            let page: Vec<Server> = serde_json::from_value(data["servers"].clone())
                .context("Invalid cloud server list")?;
            ensure!(page.len() <= 50, "Invalid cloud page size");
            out.extend(page);
            let Some(next) = data["next"].as_str() else {
                return Ok(out);
            };
            ensure!(
                next.len() == 24 && next.bytes().all(|b| b.is_ascii_hexdigit()),
                "Invalid cloud page cursor"
            );
            path = format!("api/public/servers?after={next}");
        }
        anyhow::bail!("Cloud library exceeds 1000 profiles. No local changes were applied.")
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        ensure!(
            id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid cloud server ID"
        );
        response(
            self.request(reqwest::Method::DELETE, &format!("api/public/servers/{id}"))?
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("Cloud delete failed. Local profile was kept."))?,
        )
        .await?;
        Ok(())
    }
    pub fn url(&self) -> String {
        self.base.origin().ascii_serialization()
    }
}
pub fn from_profile(p: Profile) -> Result<Server> {
    let cfg = Config::parse(&p.args)?;
    let code = sharing::encode(p.clone(), "")?;
    let mut s = Server {
        id: String::new(),
        name: p.name,
        protocol: if cfg.mode() == "ssh" { "ssh" } else { "v2ray" }.into(),
        address: String::new(),
        port: 443,
        sni: String::new(),
        notes: String::new(),
        credentials: Credentials {
            profile_code: Some(code),
            ..Credentials::default()
        },
    };
    if cfg.mode() == "ssh" {
        s.address = cfg.get("H", "").into();
        s.port = cfg.number("P", 443)?;
        s.sni = cfg.get("S", "").into();
        s.credentials.username = cfg.get("u", "").into();
        s.credentials.password = cfg.get("p", "").into();
    } else {
        let p = cfg.protocol()?;
        s.address = p.address;
        s.port = p.port;
        s.sni = p.sni;
        s.credentials.link = cfg.get("v2ray-link", "").into();
    }
    Ok(s)
}
pub fn to_profile(s: Server) -> Result<Profile> {
    ensure!(
        s.id.len() == 24 && s.id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid cloud profile identity"
    );
    let had_code = s.credentials.profile_code.is_some();
    let mut p = if let Some(code) = s.credentials.profile_code {
        sharing::decode(&code, "")?
    } else {
        Profile::default()
    };
    let mut c = if p.args.is_empty() {
        Config::default()
    } else {
        Config::parse(&p.args)?
    };
    let pairs = if s.protocol == "ssh" {
        vec![
            ("mode", "ssh".to_owned()),
            ("H", s.address),
            ("P", s.port.to_string()),
            ("u", s.credentials.username),
            ("p", s.credentials.password),
            ("S", s.sni),
        ]
    } else {
        ensure!(s.protocol == "v2ray", "Unsupported cloud protocol");
        let mut pairs = vec![("mode", "xray".to_owned())];
        if !s.credentials.link.is_empty() {
            pairs.push(("v2ray-link", s.credentials.link));
        }
        if had_code || !s.sni.is_empty() {
            pairs.push(("v2ray-sni", s.sni));
        }
        pairs
    };
    for (k, v) in pairs {
        c.flags.insert(k.into(), v);
    }
    p.id = 0;
    p.name = s.name;
    p.args = c.canonical_args();
    p.mode = c.mode().into();
    p.session_only = false;
    p.needs_credentials = false;
    p.locked = false;
    crate::features::profiles::prepare_for_save(p)
}

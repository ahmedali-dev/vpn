//! Validated session-owned TUN settings; never adopts an existing interface.
use anyhow::{Result, ensure};
use std::net::IpAddr;
#[derive(Clone, Debug)]
pub struct Address {
    pub ip: IpAddr,
    pub prefix: u8,
}
impl Address {
    pub fn parse(value: &str, family: u8) -> Result<Self> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("TUN address requires an IP/prefix"))?;
        let ip: IpAddr = ip.parse()?;
        let prefix: u8 = prefix.parse()?;
        ensure!(
            if family == 4 {
                ip.is_ipv4() && (8..=30).contains(&prefix)
            } else {
                ip.is_ipv6() && (64..=126).contains(&prefix)
            },
            "invalid TUN address family or prefix"
        );
        let private = match ip {
            IpAddr::V4(v) => {
                let [a, b, _, _] = v.octets();
                (a == 10 && prefix >= 8)
                    || (a == 172 && (16..=31).contains(&b) && prefix >= 12)
                    || (a == 192 && b == 168 && prefix >= 16)
            }
            IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
        };
        ensure!(
            private,
            "TUN addresses must use private IPv4 or IPv6 ULA space"
        );
        let bits = if family == 4 { 32 } else { 128 };
        let number = number(ip);
        let mask = u128::MAX >> (128 - (bits - prefix));
        ensure!(
            number & mask != 0 && (family != 4 || number & mask != mask),
            "use a host address rather than the subnet or broadcast address"
        );
        Ok(Self { ip, prefix })
    }
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }
    pub fn overlaps(&self, ip: IpAddr, prefix: u8) -> bool {
        if self.ip.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        let common = self.prefix.min(prefix);
        if common == 0 {
            return true;
        }
        number(self.ip) >> (bits - common) == number(ip) >> (bits - common)
    }
}
fn number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u32::from(v) as u128,
        IpAddr::V6(v) => u128::from(v),
    }
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub addresses: Vec<Address>,
    pub stack: String,
}
impl Settings {
    pub fn from_config(c: &crate::config::Config) -> Result<Self> {
        let mut addresses = vec![Address::parse(c.get("tun-address4", "172.30.111.1/30"), 4)?];
        let v6 = Address::parse(c.get("tun-address6", "fdfe:dcba:9876::1/126"), 6)?;
        addresses.push(v6);
        let stack = c.get("tun-stack", "auto");
        ensure!(
            ["auto", "system", "gvisor", "mixed"].contains(&stack),
            "unsupported TUN stack"
        );
        Ok(Self {
            addresses,
            stack: stack.into(),
        })
    }
    pub fn ips(&self) -> Vec<IpAddr> {
        self.addresses.iter().map(|a| a.ip).collect()
    }
}

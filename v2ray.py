#!/usr/bin/env python3
import json, subprocess, time, socket, tempfile, os, requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT = "work.txt"
OUTPUT = "final_working.txt"
GOOGLE_URL = "https://www.google.com"
BASE_PORT = 25000
THREADS = 30
TIMEOUT = 10

# VMess settings
BACKEND_HOST = "de-v2ray.freevmess.com"
BACKEND_PORT = 2083
VMESS_ID = "f5d7de26-0716-4ede-8fa7-bacc061dbae5"

def wait_port(port, timeout=6):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.1)
    return False


def build_config(domain, port):
    """
    VMess for tunnel + Freedom outbound for Google requests.
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": False}
            }
        ],
        "outbounds": [
            {
                "tag": "vmess",
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": BACKEND_HOST,
                            "port": BACKEND_PORT,
                            "users": [
                                {
                                    "id": VMESS_ID,
                                    "alterId": 0,
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "allowInsecure": True,
                        "serverName": domain
                    }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "vmess",
                    "domains": ["google.com", "www.google.com"]
                },
                {
                    "type": "field",
                    "outboundTag": "vmess",
                    "ip": ["8.8.8.8", "8.8.4.4"]
                },
                {
                    "type": "field",
                    "outboundTag": "vmess",
                    "network": "tcp"
                }
            ]
        }
    }


def test_domain(domain, idx):
    port = BASE_PORT + idx
    cfg = build_config(domain, port)

    fd, cfgfile = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(cfgfile, "w") as fp:
        json.dump(cfg, fp)

    proc = subprocess.Popen(
        ["xray", "run", f"-config={cfgfile}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        if not wait_port(port):
            proc.kill()
            return (domain, False, "SOCKS inbound not ready")

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }

        try:
            r = requests.get(GOOGLE_URL, proxies=proxies, timeout=TIMEOUT)
            response_preview = r.text[:200].replace("\n", "")
            return (domain, r.status_code == 200, f"HTTP {r.status_code} | {response_preview}")
        except Exception as e:
            return (domain, False, f"Request error: {e}")

    finally:
        proc.kill()
        if os.path.exists(cfgfile):
            os.remove(cfgfile)


def main():
    domains = [d.strip() for d in Path(INPUT).read_text().splitlines()]
    good = []

    print(f"\nTesting {len(domains)} domains...\n")

    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        futures = {exe.submit(test_domain, d, i): d for i, d in enumerate(domains)}

        for fut in as_completed(futures):
            domain, ok, detail = fut.result()
            print(f"[{domain}] → {'✔ WORKING' if ok else '✘ FAIL'} | {detail}")
            if ok:
                good.append(domain)

    Path(OUTPUT).write_text("\n".join(good))
    print(f"\nWorking domains saved → {OUTPUT}")
    print(f"Total working: {len(good)}\n")


if __name__ == "__main__":
    main()

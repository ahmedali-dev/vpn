import requests

INPUT_FILE = "subdomains.txt"
OUTPUT_FILE = "work.txt"

def check_domain(domain):
    try:
        url = f"http://{domain.strip()}"
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except Exception:
        return False

def main():
    with open(INPUT_FILE, "r") as f:
        domains = f.read().splitlines()

    working = []

    for domain in domains:
        print(f"[+] Checking: {domain}")
        if check_domain(domain):
            print(f"    ✔ 200 OK")
            working.append(domain)
        else:
            print(f"    ✘ Not working")

    # Save the working ones
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(working))

    print("\nDone! Working domains saved to work.txt")

if __name__ == "__main__":
    main()

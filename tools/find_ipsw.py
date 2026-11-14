#!/usr/bin/env python3
"""Finds a macOS 11 Big Sur UniversalMac Restore IPSW (VirtualMac2,1 / Macmini9,1) or matches a specific kernelcache
compressed size (reads only the ZIP/ZIP64 central directory with HTTP range requests). Prints the URL."""
import json, struct, sys, urllib.request

dev = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else "VirtualMac2,1"
want = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 0
ver_prefix = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "11."

def get(url, rng=None):
    rq = urllib.request.Request(url, headers={"User-Agent": "macnuron-ci"} | ({"Range": rng} if rng else {}))
    return urllib.request.urlopen(rq, timeout=60)

candidates = [dev]
if dev == "VirtualMac2,1":
    candidates.append("Macmini9,1")
elif dev == "Macmini9,1":
    candidates.append("VirtualMac2,1")

fw = []
for cand in candidates:
    try:
        all_fw = json.load(get(f"https://api.ipsw.me/v4/device/{cand}?type=ipsw")).get("firmwares", [])
        fw = [x for x in all_fw if x.get("version", "").startswith(ver_prefix)]
        if fw:
            print(f"{len(fw)} macOS {ver_prefix}x firmwares for {cand}", file=sys.stderr)
            break
    except Exception as e:
        print(f"device {cand}: {e}", file=sys.stderr)

for x in fw:
    url, size = x["url"], int(x["filesize"])
    try:
        tail_len = min(size, 70000)
        tail = get(url, f"bytes={size-tail_len}-{size-1}").read()
        i = tail.rfind(b"PK\x05\x06")
        if i < 0:
            if want == 0:
                print(url); sys.exit(0)
            continue
        cd_size, cd_off = struct.unpack("<II", tail[i+12:i+20])
        if (cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF) and i >= 20 and tail[i-20:i-16] == b"PK\x06\x07":
            z64_off = struct.unpack("<Q", tail[i-12:i-4])[0]
            z64 = get(url, f"bytes={z64_off}-{z64_off+55}").read()
            if z64[:4] == b"PK\x06\x06":
                cd_size, cd_off = struct.unpack("<QQ", z64[40:56])
        cd = get(url, f"bytes={cd_off}-{cd_off+cd_size-1}").read() if cd_off != 0xFFFFFFFF else b""
        p = 0
        while p + 46 <= len(cd) and cd[p:p+4] == b"PK\x01\x02":
            csz = struct.unpack("<I", cd[p+20:p+24])[0]; nl, el, cl = struct.unpack("<HHH", cd[p+28:p+34])
            nm = cd[p+46:p+46+nl].decode(errors="replace")
            if "kernelcache.release.vma2" in nm or "kernelcache.release.j274" in nm or nm.startswith("kernelcache.release"):
                print(f"{x['version']} {x['buildid']}: {nm} compressed {csz}", file=sys.stderr)
                if want == 0 or csz == want:
                    print(url); sys.exit(0)
            p += 46 + nl + el + cl
        if want == 0:
            print(url); sys.exit(0)
    except Exception as e:
        print(f"{x['version']}: {e}", file=sys.stderr)
        if want == 0:
            print(url); sys.exit(0)
sys.exit("no matching macOS 11 Big Sur firmware found")

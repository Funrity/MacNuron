#!/usr/bin/env python3
"""
Downloads ONLY the macOS 11 Big Sur kernelcache + DeviceTree (~20-40 MB instead of 13 GB)
directly from Apple's CDN using HTTP Range requests and standard library only (no pip needed).
Creates 'bigsur_mini.ipsw' and 'kernelcache.bigsur.im4p' in the current directory.
"""
import json, struct, sys, urllib.request, zipfile, zlib

out_ipsw = sys.argv[1] if len(sys.argv) > 1 else "bigsur_mini.ipsw"

def get(url, rng=None):
    headers = {"User-Agent": "macnuron-fetcher"}
    if rng:
        headers["Range"] = rng
    rq = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(rq, timeout=120)

def parse_zip64_extra(extra: bytes, usz: int, csz: int, lho: int):
    q = 0
    while q + 4 <= len(extra):
        eid, esz = struct.unpack_from("<HH", extra, q)
        v = extra[q + 4 : q + 4 + esz]
        if eid == 1:
            vo = 0
            if usz == 0xFFFFFFFF and vo + 8 <= len(v):
                usz = struct.unpack_from("<Q", v, vo)[0]; vo += 8
            if csz == 0xFFFFFFFF and vo + 8 <= len(v):
                csz = struct.unpack_from("<Q", v, vo)[0]; vo += 8
            if lho == 0xFFFFFFFF and vo + 8 <= len(v):
                lho = struct.unpack_from("<Q", v, vo)[0]; vo += 8
        q += 4 + esz
    return usz, csz, lho

print("[1/4] Поиск macOS 11 Big Sur IPSW через api.ipsw.me ...")
all_fw = json.load(get("https://api.ipsw.me/v4/device/Macmini9,1?type=ipsw")).get("firmwares", [])
fw = [x for x in all_fw if x.get("version", "").startswith("11.")]
if not fw:
    sys.exit("Не найдены прошивки macOS 11.x")

chosen = fw[0]
url = chosen["url"]
size = int(chosen["filesize"])
print(f"      Найдена macOS {chosen['version']} ({chosen['buildid']}), размер полного IPSW: {size / (1024**3):.2f} ГБ")
print(f"      URL: {url}")

print("[2/4] Чтение ZIP64 каталога по HTTP Range (без скачивания 13 ГБ) ...")
tail_len = min(size, 70000)
tail = get(url, f"bytes={size-tail_len}-{size-1}").read()
i = tail.rfind(b"PK\x05\x06")
if i < 0:
    sys.exit("Не найден конец центрального каталога ZIP")

cd_size, cd_off = struct.unpack("<II", tail[i+12:i+20])
if (cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF) and i >= 20 and tail[i-20:i-16] == b"PK\x06\x07":
    z64_off = struct.unpack("<Q", tail[i-12:i-4])[0]
    z64 = get(url, f"bytes={z64_off}-{z64_off+55}").read()
    if z64[:4] == b"PK\x06\x06":
        cd_size, cd_off = struct.unpack("<QQ", z64[40:56])

cd = get(url, f"bytes={cd_off}-{cd_off+cd_size-1}").read()
entries = {}
p = 0
while p + 46 <= len(cd) and cd[p:p+4] == b"PK\x01\x02":
    method = struct.unpack("<H", cd[p+10:p+12])[0]
    csz, usz = struct.unpack("<II", cd[p+20:p+28])
    nl, el, cl = struct.unpack("<HHH", cd[p+28:p+34])
    lho = struct.unpack("<I", cd[p+42:p+46])[0]
    nm = cd[p+46:p+46+nl].decode(errors="replace")
    extra = cd[p+46+nl:p+46+nl+el]
    usz, csz, lho = parse_zip64_extra(extra, usz, csz, lho)
    entries[nm] = (method, csz, usz, lho)
    p += 46 + nl + el + cl

kernels = [k for k in entries if "kernelcache" in k and not k.endswith(".plist")]
dtrees = [k for k in entries if "DeviceTree" in k and k.endswith(".im4p")]
print(f"      В архиве найдено ядер (kernelcache): {kernels}")
print(f"      В архиве найдено DeviceTree: {dtrees}")

def rank_key(name):
    low = name.lower()
    if "vma2" in low:
        return (0, len(name), name)
    if "j274" in low:
        return (1, len(name), name)
    if "osx" in low or "mac" in low:
        return (2, len(name), name)
    return (3, len(name), name)

kernels.sort(key=rank_key)
dtrees.sort(key=rank_key)

want_files = []
if "BuildManifest.plist" in entries:
    want_files.append("BuildManifest.plist")
if kernels:
    # Take the top-ranked kernelcache (and vma2 if present)
    want_files.append(kernels[0])
    for k in kernels[1:]:
        if "vma2" in k.lower() or "j274" in k.lower() or "osx" in k.lower():
            want_files.append(k)
            break
if dtrees:
    want_files.append(dtrees[0])
    for d in dtrees[1:]:
        if "vma2" in d.lower() or "j274" in d.lower():
            want_files.append(d)
            break

def extract_member(name):
    method, csz, usz, lho = entries[name]
    lh = get(url, f"bytes={lho}-{lho+29}").read()
    nl, xl = struct.unpack("<HH", lh[26:30])
    data_off = lho + 30 + nl + xl
    print(f"      Скачивание {name} ({csz / (1024*1024):.2f} МБ сжато -> {usz / (1024*1024):.2f} МБ) ...")
    raw = get(url, f"bytes={data_off}-{data_off+csz-1}").read()
    if method == 0:
        return raw
    elif method == 8:
        return zlib.decompress(raw, -15)
    else:
        raise RuntimeError(f"Unsupported ZIP method {method}")

print(f"[3/4] Извлечение компонентов ({len(want_files)} шт.): {want_files} ...")
saved_kernel = False
with zipfile.ZipFile(out_ipsw, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for name in want_files:
        data = extract_member(name)
        zf.writestr(name, data)
        if "kernelcache" in name and not saved_kernel:
            with open("kernelcache.bigsur.im4p", "wb") as kf:
                kf.write(data)
            saved_kernel = True
            print(f"      Отдельно сохранён файл ядра: kernelcache.bigsur.im4p ({len(data) / (1024*1024):.2f} МБ)")

print(f"[4/4] Готово! Создан мини-IPSW: {out_ipsw}")

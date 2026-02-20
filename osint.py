"""
Açık kaynak istihbarat (OSINT) toplama modülü.
Sadece kamuya açık bilgiler: WHOIS, DNS, IP çözümleme, IP konum, ters DNS,
subdomain tarama, IP aralığı (bölge) tarama.
Eğitim amaçlı – yalnızca yasal ve açık kaynaklarla çalışır.
"""

import ipaddress
import json
import socket
import subprocess
import urllib.request
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse

# Yaygın subdomain önekleri (subdomain tarama için)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "admin", "blog", "shop", "cdn",
    "static", "img", "images", "test", "staging", "app", "m", "mobile",
    "secure", "vpn", "ns1", "ns2", "webmail", "smtp", "mx", "git",
]


def normalize_target(target: str) -> str:
    """URL veya domain'den sadece hostname çıkarır."""
    target = target.strip().lower()
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    if "/" in target:
        target = target.split("/")[0]
    return target.split(":")[0]


def dns_lookup(hostname: str, timeout: int = 5) -> Dict[str, Any]:
    """Domain'in A kaydı (IP) ve ters DNS bilgisini toplar."""
    hostname = normalize_target(hostname)
    result = {"hostname": hostname, "ips": [], "error": None}
    try:
        ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        seen = set()
        for (_, _, _, _, sockaddr) in ips:
            ip = sockaddr[0]
            if ip and ip not in seen:
                seen.add(ip)
                result["ips"].append(ip)
    except socket.gaierror as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def whois_lookup(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """WHOIS bilgisini toplar (sistem whois komutu kullanır)."""
    domain = normalize_target(domain)
    result = {"domain": domain, "raw": "", "error": None}
    try:
        out = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["raw"] = (out.stdout or "") + (out.stderr or "")
        if not result["raw"].strip():
            result["error"] = "WHOIS yanıtı boş"
    except FileNotFoundError:
        result["error"] = "Sistemde 'whois' komutu bulunamadı (Linux/macOS'ta yüklü olabilir)"
    except subprocess.TimeoutExpired:
        result["error"] = "WHOIS zaman aşımı"
    except Exception as e:
        result["error"] = str(e)
    return result


def ip_geolocation(ip: str, timeout: int = 5) -> Dict[str, Any]:
    """IP için konum/organizasyon bilgisi (ip-api.com – ücretsiz, anahtar yok)."""
    result = {"ip": ip, "country": None, "city": None, "org": None, "raw": {}, "error": None}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,query"
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Tool/1.0 (Educational)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        result["raw"] = data
        if data.get("status") == "success":
            result["country"] = data.get("country")
            result["city"] = data.get("city")
            result["org"] = data.get("org") or data.get("isp")
        else:
            result["error"] = data.get("message", "Bilgi alınamadı")
    except urllib.error.URLError as e:
        result["error"] = str(e.reason) if hasattr(e, "reason") else str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def reverse_dns(ip: str, timeout: int = 3) -> Dict[str, Any]:
    """IP için ters DNS (PTR) / hostname bilgisi."""
    result = {"ip": ip, "hostnames": [], "error": None}
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            result["hostnames"] = [name]
    except socket.herror:
        result["hostnames"] = []
    except (socket.gaierror, socket.timeout, OSError) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def subdomain_scan(
    domain: str,
    subdomains: Optional[List[str]] = None,
    timeout: int = 3,
) -> Dict[str, Any]:
    """Domain için yaygın subdomain'leri dener; çözümlenenleri listeler."""
    domain = normalize_target(domain)
    subs = subdomains or COMMON_SUBDOMAINS
    result = {"domain": domain, "found": [], "error": None}
    for sub in subs[:30]:  # En fazla 30 subdomain
        host = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(host)
            result["found"].append({"subdomain": host, "ip": ip})
        except (socket.gaierror, socket.timeout):
            pass
        except Exception:
            pass
    return result


def _parse_ip_range(spec: str) -> List[str]:
    """'192.168.1.1-20' veya '192.168.1.0/28' formatında IP listesi döner. En fazla 64 IP."""
    ips: List[str] = []
    spec = spec.strip()
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            for ip in list(net.hosts())[:64]:
                ips.append(str(ip))
        elif "-" in spec:
            base, end = spec.rsplit("-", 1)
            base = base.strip()
            end = end.strip()
            try:
                start_ip = ipaddress.ip_address(base)
                end_num = int(end)
                # 192.168.1.1-20 => son oktet 1..20
                if "." in base:
                    parts = base.split(".")
                    prefix = ".".join(parts[:-1])
                    start_octet = int(parts[-1])
                    for i in range(start_octet, min(end_num + 1, start_octet + 64)):
                        ips.append(f"{prefix}.{i}")
                else:
                    for i in range(0, min(end_num, 64)):
                        ips.append(str(start_ip + i))
            except ValueError:
                start_ip = ipaddress.ip_address(base)
                end_ip = ipaddress.ip_address(end.strip())
                n = 0
                for ip in ipaddress.summarize_address_range(start_ip, end_ip):
                    for addr in ip.hosts():
                        if n >= 64:
                            break
                        ips.append(str(addr))
                        n += 1
        else:
            ips.append(spec)
    except Exception:
        pass
    return ips[:64]


def ip_range_scan(
    range_spec: str,
    port: int = 80,
    timeout: float = 1.0,
    max_hosts: int = 64,
) -> Dict[str, Any]:
    """IP aralığında (bölge) belirtilen portun açık olup olmadığını tarar."""
    result = {"range": range_spec, "port": port, "open": [], "closed_count": 0, "error": None}
    ips = _parse_ip_range(range_spec)[:max_hosts]
    if not ips:
        result["error"] = "Geçersiz IP aralığı (örn: 192.168.1.1-20 veya 10.0.0.0/28)"
        return result
    for ip in ips:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            r = sock.connect_ex((ip, port))
            sock.close()
            if r == 0:
                result["open"].append(ip)
            else:
                result["closed_count"] += 1
        except Exception:
            result["closed_count"] += 1
    return result


def collect_all(
    target: str,
    timeout: int = 8,
    with_subdomains: bool = True,
    with_reverse_dns: bool = True,
) -> Dict[str, Any]:
    """Hedef için WHOIS, DNS, IP konum, ters DNS ve (isteğe bağlı) subdomain bilgisini toplar."""
    target = normalize_target(target)
    out = {
        "target": target,
        "dns": dns_lookup(target, timeout),
        "whois": whois_lookup(target, timeout),
        "ip_info": [],
        "reverse_dns": [],
        "subdomains": None,
    }
    ips = out["dns"].get("ips", [])[:5]
    for ip in ips:
        out["ip_info"].append(ip_geolocation(ip, timeout))
        if with_reverse_dns:
            out["reverse_dns"].append(reverse_dns(ip, min(timeout, 3)))
    if with_subdomains:
        out["subdomains"] = subdomain_scan(target, timeout=min(timeout, 3))
    return out

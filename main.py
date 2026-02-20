#!/usr/bin/env python3
"""
Açık kaynak istihbarat (OSINT) toplama aracı – CLI.
Kullanım: python3 main.py example.com  veya  python3 main.py https://example.com
"""

import argparse
import sys
from osint import (
    collect_all,
    normalize_target,
    dns_lookup,
    whois_lookup,
    ip_geolocation,
    reverse_dns,
    subdomain_scan,
    ip_range_scan,
)


def print_report(data: dict) -> None:
    """Toplanan bilgileri rapor olarak yazdırır."""
    target = data["target"]
    dns = data.get("dns", {})
    whois = data.get("whois", {})
    ip_info_list = data.get("ip_info", [])
    reverse_dns_list = data.get("reverse_dns", [])
    subdomains = data.get("subdomains")

    print()
    print("═" * 62)
    print("  AÇIK KAYNAK İSTİHBARAT (OSINT) – RAPOR")
    print("═" * 62)
    print(f"  Hedef: {target}")
    print()

    # DNS
    print("  DNS (A kayıtları)")
    print("  " + "─" * 58)
    if dns.get("error"):
        print(f"  ⚠ {dns['error']}")
    elif dns.get("ips"):
        for ip in dns["ips"]:
            print(f"  • {ip}")
    else:
        print("  (IP bulunamadı)")
    print()

    # Ters DNS (IP → hostname)
    if reverse_dns_list:
        print("  TERS DNS (IP → hostname)")
        print("  " + "─" * 58)
        for rd in reverse_dns_list:
            ip = rd.get("ip", "?")
            if rd.get("hostnames"):
                print(f"  {ip} → {', '.join(rd['hostnames'])}")
            elif rd.get("error"):
                print(f"  {ip} → (yok veya hata)")
            else:
                print(f"  {ip} → (PTR yok)")
        print()

    # IP konum bilgisi
    if ip_info_list:
        print("  IP KONUM / ORGANİZASYON")
        print("  " + "─" * 58)
        for info in ip_info_list:
            ip = info.get("ip", "?")
            if info.get("error"):
                print(f"  {ip}: {info['error']}")
            else:
                parts = []
                if info.get("city"):
                    parts.append(info["city"])
                if info.get("country"):
                    parts.append(info["country"])
                if info.get("org"):
                    parts.append(f"({info['org']})")
                print(f"  {ip}: {', '.join(parts) or '-'}")
        print()

    # Subdomain taraması
    if subdomains and subdomains.get("found"):
        print("  SUBDOMAIN TARAMASI (bulunanlar)")
        print("  " + "─" * 58)
        for item in subdomains["found"][:20]:
            print(f"  • {item['subdomain']} → {item['ip']}")
        if len(subdomains["found"]) > 20:
            print(f"  ... ve {len(subdomains['found']) - 20} tane daha")
        print()

    # WHOIS
    print("  WHOIS (kayıt bilgisi)")
    print("  " + "─" * 58)
    if whois.get("error"):
        print(f"  ⚠ {whois['error']}")
    elif whois.get("raw"):
        raw = whois["raw"].strip()
        lines = raw.split("\n")[:25]
        for line in lines:
            if line.strip():
                print(f"  {line}")
        if len(raw.split("\n")) > 25:
            print("  ... (kısaltıldı)")
    else:
        print("  (WHOIS verisi yok)")
    print()

    print("═" * 62)
    print("  Not: Tüm veriler kamuya açık kaynaklardan toplanmıştır.")
    print("═" * 62)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Açık kaynak istihbarat (OSINT) – domain/IP için WHOIS, DNS ve konum bilgisi"
    )
    parser.add_argument("hedef", nargs="?", default="", help="Domain veya URL (örn. example.com); --scan-range ile kullanılmaz")
    parser.add_argument(
        "--timeout", "-t", type=int, default=8,
        help="İstek zaman aşımı (saniye)",
    )
    parser.add_argument(
        "--whois-only", action="store_true",
        help="Sadece WHOIS sorgula",
    )
    parser.add_argument(
        "--dns-only", action="store_true",
        help="Sadece DNS (IP) sorgula",
    )
    parser.add_argument(
        "--ip", action="store_true",
        help="Hedef bir IP adresi; sadece konum bilgisi getir",
    )
    parser.add_argument(
        "--subdomains-only", action="store_true",
        help="Sadece subdomain taraması yap",
    )
    parser.add_argument(
        "--no-subdomains", action="store_true",
        help="Tam raporda subdomain taraması yapma",
    )
    parser.add_argument(
        "--scan-range", metavar="ARALIK",
        help="IP aralığı tara (örn: 192.168.1.1-20 veya 10.0.0.0/28)",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=80,
        help="Bölge taramasında kontrol edilecek port (varsayılan: 80)",
    )
    args = parser.parse_args()

    if args.scan_range:
        scan = ip_range_scan(args.scan_range, port=args.port)
        print()
        print("  Bölge / IP aralığı taraması")
        print("  " + "─" * 50)
        print(f"  Aralık: {scan['range']}  Port: {scan['port']}")
        if scan.get("error"):
            print(f"  ⚠ {scan['error']}")
        elif scan.get("open"):
            print("  Açık port bulunan IP'ler:")
            for ip in scan["open"]:
                print(f"  • {ip}")
            print(f"  Toplam: {len(scan['open'])} açık, {scan.get('closed_count', 0)} kapalı")
        else:
            print("  Açık port bulunamadı.")
        print()
        sys.exit(0 if not scan.get("error") else 1)

    if not args.hedef:
        parser.error("Hedef domain veya URL gerekli (örn. example.com)")

    target = normalize_target(args.hedef)

    if args.ip:
        info = ip_geolocation(target, args.timeout)
        print()
        print("  IP Konum Bilgisi")
        print("  " + "─" * 40)
        if info.get("error"):
            print(f"  ⚠ {info['error']}")
        else:
            print(f"  IP:    {info.get('ip')}")
            print(f"  Ülke:  {info.get('country', '-')}")
            print(f"  Şehir: {info.get('city', '-')}")
            print(f"  Org:   {info.get('org', '-')}")
        print()
        sys.exit(0 if not info.get("error") else 1)

    if args.whois_only:
        whois = whois_lookup(target, args.timeout)
        print()
        print("  WHOIS:", target)
        print("  " + "─" * 58)
        if whois.get("error"):
            print(f"  ⚠ {whois['error']}")
        else:
            print(whois.get("raw", ""))
        print()
        sys.exit(0 if not whois.get("error") else 1)

    if args.dns_only:
        dns = dns_lookup(target, args.timeout)
        print()
        print("  DNS (A):", target)
        print("  " + "─" * 40)
        if dns.get("error"):
            print(f"  ⚠ {dns['error']}")
        else:
            for ip in dns.get("ips", []):
                print(f"  {ip}")
        print()
        sys.exit(0 if not dns.get("error") else 1)

    if args.subdomains_only:
        sub = subdomain_scan(target, timeout=args.timeout)
        print()
        print("  Subdomain taraması:", target)
        print("  " + "─" * 50)
        if sub.get("found"):
            for item in sub["found"]:
                print(f"  • {item['subdomain']} → {item['ip']}")
        else:
            print("  (Bulunan subdomain yok)")
        print()
        sys.exit(0)

    data = collect_all(
        target,
        args.timeout,
        with_subdomains=not args.no_subdomains,
        with_reverse_dns=True,
    )
    print_report(data)
    if data.get("dns", {}).get("error") and not data.get("dns", {}).get("ips"):
        sys.exit(1)


if __name__ == "__main__":
    main()

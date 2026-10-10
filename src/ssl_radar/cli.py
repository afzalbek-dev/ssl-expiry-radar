"""CLI for SSL Expiry Radar."""
import sys
import argparse
from .scanner import DomainScanner

def main():
    parser = argparse.ArgumentParser(description="SSL Expiry Radar — TLS Certificate Expiry Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Mavjud buyruqlar")

    # check single
    check_p = subparsers.add_parser("check", help="Bitta domen sertifikatini tekshirish")
    check_p.add_argument("domain", help="Domen nomi (masalan: github.com)")

    # scan-list
    scan_p = subparsers.add_parser("scan-list", help="Fayldan domenlar ro'yxatini skanlash")
    scan_p.add_argument("file", help="Domenlar yozilgan matn fayli")

    args = parser.parse_args()
    scanner = DomainScanner()

    if args.command == "check":
        res = scanner.scan_domains([args.domain])[0]
        print("\n🔒  SSL EXPIRY RADAR TEKSHIRUVI")
        print("──────────────────────────────────────────")
        print(f"🌐 Domen:    {res['hostname']}")
        if res['valid']:
            icon = "🟢" if res['status'] == "HEALTHY" else ("🟡" if res['status'] == "WARNING" else "🔴")
            print(f"📊 Holat:    {icon} {res['status']}")
            print(f"⏳ Qolgan:   {res['days_remaining']} kun")
            print(f"📅 Tugash:   {res['expires_at']}")
            print(f"🏢 Chiqardi: {res['issuer']}")
        else:
            print(f"❌ Xatolik:  {res.get('error', 'Ulanib bo‘lmadi')}")
        print()

    elif args.command == "scan-list":
        try:
            with open(args.file, "r") as f:
                domains = f.read().splitlines()
        except Exception as e:
            print(f"❌ Faylni o'qishda xatolik: {e}")
            sys.exit(1)

        results = scanner.scan_domains(domains)
        print(f"\n📡 SKANLASH NATIJALARI ({len(results)} ta domen):")
        print("────────────────────────────────────────────────────────────")
        has_critical = False
        for r in results:
            if r['valid']:
                icon = "🟢" if r['status'] == "HEALTHY" else ("🟡" if r['status'] == "WARNING" else "🔴")
                print(f"{icon} {r['hostname']:25} | {r['status']:8} | Qolgan: {r['days_remaining']} kun | {r['issuer']}")
                if r['status'] in ("CRITICAL", "EXPIRED"):
                    has_critical = True
            else:
                print(f"❌ {r['hostname']:25} | ERROR    | {r.get('error', 'Fail')}")
                has_critical = True
        print()
        if has_critical:
            sys.exit(2)

if __name__ == "__main__":
    main()

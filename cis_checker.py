import argparse
from utils import detect_os, generate_report
import windows_controls
import linux_controls
from exporter import export_to_json, export_to_csv, mostrar_resultados

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chequeo de controles CIS - Windows/Linux")
    parser.add_argument("--json", help="Exportar a JSON", action="store_true")
    parser.add_argument("--csv", help="Exportar a CSV", action="store_true")
    parser.add_argument("--mostrar", help="Mostrar resultados en consola con colores", action="store_true")
    args = parser.parse_args()

    print("🛡️ Ejecutando chequeo de controles CIS...")
    system = detect_os()

    if system == "linux":
        results = linux_controls.check_all()
    elif system == "windows":
        results = windows_controls.check_all()
    else:
        print("❌ Sistema operativo no soportado.")
        exit(1)

    if args.mostrar:
        mostrar_resultados(results)

    if args.json:
        path = export_to_json(results)
        print(f"📄 Resultados exportados a JSON: {path}")

    if args.csv:
        path = export_to_csv(results)
        print(f"📄 Resultados exportados a CSV: {path}")

    if not any([args.json, args.csv, args.mostrar]):
        generate_report(results)
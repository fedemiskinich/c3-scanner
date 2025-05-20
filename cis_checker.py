import argparse
from utils import detect_os, is_docker
import windows_controls
import linux_controls
import controls_docker
from exporter import export_to_json, export_to_csv, mostrar_resultados, resumen_resultados

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C3 - CIS Compliance Checker")
    parser.add_argument("--json", action="store_true", help="Exportar resultados a JSON")
    parser.add_argument("--csv", action="store_true", help="Exportar resultados a CSV")
    parser.add_argument("--mostrar", action="store_true", help="Mostrar resultados en consola")
    args = parser.parse_args()

    print("🛡️ Ejecutando chequeo de controles CIS...")

    system = detect_os()
    results = []

    if system == "windows":
        print("🪟 Sistema detectado: Windows")
        scope = "windows"
        results = windows_controls.check_all()
    elif is_docker():
        print("🐳 Entorno detectado: Contenedor Docker")
        scope = "docker"
        results = controls_docker.run_cis_docker_checks()
    elif system == "linux":
        print("🐧 Sistema detectado: Linux")
        scope = "linux"
        results = linux_controls.check_all()
    else:
        print("❌ Sistema operativo no soportado.")
        exit(1)

    if args.mostrar:
        mostrar_resultados(results, scope=scope)

    if args.json:
        path = export_to_json(results)
        print(f"📄 Resultados exportados a JSON: {path}")

    if args.csv:
        path = export_to_csv(results, scope=scope)
        print(f"📄 Resultados exportados a CSV: {path}")

    if not any([args.mostrar, args.json, args.csv]):
        for r in results:
            print(f"[{r[2]}] {r[0]} - {r[1]}")

    resumen_resultados(results, scope=scope)
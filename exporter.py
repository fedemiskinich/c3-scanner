import json
import csv
import os

def export_to_json(findings, path="cis_results.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    return path

def export_to_csv(findings, path="cis_results.csv", scope="docker"):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["CIS_ID", "Descripción", "Estado", "Recomendación", "Evidencia"])
        for item in findings:
            remed = get_remediation(item[0], scope=scope) if item[2] == "FAIL" else ""
            evidencia = item[3] if len(item) > 3 and item[2] == "FAIL" else ""
            writer.writerow(item[:3] + [remed, evidencia])
    return path

def get_remediation(cis_id, scope="docker"):
    file_path = f"scopes/{scope}.json"
    if not os.path.exists(file_path):
        return "No hay archivo de remediaciones definido para este entorno."
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            soluciones = json.load(f)
        return soluciones.get(cis_id, "No hay recomendación definida aún.")
    except Exception as e:
        return f"Error al cargar remediaciones: {e}"

def mostrar_resultados(findings, scope="docker"):
    for item in findings:
        cid, desc, status = item[0], item[1], item[2]
        if status == "FAIL":
            print(f"\033[91m[FAIL] {cid}: {desc}\033[0m")
            print(f"\033[92m   🔧 Recomendación: {get_remediation(cid, scope)}\033[0m")
            if len(item) > 3:
                print(f"\033[94m   📄 Evidencia: {item[3]}\033[0m")
        else:
            print(f"[{status}] {cid}: {desc}")

def resumen_resultados(findings, scope="linux"):
    scope_titles = {
        "linux": "CIS LINUX",
        "windows": "CIS WINDOWS",
        "docker": "CIS DOCKER"
    }
    titulo = scope_titles.get(scope.lower(), f"CIS {scope.upper()}")

    total = len(findings)
    passed = sum(1 for r in findings if r[2] == "PASS")
    failed = sum(1 for r in findings if r[2] == "FAIL")
    warn = sum(1 for r in findings if r[2] == "WARN")

    print("="*50)
    print(f"🔍 RESUMEN FINAL DE LA EVALUACIÓN {titulo}")
    print("="*50)
    print(f"✔️ Controles OK      : {passed}")
    print(f"❌ Controles FALLIDOS: {failed}")
    print(f"⚠️  Advertencias     : {warn}")
    print(f"📊 Total ejecutados  : {total}")
    print("="*50)

    if failed:
        print("="*50)
        print("📌 Detalle de hallazgos (solo FAIL):")
        for item in findings:
            cid, desc, status = item[0], item[1], item[2]
            if status == "FAIL":
                print(f"\033[91m▶️[FAIL] {cid}: {desc}\033[0m")
                print(f"\033[92m   🔧 Recomendación: {get_remediation(cid, scope)}\033[0m")
                if len(item) > 3:
                    print(f"\033[94m   📄 Evidencia: {item[3]}\033[0m")
        print("="*50)
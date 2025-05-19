import json
import csv

def export_to_json(findings, path="cis_results.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    return path

def export_to_csv(findings, path="cis_results.csv"):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["CIS_ID", "Descripción", "Estado"])
        for item in findings:
            writer.writerow(item)
    return path

def mostrar_resultados(findings):
    for cid, desc, status in findings:
        if status == "PASS":
            color = "\033[92m"  # Verde
        elif status == "FAIL":
            color = "\033[91m"  # Rojo
        elif status == "WARN":
            color = "\033[0m" # "\033[93m"  # Amarillo
        else:
            color = "\033[0m"   # Sin color

        print(f"{color}[{status}] {cid}: {desc}\033[0m")
import platform
import json

def detect_os():
    return platform.system().lower()

def generate_report(results):
    summary = {"PASS": 0, "FAIL": 0, "WARN": 0}
    for _, _, status in results:
        summary[status] += 1
    print("\n📝 RESULTADOS DEL CHEQUEO DE CONTROLES CIS\n")
    for cid, desc, status in results:
        print(f"[{status}] {cid}: {desc}")
    print("\n📊 RESUMEN:")
    print(json.dumps(summary, indent=2))
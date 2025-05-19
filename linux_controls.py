import os

def check_permissions():
    results = []
    files = ["/etc/passwd", "/etc/shadow"]
    for f in files:
        try:
            perm = oct(os.stat(f).st_mode)[-3:]
            status = "PASS" if f == "/etc/shadow" and perm == "000" else "FAIL"
            results.append(("CIS 1.1.1", f"{f} → {perm}", status))
        except Exception as e:
            results.append(("CIS 1.1.1", f"Error accediendo a {f}: {e}", "WARN"))
    return results

def check_all():
    return check_permissions()
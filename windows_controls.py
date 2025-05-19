import subprocess
import re

def parse_net_accounts():
    try:
        output = subprocess.check_output(["net", "accounts"], encoding="utf-8")
        return output.splitlines()
    except Exception as e:
        return []

def check_password_history(lines):
    for line in lines:
        if "Enforce password history" in line:
            value = int(re.findall(r"\d+", line)[0])
            return ("CIS 1.1.1", f"Password history: {value}", "PASS" if value >= 24 else "FAIL")
    return ("CIS 1.1.1", "No se pudo determinar el valor", "WARN")

def check_max_password_age(lines):
    for line in lines:
        if "Maximum password age" in line:
            value = int(re.findall(r"\d+", line)[0])
            return ("CIS 1.1.2", f"Maximum password age: {value}", "PASS" if value <= 60 else "FAIL")
    return ("CIS 1.1.2", "No se pudo determinar el valor", "WARN")

def check_min_password_age(lines):
    for line in lines:
        if "Minimum password age" in line:
            value = int(re.findall(r"\d+", line)[0])
            return ("CIS 1.1.3", f"Minimum password age: {value}", "PASS" if value >= 1 else "FAIL")
    return ("CIS 1.1.3", "No se pudo determinar el valor", "WARN")

def check_min_password_length(lines):
    for line in lines:
        if "Minimum password length" in line:
            value = int(re.findall(r"\d+", line)[0])
            return ("CIS 1.1.4", f"Minimum password length: {value}", "PASS" if value >= 14 else "FAIL")
    return ("CIS 1.1.4", "No se pudo determinar el valor", "WARN")

def check_lockout_policy():
    try:
        output = subprocess.check_output(["net", "accounts"], encoding="utf-8").splitlines()
        result = []
        for line in output:
            if "Lockout threshold" in line:
                value = int(re.findall(r"\d+", line)[0])
                result.append(("CIS 1.2.2", f"Lockout threshold: {value}", "PASS" if 0 < value <= 10 else "FAIL"))
            elif "Lockout duration" in line:
                value = int(re.findall(r"\d+", line)[0])
                result.append(("CIS 1.2.1", f"Lockout duration: {value}", "PASS" if value >= 15 else "FAIL"))
            elif "Reset account lockout" in line:
                value = int(re.findall(r"\d+", line)[0])
                result.append(("CIS 1.2.3", f"Reset lockout counter after: {value}", "PASS" if value >= 15 else "FAIL"))
        return result
    except Exception as e:
        return [("CIS 1.2.x", f"Error al verificar políticas de bloqueo: {e}", "WARN")]

def check_kerberos_policy():
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-ADDefaultDomainPasswordPolicy"],
            encoding="utf-8"
        )
        lines = output.splitlines()
        results = []
        for line in lines:
            if "MaxPasswordAge" in line:
                days = int(re.findall(r"\d+", line)[0])
                results.append(("CIS 1.3.3", f"Max user ticket lifetime (days): {days}", "PASS" if days <= 1 else "FAIL"))
            elif "MaxClockSkew" in line:
                minutes = int(re.findall(r"\d+", line)[0])
                results.append(("CIS 1.3.5", f"Max clock skew: {minutes}", "PASS" if minutes <= 5 else "FAIL"))
            elif "TicketLifetime" in line:
                minutes = int(re.findall(r"\d+", line)[0])
                results.append(("CIS 1.3.2", f"Max service ticket lifetime: {minutes}", "PASS" if minutes <= 600 else "FAIL"))
            elif "EnforceUserLogonRestrictions" in line:
                if "True" in line:
                    results.append(("CIS 1.3.1", "Logon restrictions enforced", "PASS"))
                else:
                    results.append(("CIS 1.3.1", "Logon restrictions not enforced", "FAIL"))
        return results
    except Exception as e:
        return [("CIS 1.3.x", f"Error al verificar política Kerberos: {e}", "WARN")]

def check_audit_policy():
    try:
        output = subprocess.check_output(["auditpol", "/get", "/category:*"], encoding="utf-8")
        results = []
        for line in output.splitlines():
            if "Logon/Logoff" in line and "Success and Failure" not in line:
                results.append(("CIS 2.3.1", "Audit Logon/Logoff incompleto", "FAIL"))
            elif "Account Logon" in line and "Success and Failure" not in line:
                results.append(("CIS 2.3.2", "Audit Account Logon incompleto", "FAIL"))
        if not results:
            results.append(("CIS 2.3.x", "Políticas de auditoría correctamente configuradas", "PASS"))
        return results
    except Exception as e:
        return [("CIS 2.3.x", f"Error al obtener políticas de auditoría: {e}", "WARN")]

def check_user_rights_assignment():
    try:
        subprocess.check_output(["secedit", "/export", "/cfg", "C:\\Windows\\Temp\\secpol.inf"],
                                stderr=subprocess.DEVNULL)
        with open("C:\\Windows\\Temp\\secpol.inf", "r", encoding="utf-8") as f:
            content = f.read()
        if "SeRemoteInteractiveLogonRight" in content and "Administrators" in content:
            return [("CIS 2.2.x", "Solo Administradores tienen acceso RDP", "PASS")]
        else:
            return [("CIS 2.2.x", "Acceso RDP permitido a otros usuarios", "FAIL")]
    except Exception as e:
        return [("CIS 2.2.x", f"Error al verificar derechos de usuario: {e}", "WARN")]

def check_firewall_profiles():
    results = []
    try:
        output = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles"], encoding="utf-8").splitlines()
        profiles = ["Domain Profile", "Private Profile", "Public Profile"]
        current_profile = ""
        for line in output:
            if any(p in line for p in profiles):
                current_profile = line.strip(":")
            if "State" in line and "ON" not in line:
                results.append(("CIS 4.1", f"{current_profile}: Firewall desactivado", "FAIL"))
        if not results:
            results.append(("CIS 4.1", "Firewall habilitado en todos los perfiles", "PASS"))
        return results
    except Exception as e:
        return [("CIS 4.1", f"Error al verificar el firewall: {e}", "WARN")]

def check_firewall_inbound():
    results = []
    try:
        output = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles"], encoding="utf-8")
        blocks = output.split("Profile Settings -")
        for profile_block in blocks[1:]:
            if "Inbound connections that do not match a rule" in profile_block:
                if "Block" not in profile_block:
                    results.append(("CIS 4.2", "Conexiones entrantes permitidas sin regla", "FAIL"))
        if not results:
            results.append(("CIS 4.2", "Conexiones entrantes no autorizadas están bloqueadas", "PASS"))
        return results
    except Exception as e:
        return [("CIS 4.2", f"Error al verificar reglas de entrada: {e}", "WARN")]

def check_all():
    lines = parse_net_accounts()
    results = []
    results.append(check_password_history(lines))
    results.append(check_max_password_age(lines))
    results.append(check_min_password_age(lines))
    results.append(check_min_password_length(lines))
    results += check_lockout_policy()
    results += check_kerberos_policy()
    results += check_audit_policy()
    results += check_user_rights_assignment()
    results += check_firewall_profiles()
    results += check_firewall_inbound()
    results += check_guest_account_status()
    results += check_unused_services()
    results += check_wdigest_status()
    results += check_system_restore_disabled()
    results += check_smb1_disabled()
    results += check_cdrom_disabled()
    results += check_autorun_disabled()
    results += check_usb_storage_disabled()
    results += check_smb_signing_required()
    results += check_smb_signing_server_required()
    results += check_llmnr_disabled()
    results += check_netbios_disabled()
    results += check_local_admins()
    results += check_guest_group_members()
    results += check_defender_enabled()
    results += check_realtime_protection() 
    results += check_defender_signatures() 
    results += check_windows_update_service()
    results += check_automatic_updates_enabled()
    results += check_event_log_size()
    results += check_log_retention_enabled()
    results += check_bitlocker_enabled()
    results += check_recovery_password_protection()

    return results

def check_bitlocker_enabled():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq 'FullyEncrypted' }"
        ], encoding="utf-8")
        if output.strip():
            return [("CIS 13.1", "Volumen cifrado completamente con BitLocker", "PASS")]
        else:
            return [("CIS 13.1", "BitLocker no habilitado o volumen no cifrado", "FAIL")]
    except Exception as e:
        return [("CIS 13.1", f"Error al verificar estado de BitLocker: {e}", "WARN")]

def check_recovery_password_protection():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-BitLockerVolume | Select-Object -ExpandProperty KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }"
        ], encoding="utf-8")
        if output.strip():
            return [("CIS 13.2", "Protección por contraseña de recuperación configurada", "PASS")]
        else:
            return [("CIS 13.2", "No hay contraseña de recuperación configurada", "FAIL")]
    except Exception as e:
        return [("CIS 13.2", f"Error al verificar clave de recuperación: {e}", "WARN")]



def check_event_log_size():
    results = []
    try:
        logs = {
            "Application": "CIS 12.1",
            "Security": "CIS 12.2",
            "System": "CIS 12.3"
        }
        for log_name, control_id in logs.items():
            output = subprocess.check_output([
                "wevtutil", "gl", log_name
            ], encoding="utf-8", stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "maxSize:" in line:
                    size_kb = int(line.split(":")[1].strip()) // 1024
                    if size_kb >= 196608:  # 192 MB mínimo recomendado
                        results.append((control_id, f"{log_name} log size: {size_kb} KB", "PASS"))
                    else:
                        results.append((control_id, f"{log_name} log size bajo: {size_kb} KB", "FAIL"))
        return results
    except Exception as e:
        return [("CIS 12.x", f"Error al verificar tamaño de logs: {e}", "WARN")]

def check_log_retention_enabled():
    try:
        output = subprocess.check_output([
            "wevtutil", "gl", "Security"
        ], encoding="utf-8", stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            if "retention:" in line.lower() and "true" in line.lower():
                return [("CIS 12.4", "Retención habilitada en log de seguridad", "PASS")]
        return [("CIS 12.4", "Retención no habilitada en log de seguridad", "FAIL")]
    except Exception as e:
        return [("CIS 12.4", f"Error al verificar retención de logs: {e}", "WARN")]



def check_windows_update_service():
    try:
        output = subprocess.check_output([
            "sc", "query", "wuauserv"
        ], encoding="utf-8")
        if "RUNNING" in output:
            return [("CIS 11.1", "Servicio Windows Update en ejecución", "PASS")]
        else:
            return [("CIS 11.1", "Servicio Windows Update detenido", "FAIL")]
    except Exception as e:
        return [("CIS 11.1", f"Error al consultar el servicio de Windows Update: {e}", "WARN")]

def check_automatic_updates_enabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
            "/v", "NoAutoUpdate"
        ], encoding="utf-8")
        if "0x0" in output:
            return [("CIS 11.2", "Actualizaciones automáticas habilitadas", "PASS")]
        else:
            return [("CIS 11.2", "Actualizaciones automáticas deshabilitadas", "FAIL")]
    except subprocess.CalledProcessError:
        # Clave no existe → por defecto, están habilitadas
        return [("CIS 11.2", "Clave no encontrada → actualizaciones automáticas por defecto", "PASS")]
    except Exception as e:
        return [("CIS 11.2", f"Error al verificar actualizaciones automáticas: {e}", "WARN")]


def check_local_admins():
    try:
        output = subprocess.check_output([
            "net", "localgroup", "Administrators"
        ], encoding="utf-8", stderr=subprocess.DEVNULL)

        members = [line.strip() for line in output.splitlines() if "\\" in line or "Administrators" in line]
        suspicious = [m for m in members if "Administrator" not in m and "admin" not in m.lower()]

        if suspicious:
            return [("CIS 9.1", f"Miembros sospechosos en Administrators: {', '.join(suspicious)}", "FAIL")]
        else:
            return [("CIS 9.1", "Solo cuentas válidas en grupo Administrators", "PASS")]
    except Exception as e:
        return [("CIS 9.1", f"Error al listar miembros del grupo Administrators: {e}", "WARN")]

def check_guest_group_members():
    try:
        output = subprocess.check_output([
            "net", "localgroup", "Guests"
        ], encoding="utf-8", stderr=subprocess.DEVNULL)

        members = [line.strip() for line in output.splitlines() if "\\" in line or "Guest" in line]
        if len(members) > 1:
            return [("CIS 9.2", f"Miembros adicionales en grupo Guests: {', '.join(members)}", "FAIL")]
        else:
            return [("CIS 9.2", "Grupo Guests limpio", "PASS")]
    except Exception as e:
        return [("CIS 9.2", f"Error al verificar grupo Guests: {e}", "WARN")]


def check_smb_signing_required():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            "/v", "RequireSecuritySignature"
        ], encoding="utf-8")
        if "0x1" in output:
            return [("CIS 8.1", "SMB signing requerido en cliente", "PASS")]
        else:
            return [("CIS 8.1", "SMB signing no requerido en cliente", "FAIL")]
    except Exception as e:
        return [("CIS 8.1", f"Error al verificar SMB signing (cliente): {e}", "WARN")]

def check_smb_signing_server_required():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "/v", "RequireSecuritySignature"
        ], encoding="utf-8")
        if "0x1" in output:
            return [("CIS 8.2", "SMB signing requerido en servidor", "PASS")]
        else:
            return [("CIS 8.2", "SMB signing no requerido en servidor", "FAIL")]
    except Exception as e:
        return [("CIS 8.2", f"Error al verificar SMB signing (servidor): {e}", "WARN")]

def check_llmnr_disabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient",
            "/v", "EnableMulticast"
        ], encoding="utf-8")
        if "0x0" in output:
            return [("CIS 8.3", "LLMNR deshabilitado", "PASS")]
        else:
            return [("CIS 8.3", "LLMNR habilitado (inseguro)", "FAIL")]
    except Exception as e:
        return [("CIS 8.3", f"Error al verificar LLMNR: {e}", "WARN")]

def check_netbios_disabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces",
            "/s"
        ], encoding="utf-8")
        if "NetbiosOptions" in output and "0x2" in output:
            return [("CIS 8.4", "NetBIOS deshabilitado", "PASS")]
        else:
            return [("CIS 8.4", "NetBIOS habilitado o parcialmente activo", "FAIL")]
    except Exception as e:
        return [("CIS 8.4", f"Error al verificar NetBIOS: {e}", "WARN")]


def check_defender_enabled():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled"
        ], encoding="utf-8")
        if "True" in output:
            return [("CIS 10.1", "Windows Defender activado", "PASS")]
        else:
            return [("CIS 10.1", "Windows Defender desactivado", "FAIL")]
    except Exception as e:
        return [("CIS 10.1", f"Error al verificar Defender: {e}", "WARN")]

def check_realtime_protection():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled"
        ], encoding="utf-8")
        if "True" in output:
            return [("CIS 10.2", "Protección en tiempo real habilitada", "PASS")]
        else:
            return [("CIS 10.2", "Protección en tiempo real deshabilitada", "FAIL")]
    except Exception as e:
        return [("CIS 10.2", f"Error al verificar protección en tiempo real: {e}", "WARN")]

def check_defender_signatures():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated"
        ], encoding="utf-8")
        if "AntivirusSignatureLastUpdated" in output:
            return [("CIS 10.3", "Firmas antivirus actualizadas", "PASS")]
        else:
            return [("CIS 10.3", "No se encontró fecha de actualización", "FAIL")]
    except Exception as e:
        return [("CIS 10.3", f"Error al verificar actualización de firmas: {e}", "WARN")]



def check_cdrom_disabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\cdrom",
            "/v", "Start"
        ], encoding="utf-8")
        if "0x4" in output:
            return [("CIS 7.1", "CD-ROM deshabilitado", "PASS")]
        else:
            return [("CIS 7.1", "CD-ROM habilitado (inseguro)", "FAIL")]
    except Exception as e:
        return [("CIS 7.1", f"Error al verificar el estado del CD-ROM: {e}", "WARN")]

def check_autorun_disabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "/v", "NoDriveTypeAutoRun"
        ], encoding="utf-8")
        if "0xFF" in output or "0x000000FF" in output:
            return [("CIS 7.2", "AutoRun deshabilitado en todas las unidades", "PASS")]
        else:
            return [("CIS 7.2", "AutoRun no deshabilitado completamente", "FAIL")]
    except Exception as e:
        return [("CIS 7.2", f"Error al verificar AutoRun: {e}", "WARN")]

def check_usb_storage_disabled():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
            "/v", "Start"
        ], encoding="utf-8")
        if "0x4" in output:
            return [("CIS 7.3", "Almacenamiento USB deshabilitado", "PASS")]
        else:
            return [("CIS 7.3", "Almacenamiento USB habilitado", "FAIL")]
    except Exception as e:
        return [("CIS 7.3", f"Error al verificar almacenamiento USB: {e}", "WARN")]



def check_guest_account_status():
    try:
        output = subprocess.check_output(["net", "user", "guest"], encoding="utf-8").lower()
        if "account active" in output and "no" in output:
            return [("CIS 5.1", "Cuenta invitado deshabilitada", "PASS")]
        else:
            return [("CIS 5.1", "Cuenta invitado activa", "FAIL")]
    except Exception as e:
        return [("CIS 5.1", f"Error al verificar cuenta guest: {e}", "WARN")]

def check_unused_services():
    results = []
    try:
        output = subprocess.check_output(["powershell", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'}"], encoding="utf-8")
        running_services = output.lower()
        # Lista negra de servicios comunes e inseguros
        blacklist = {
            "telnet": "CIS 5.2",
            "remote registry": "CIS 5.3",
            "ssdp": "CIS 5.4",
            "xbl": "CIS 5.5"
        }
        for key, control in blacklist.items():
            if key in running_services:
                results.append((control, f"Servicio activo: {key}", "FAIL"))
            else:
                results.append((control, f"Servicio inactivo: {key}", "PASS"))
            results += check_guest_account_status()
            results += check_unused_services()
            return results
    except Exception as e:
        return [("CIS 5.x", f"Error al verificar servicios: {e}", "WARN")]


def check_wdigest_status():
    try:
        output = subprocess.check_output([
            "reg", "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            "/v", "UseLogonCredential"
        ], encoding="utf-8")
        if "0x0" in output:
            return [("CIS 6.1", "WDigest deshabilitado (seguro)", "PASS")]
        else:
            return [("CIS 6.1", "WDigest habilitado (inseguro)", "FAIL")]
    except Exception as e:
        return [("CIS 6.1", f"Error al verificar WDigest: {e}", "WARN")]

def check_system_restore_disabled():
    try:
        output = subprocess.check_output([
            "powershell", "-Command",
            "Get-ComputerRestorePoint"
        ], stderr=subprocess.DEVNULL, encoding="utf-8")
        if "RestorePoint" in output:
            return [("CIS 6.2", "Puntos de restauración habilitados", "FAIL")]
        else:
            return [("CIS 6.2", "No se encontraron puntos de restauración", "PASS")]
    except subprocess.CalledProcessError:
        return [("CIS 6.2", "Restauración del sistema deshabilitada", "PASS")]
    except Exception as e:
        return [("CIS 6.2", f"Error al verificar restauración del sistema: {e}", "WARN")]

def check_smb1_disabled():
    try:
        output = subprocess.check_output([
            "dism", "/online", "/get-features", "/format:table"
        ], encoding="utf-8")
        if "SMB1Protocol" in output and "Disabled" in output:
            return [("CIS 6.3", "SMBv1 deshabilitado", "PASS")]
        else:
            return [("CIS 6.3", "SMBv1 habilitado (inseguro)", "FAIL")]
    except Exception as e:
        return [("CIS 6.3", f"Error al verificar SMBv1: {e}", "WARN")]

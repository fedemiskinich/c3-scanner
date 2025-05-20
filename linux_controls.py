import os
import subprocess
import re

def check_password_max_days():
    try:
        with open("/etc/login.defs", "r") as f:
            for line in f:
                if "PASS_MAX_DAYS" in line and not line.strip().startswith("#"):
                    value = int(line.split()[1])
                    return ("CIS 1.1.1", f"PASS_MAX_DAYS configurado en {value}", "PASS" if value <= 90 else "FAIL")
        return ("CIS 1.1.1", "PASS_MAX_DAYS no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.1.1", f"Error al verificar PASS_MAX_DAYS: {e}", "WARN")

def check_password_min_days():
    try:
        with open("/etc/login.defs", "r") as f:
            for line in f:
                if "PASS_MIN_DAYS" in line and not line.strip().startswith("#"):
                    value = int(line.split()[1])
                    return ("CIS 1.1.2", f"PASS_MIN_DAYS configurado en {value}", "PASS" if value >= 7 else "FAIL")
        return ("CIS 1.1.2", "PASS_MIN_DAYS no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.1.2", f"Error al verificar PASS_MIN_DAYS: {e}", "WARN")

def check_password_warn_age():
    try:
        with open("/etc/login.defs", "r") as f:
            for line in f:
                if "PASS_WARN_AGE" in line and not line.strip().startswith("#"):
                    value = int(line.split()[1])
                    return ("CIS 1.1.3", f"PASS_WARN_AGE configurado en {value}", "PASS" if value >= 7 else "FAIL")
        return ("CIS 1.1.3", "PASS_WARN_AGE no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.1.3", f"Error al verificar PASS_WARN_AGE: {e}", "WARN")

def check_shadow_file_permissions():
    try:
        stat_output = subprocess.check_output(["stat", "/etc/shadow"], encoding="utf-8")
        if "0600" in stat_output or "Access: 0600" in stat_output:
            return ("CIS 1.1.4", "Permisos /etc/shadow correctos (0600)", "PASS")
        else:
            return ("CIS 1.1.4", "Permisos incorrectos en /etc/shadow", "FAIL")
    except Exception as e:
        return ("CIS 1.1.4", f"Error al verificar permisos de /etc/shadow: {e}", "WARN")

def check_all():
    results = []
    results.append(check_password_max_days())
    results.append(check_password_min_days())
    results.append(check_password_warn_age())
    results.append(check_shadow_file_permissions())
    results.append(check_telnet_not_installed())
    results.append(check_rsh_disabled())
    results.append(check_ftp_disabled())
    results.append(check_services_not_listening())
    results.append(check_auditd_installed())
    results.append(check_auditd_service_enabled())
    results.append(check_auditd_rules_file_exists())
    results.append(check_audit_log_permissions())
    results.append(check_rsyslog_installed())
    results.append(check_rsyslog_enabled())
    results.append(check_logrotate_installed())
    results.append(check_logrotate_config_exists())

    results.append(check_password_max_days())
    results.append(check_password_min_days())
    results.append(check_password_warn_age())
    results.append(check_shadow_file_permissions())
    results.append(check_telnet_not_installed())
    results.append(check_rsh_disabled())
    results.append(check_ftp_disabled())
    results.append(check_services_not_listening())
    results.append(check_auditd_installed())
    results.append(check_auditd_service_enabled())
    results.append(check_auditd_rules_file_exists())
    results.append(check_audit_log_permissions())
  
    results.append(check_password_max_days())
    results.append(check_password_min_days())
    results.append(check_password_warn_age())
    results.append(check_shadow_file_permissions())
    results.append(check_telnet_not_installed())
    results.append(check_rsh_disabled())
    results.append(check_ftp_disabled())
    results.append(check_services_not_listening())

    results.append(check_password_max_days())
    results.append(check_password_min_days())
    results.append(check_password_warn_age())
    results.append(check_shadow_file_permissions())

    results.append(check_cron_allow_exists())
    results.append(check_cron_deny_absent())
    results.append(check_sshd_config_secure())

    results.append(check_shadow_permissions())
    results.append(check_passwd_permissions())
    results.append(check_unique_uid_0())
    results.append(check_home_dirs_exist())

    results.append(check_module_disabled("usb-storage"))
    results.append(check_module_disabled("firewire-core"))
    results.append(check_pam_password_policy())
    results.append(check_sudoers_permissions())
    results.append(check_automatic_updates_enabled())
    results.append(check_file_integrity_tool_installed())
    results.append(check_firewall_active())
    results.append(check_disk_encryption_enabled())
    results.append(check_key_management_present())
    return results

def check_disk_encryption_enabled():
    try:
        result = subprocess.check_output(["lsblk", "-o", "NAME,TYPE,MOUNTPOINT"], encoding="utf-8")
        if "crypt" in result:
            return ("CIS 13.1", "Particiones cifradas detectadas", "PASS")
        else:
            return ("CIS 13.1", "No se detecta cifrado de disco", "FAIL")
    except Exception as e:
        return ("CIS 13.1", f"Error al verificar cifrado de disco: {e}", "WARN")

def check_key_management_present():
    try:
        if os.path.exists("/etc/keys") or os.path.exists("/etc/ssl/private"):
            return ("CIS 13.2", "Infraestructura de gestión de claves presente", "PASS")
        return ("CIS 13.2", "No se detecta manejo centralizado de claves", "FAIL")
    except Exception as e:
        return ("CIS 13.2", f"Error al verificar claves: {e}", "WARN")

def check_firewall_active():
    try:
        result = subprocess.run(["ufw", "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b"Status: active" in result.stdout:
            return ("CIS 12.1", "Firewall (ufw) está activo", "PASS")
        else:
            return ("CIS 12.1", "Firewall no está activo", "FAIL")
    except Exception as e:
        return ("CIS 12.1", f"Error al verificar estado de firewall: {e}", "WARN")

def check_file_integrity_tool_installed():
    try:
        result = subprocess.run(["which", "aide"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ("CIS 11.1", "AIDE instalado para monitorear integridad", "PASS")
        else:
            return ("CIS 11.1", "No se detecta herramienta de integridad como AIDE", "FAIL")
    except Exception as e:
        return ("CIS 11.1", f"Error al verificar integridad del sistema: {e}", "WARN")

def check_automatic_updates_enabled():
    try:
        path = "/etc/apt/apt.conf.d/20auto-upgrades"
        if os.path.exists(path):
            with open(path, "r") as f:
                content = f.read()
            if '"1"' in content:
                return ("CIS 10.1", "Actualizaciones automáticas habilitadas", "PASS")
            else:
                return ("CIS 10.1", "El archivo existe pero no habilita auto-upgrades", "FAIL")
        else:
            return ("CIS 10.1", "Archivo de configuración de auto-upgrades no encontrado", "FAIL")
    except Exception as e:
        return ("CIS 10.1", f"Error al verificar actualizaciones automáticas: {e}", "WARN")

def check_sudoers_permissions():
    try:
        stat_output = subprocess.check_output(["stat", "/etc/sudoers"], encoding="utf-8")
        if "0440" in stat_output or "Access: 0440" in stat_output:
            return ("CIS 9.1", "Permisos de /etc/sudoers correctos (0440)", "PASS")
        else:
            return ("CIS 9.1", "Permisos incorrectos en /etc/sudoers", "FAIL")
    except Exception as e:
        return ("CIS 9.1", f"Error al verificar sudoers: {e}", "WARN")


def check_pam_password_policy():
    try:
        path = "/etc/pam.d/common-password"
        if os.path.exists(path):
            with open(path, "r") as f:
                content = f.read()
            if "pam_pwquality.so" in content or "pam_cracklib.so" in content:
                return ("CIS 8.1", "Política de contraseñas PAM aplicada (pwquality o cracklib)", "PASS")
            else:
                return ("CIS 8.1", "No se detecta política de contraseñas segura en PAM", "FAIL")
        else:
            return ("CIS 8.1", f"No se encuentra {path}", "FAIL")
    except Exception as e:
        return ("CIS 8.1", f"Error al verificar política PAM: {e}", "WARN")

def check_module_disabled(module):
    try:
        blacklist_file = f"/etc/modprobe.d/{module}.conf"
        if os.path.exists(blacklist_file):
            with open(blacklist_file, "r") as f:
                if f"install {module} /bin/true" in f.read():
                    return ("CIS 7.1", f"Módulo {module} está deshabilitado correctamente", "PASS")
        return ("CIS 7.1", f"Módulo {module} no está deshabilitado o falta configuración", "FAIL")
    except Exception as e:
        return ("CIS 7.1", f"Error al verificar módulo {module}: {e}", "WARN") 

def check_shadow_permissions():
    try:
        stat_output = subprocess.check_output(["stat", "/etc/shadow"], encoding="utf-8")
        if "0600" in stat_output or "Access: 0600" in stat_output:
            return ("CIS 6.1.1", "Permisos correctos en /etc/shadow (0600)", "PASS")
        else:
            return ("CIS 6.1.1", "Permisos incorrectos en /etc/shadow", "FAIL")
    except Exception as e:
        return ("CIS 6.1.1", f"Error al verificar /etc/shadow: {e}", "WARN")

def check_passwd_permissions():
    try:
        stat_output = subprocess.check_output(["stat", "/etc/passwd"], encoding="utf-8")
        if "0644" in stat_output or "Access: 0644" in stat_output:
            return ("CIS 6.1.2", "Permisos correctos en /etc/passwd (0644)", "PASS")
        else:
            return ("CIS 6.1.2", "Permisos incorrectos en /etc/passwd", "FAIL")
    except Exception as e:
        return ("CIS 6.1.2", f"Error al verificar /etc/passwd: {e}", "WARN")

def check_unique_uid_0():
    try:
        with open("/etc/passwd", "r") as f:
            root_uids = [line for line in f if line.strip().split(":")[2] == "0"]
        if len(root_uids) == 1:
            return ("CIS 6.2.1", "Solo root tiene UID 0", "PASS")
        else:
            return ("CIS 6.2.1", f"Múltiples cuentas con UID 0: {len(root_uids)}", "FAIL")
    except Exception as e:
        return ("CIS 6.2.1", f"Error al verificar UID 0: {e}", "WARN")

def check_home_dirs_exist():
    try:
        missing = []
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    user, uid, home = parts[0], int(parts[2]), parts[5]
                    if uid >= 1000 and not os.path.isdir(home):
                        missing.append(user)
        if missing:
            return ("CIS 6.2.2", f"Usuarios sin home directory: {', '.join(missing)}", "FAIL")
        else:
            return ("CIS 6.2.2", "Todos los usuarios tienen directorio home", "PASS")
    except Exception as e:
        return ("CIS 6.2.2", f"Error al verificar home directories: {e}", "WARN")

def check_cron_allow_exists():
    try:
        if os.path.exists("/etc/cron.allow"):
            return ("CIS 5.1.1", "/etc/cron.allow existe", "PASS")
        else:
            return ("CIS 5.1.1", "/etc/cron.allow no existe", "FAIL")
    except Exception as e:
        return ("CIS 5.1.1", f"Error al verificar cron.allow: {e}", "WARN")

def check_cron_deny_absent():
    try:
        if not os.path.exists("/etc/cron.deny"):
            return ("CIS 5.1.2", "/etc/cron.deny no existe (correcto)", "PASS")
        else:
            return ("CIS 5.1.2", "/etc/cron.deny existe (inseguro)", "FAIL")
    except Exception as e:
        return ("CIS 5.1.2", f"Error al verificar cron.deny: {e}", "WARN")

def check_sshd_config_secure():
    try:
        if os.path.exists("/etc/ssh/sshd_config"):
            with open("/etc/ssh/sshd_config", "r") as f:
                content = f.read()
            root_login = "PermitRootLogin no" in content
            protocol = "Protocol 2" in content
            if root_login and protocol:
                return ("CIS 5.2.1", "sshd_config seguro (root login deshabilitado, protocolo 2)", "PASS")
            else:
                details = []
                if not root_login:
                    details.append("PermitRootLogin no falta")
                if not protocol:
                    details.append("Protocol 2 falta")
                return ("CIS 5.2.1", f"sshd_config inseguro: {', '.join(details)}", "FAIL")
        else:
            return ("CIS 5.2.1", "sshd_config no encontrado", "FAIL")
    except Exception as e:
        return ("CIS 5.2.1", f"Error al verificar sshd_config: {e}", "WARN")

def check_telnet_not_installed():
    try:
        result = subprocess.run(["which", "telnet"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            return ("CIS 2.1.1", "Telnet no está instalado", "PASS")
        else:
            return ("CIS 2.1.1", "Telnet está instalado", "FAIL")
    except Exception as e:
        return ("CIS 2.1.1", f"Error al verificar Telnet: {e}", "WARN")

def check_rsh_disabled():
    try:
        result = subprocess.run(["systemctl", "is-enabled", "rsh.socket"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b"disabled" in result.stdout or result.returncode != 0:
            return ("CIS 2.1.2", "Servicio RSH deshabilitado", "PASS")
        else:
            return ("CIS 2.1.2", "RSH está habilitado", "FAIL")
    except Exception as e:
        return ("CIS 2.1.2", f"Error al verificar RSH: {e}", "WARN")

def check_ftp_disabled():
    try:
        result = subprocess.run(["systemctl", "is-enabled", "vsftpd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b"disabled" in result.stdout or result.returncode != 0:
            return ("CIS 2.1.3", "FTP deshabilitado", "PASS")
        else:
            return ("CIS 2.1.3", "FTP está habilitado", "FAIL")
    except Exception as e:
        return ("CIS 2.1.3", f"Error al verificar FTP: {e}", "WARN")

def check_services_not_listening():
    try:
        output = subprocess.check_output(["ss", "-tuln"], encoding="utf-8")
        suspicious = []
        for line in output.splitlines():
            if any(p in line for p in ["21", "23", "69"]):  # FTP, Telnet, TFTP
                suspicious.append(line.strip())
        if suspicious:
            return ("CIS 2.1.4", f"Puertos inseguros escuchando: {'; '.join(suspicious)}", "FAIL")
        else:
            return ("CIS 2.1.4", "No se detectaron servicios inseguros escuchando", "PASS")
    except Exception as e:
        return ("CIS 2.1.4", f"Error al verificar servicios en red: {e}", "WARN")

def check_auditd_installed():
    try:
        result = subprocess.run(["which", "auditctl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ("CIS 3.1.1", "auditd está instalado", "PASS")
        else:
            return ("CIS 3.1.1", "auditd no está instalado", "FAIL")
    except Exception as e:
        return ("CIS 3.1.1", f"Error al verificar auditd: {e}", "WARN")

def check_auditd_service_enabled():
    try:
        result = subprocess.run(["systemctl", "is-enabled", "auditd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b"enabled" in result.stdout:
            return ("CIS 3.1.2", "auditd está habilitado", "PASS")
        else:
            return ("CIS 3.1.2", "auditd no está habilitado", "FAIL")
    except Exception as e:
        return ("CIS 3.1.2", f"Error al verificar auditd: {e}", "WARN")

def check_auditd_rules_file_exists():
    try:
        if os.path.exists("/etc/audit/audit.rules") or os.path.exists("/etc/audit/rules.d/audit.rules"):
            return ("CIS 3.1.3", "Archivo de reglas de auditd encontrado", "PASS")
        else:
            return ("CIS 3.1.3", "Archivo de reglas de auditd no encontrado", "FAIL")
    except Exception as e:
        return ("CIS 3.1.3", f"Error al verificar reglas de auditd: {e}", "WARN")

def check_audit_log_permissions():
    try:
        stat_output = subprocess.check_output(["stat", "/var/log/audit/audit.log"], encoding="utf-8")
        if "600" in stat_output or "Access: 0600" in stat_output:
            return ("CIS 3.1.4", "Permisos de log de auditoría son seguros (0600)", "PASS")
        else:
            return ("CIS 3.1.4", "Permisos inseguros en audit.log", "FAIL")
    except Exception as e:
        return ("CIS 3.1.4", f"Error al verificar permisos de audit.log: {e}", "WARN")

def check_rsyslog_installed():
    try:
        result = subprocess.run(["which", "rsyslogd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ("CIS 4.1.1", "rsyslog está instalado", "PASS")
        else:
            return ("CIS 4.1.1", "rsyslog no está instalado", "FAIL")
    except Exception as e:
        return ("CIS 4.1.1", f"Error al verificar rsyslog: {e}", "WARN")

def check_rsyslog_enabled():
    try:
        result = subprocess.run(["systemctl", "is-enabled", "rsyslog"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b"enabled" in result.stdout:
            return ("CIS 4.1.2", "rsyslog está habilitado", "PASS")
        else:
            return ("CIS 4.1.2", "rsyslog no está habilitado", "FAIL")
    except Exception as e:
        return ("CIS 4.1.2", f"Error al verificar servicio rsyslog: {e}", "WARN")

def check_logrotate_installed():
    try:
        result = subprocess.run(["which", "logrotate"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ("CIS 4.1.3", "logrotate está instalado", "PASS")
        else:
            return ("CIS 4.1.3", "logrotate no está instalado", "FAIL")
    except Exception as e:
        return ("CIS 4.1.3", f"Error al verificar logrotate: {e}", "WARN")

def check_logrotate_config_exists():
    try:
        if os.path.exists("/etc/logrotate.conf") or os.path.isdir("/etc/logrotate.d"):
            return ("CIS 4.1.4", "Configuraciones de logrotate detectadas", "PASS")
        else:
            return ("CIS 4.1.4", "No se encontraron configuraciones de logrotate", "FAIL")
    except Exception as e:
        return ("CIS 4.1.4", f"Error al verificar configuración de logrotate: {e}", "WARN")
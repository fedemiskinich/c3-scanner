import os
import json
import subprocess

def check_daemon_json_exists():
    path = "/etc/docker/daemon.json"
    if os.path.exists(path):
        return ("CIS 1.1", f"Archivo {path} encontrado", "PASS")
    else:
        return ("CIS 1.1", f"Archivo {path} no existe", "FAIL")

def check_daemon_json_permissions():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            stat = os.stat(path)
            perms = oct(stat.st_mode)[-3:]
            if perms <= "644":
                return ("CIS 1.2", f"Permisos del daemon.json: {perms}", "PASS")
            else:
                return ("CIS 1.2", f"Permisos inseguros del daemon.json: {perms}", "FAIL")
        else:
            return ("CIS 1.2", "Archivo daemon.json no existe", "WARN")
    except Exception as e:
        return ("CIS 1.2", f"Error al verificar permisos: {e}", "WARN")

def check_rootless_mode():
    try:
        output = subprocess.check_output(["docker", "info", "--format", "'{{.SecurityOptions}}'"], encoding="utf-8")
        if "rootless" in output:
            return ("CIS 1.3", "Docker en modo rootless", "PASS")
        else:
            return ("CIS 1.3", "Docker NO está en modo rootless", "FAIL")
    except Exception as e:
        return ("CIS 1.3", f"Error al verificar modo rootless: {e}", "WARN")

def check_log_level():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                config = json.load(f)
            level = config.get("log-level", "")
            if level.lower() == "info":
                return ("CIS 1.4", "log-level configurado en 'info'", "PASS")
            else:
                return ("CIS 1.4", f"log-level mal configurado: {level}", "FAIL")
        else:
            return ("CIS 1.4", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.4", f"Error al leer daemon.json: {e}", "WARN")

def check_iptables_enabled():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                config = json.load(f)
            if config.get("iptables", True) is True:
                return ("CIS 1.5", "iptables está habilitado (por defecto)", "PASS")
            else:
                return ("CIS 1.5", "iptables está deshabilitado", "FAIL")
        else:
            return ("CIS 1.5", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.5", f"Error al leer daemon.json: {e}", "WARN")

def run_cis_docker_checks():
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    results.append(check_containers_do_not_mount_sensitive_dirs())
    results.append(check_healthcheck_configured())
    results.append(check_restart_policy())
    results.append(check_container_user_not_root())
    results.append(check_containers_have_limits())
    results.append(check_images_signed())
    results.append(check_images_from_trusted_registry())
    results.append(check_unused_images_removed())
    results.append(check_icc_disabled())
    results.append(check_default_bridge_not_used())
    results.append(check_iptables_active())
    results.append(check_ports_not_exposed())
    results.append(check_containers_drop_all_capabilities())
    results.append(check_containers_use_seccomp())
    results.append(check_containers_use_apparmor())
    results.append(check_docker_audit_logging_enabled())
    results.append(check_logging_driver_configured())
    results.append(check_containers_use_logging_driver())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    results.append(check_containers_do_not_mount_sensitive_dirs())
    results.append(check_healthcheck_configured())
    results.append(check_restart_policy())
    results.append(check_container_user_not_root())
    results.append(check_containers_have_limits())
    results.append(check_images_signed())
    results.append(check_images_from_trusted_registry())
    results.append(check_unused_images_removed())
    results.append(check_icc_disabled())
    results.append(check_default_bridge_not_used())
    results.append(check_iptables_active())
    results.append(check_ports_not_exposed())
    results.append(check_containers_drop_all_capabilities())
    results.append(check_containers_use_seccomp())
    results.append(check_containers_use_apparmor())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    results.append(check_containers_do_not_mount_sensitive_dirs())
    results.append(check_healthcheck_configured())
    results.append(check_restart_policy())
    results.append(check_container_user_not_root())
    results.append(check_containers_have_limits())
    results.append(check_images_signed())
    results.append(check_images_from_trusted_registry())
    results.append(check_unused_images_removed())
    results.append(check_icc_disabled())
    results.append(check_default_bridge_not_used())
    results.append(check_iptables_active())
    results.append(check_ports_not_exposed())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    results.append(check_containers_do_not_mount_sensitive_dirs())
    results.append(check_healthcheck_configured())
    results.append(check_restart_policy())
    results.append(check_container_user_not_root())
    results.append(check_containers_have_limits())
    results.append(check_images_signed())
    results.append(check_images_from_trusted_registry())
    results.append(check_unused_images_removed())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    results.append(check_containers_do_not_mount_sensitive_dirs())
    results.append(check_healthcheck_configured())
    results.append(check_restart_policy())
    results.append(check_container_user_not_root())
    results.append(check_containers_have_limits())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    results.append(check_running_containers_not_privileged())
    results.append(check_containers_use_readonly_fs())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    results.append(check_live_restore_enabled())
    results.append(check_user_namespace_remap())
    results.append(check_cgroup_usage())
    results.append(check_default_ulimit())
    results.append(check_authentication_plugins())
    return results
    results = []
    results.append(check_daemon_json_exists())
    results.append(check_daemon_json_permissions())
    results.append(check_rootless_mode())
    results.append(check_log_level())
    results.append(check_iptables_enabled())
    return results

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

def check_live_restore_enabled():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            if config.get("live-restore", False) is True:
                return ("CIS 1.6", "live-restore está habilitado", "PASS")
            else:
                return ("CIS 1.6", "live-restore no está habilitado", "FAIL")
        else:
            return ("CIS 1.6", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.6", f"Error al verificar live-restore: {e}", "WARN")

def check_user_namespace_remap():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            remap = config.get("userns-remap", "")
            if remap and remap != "default":
                return ("CIS 1.7", f"userns-remap configurado: {remap}", "PASS")
            else:
                return ("CIS 1.7", "userns-remap no está configurado", "FAIL")
        else:
            return ("CIS 1.7", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.7", f"Error al verificar userns-remap: {e}", "WARN")

def check_cgroup_usage():
    try:
        output = subprocess.check_output(["docker", "info"], encoding="utf-8")
        if "Cgroup Version: 2" in output or "Cgroup Version: 1" in output:
            return ("CIS 1.8", "Cgroups están en uso", "PASS")
        else:
            return ("CIS 1.8", "No se detectaron Cgroups", "FAIL")
    except Exception as e:
        return ("CIS 1.8", f"Error al verificar Cgroups: {e}", "WARN")

def check_default_ulimit():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            if "default-ulimits" in config:
                return ("CIS 1.9", "default-ulimits configurado", "PASS")
            else:
                return ("CIS 1.9", "default-ulimits no está configurado", "FAIL")
        else:
            return ("CIS 1.9", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.9", f"Error al verificar default-ulimits: {e}", "WARN")

def check_authentication_plugins():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            if config.get("authorization-plugins"):
                return ("CIS 1.10", "authorization-plugins configurado", "PASS")
            else:
                return ("CIS 1.10", "authorization-plugins no configurado", "FAIL")
        else:
            return ("CIS 1.10", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 1.10", f"Error al verificar authorization-plugins: {e}", "WARN")

def check_running_containers_not_privileged():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        failures = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"Privileged": true' in inspect:
                failures.append(cid)
        if failures:
            return ("CIS 2.1", f"Contenedores en modo privilegiado: {', '.join(failures)}", "FAIL")
        else:
            return ("CIS 2.1", "Ningún contenedor corre como privilegiado", "PASS")
    except Exception as e:
        return ("CIS 2.1", f"Error al inspeccionar contenedores: {e}", "WARN")

def check_containers_use_readonly_fs():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        failures = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"ReadonlyRootfs": true' not in inspect:
                failures.append(cid)
        if failures:
            return ("CIS 2.2", f"Contenedores sin sistema de archivos de solo lectura: {', '.join(failures)}", "FAIL")
        else:
            return ("CIS 2.2", "Todos los contenedores tienen rootfs en solo lectura", "PASS")
    except Exception as e:
        return ("CIS 2.2", f"Error al verificar rootfs de contenedores: {e}", "WARN")

def check_containers_do_not_mount_sensitive_dirs():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        findings = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            for sensitive in ["/etc", "/var", "/boot", "/usr", "/lib"]:
                if f'"Source": "{sensitive}"' in inspect:
                    findings.append((cid, sensitive))
        if findings:
            detail = ", ".join([f"{cid}:{src}" for cid, src in findings])
            return ("CIS 2.3", f"Contenedores montan directorios sensibles: {detail}", "FAIL")
        else:
            return ("CIS 2.3", "Ningún contenedor monta rutas sensibles del host", "PASS")
    except Exception as e:
        return ("CIS 2.3", f"Error al verificar mounts sensibles: {e}", "WARN")

def check_healthcheck_configured():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        missing = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"Health": null' in inspect or '"Health": {}' in inspect:
                missing.append(cid)
        if missing:
            return ("CIS 2.4", f"Contenedores sin healthcheck: {', '.join(missing)}", "FAIL")
        else:
            return ("CIS 2.4", "Todos los contenedores tienen healthcheck", "PASS")
    except Exception as e:
        return ("CIS 2.4", f"Error al verificar healthchecks: {e}", "WARN")

def check_restart_policy():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        failures = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"Name": "no"' in inspect:
                failures.append(cid)
        if failures:
            return ("CIS 2.5", f"Contenedores sin política de reinicio: {', '.join(failures)}", "FAIL")
        else:
            return ("CIS 2.5", "Todos los contenedores tienen restart policy", "PASS")
    except Exception as e:
        return ("CIS 2.5", f"Error al verificar restart policy: {e}", "WARN")

def check_container_user_not_root():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        root_containers = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"User": ""' in inspect or '"User": "0"' in inspect:
                root_containers.append(cid)
        if root_containers:
            return ("CIS 2.6", f"Contenedores corriendo como root: {', '.join(root_containers)}", "FAIL")
        else:
            return ("CIS 2.6", "Todos los contenedores usan usuarios sin privilegios", "PASS")
    except Exception as e:
        return ("CIS 2.6", f"Error al verificar usuario de contenedores: {e}", "WARN")

def check_containers_have_limits():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        missing = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"Memory": 0' in inspect or '"NanoCpus": 0' in inspect:
                missing.append(cid)
        if missing:
            return ("CIS 2.7", f"Contenedores sin límites de recursos: {', '.join(missing)}", "FAIL")
        else:
            return ("CIS 2.7", "Todos los contenedores tienen límites configurados", "PASS")
    except Exception as e:
        return ("CIS 2.7", f"Error al verificar límites de recursos: {e}", "WARN")

def check_images_signed():
    try:
        output = subprocess.check_output(["docker", "images", "--digests"], encoding="utf-8")
        lines = output.strip().split("\n")[1:]
        unsigned = []
        for line in lines:
            if "<none>" in line.split()[2]:
                unsigned.append(line.split()[0])
        if unsigned:
            return ("CIS 3.1", f"Imágenes no firmadas: {', '.join(unsigned)}", "FAIL")
        else:
            return ("CIS 3.1", "Todas las imágenes tienen firma o digest", "PASS")
    except Exception as e:
        return ("CIS 3.1", f"Error al verificar firmas de imágenes: {e}", "WARN")

def check_images_from_trusted_registry():
    try:
        output = subprocess.check_output(["docker", "images"], encoding="utf-8")
        lines = output.strip().split("\n")[1:]
        untrusted = []
        for line in lines:
            repo = line.split()[0]
            if not (repo.startswith("mycorp/") or repo.startswith("registry.mycompany.com")):
                untrusted.append(repo)
        if untrusted:
            return ("CIS 3.2", f"Imágenes desde repos no confiables: {', '.join(set(untrusted))}", "FAIL")
        else:
            return ("CIS 3.2", "Todas las imágenes provienen de registries confiables", "PASS")
    except Exception as e:
        return ("CIS 3.2", f"Error al verificar fuentes de imágenes: {e}", "WARN")

def check_unused_images_removed():
    try:
        output = subprocess.check_output(["docker", "images", "-f", "dangling=true", "-q"], encoding="utf-8")
        if output.strip():
            return ("CIS 3.3", f"Imágenes colgantes (no utilizadas): {len(output.strip().splitlines())}", "FAIL")
        else:
            return ("CIS 3.3", "No hay imágenes sin usar (dangling)", "PASS")
    except Exception as e:
        return ("CIS 3.3", f"Error al verificar imágenes no utilizadas: {e}", "WARN")

def check_icc_disabled():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            if config.get("icc", True) is False:
                return ("CIS 4.1", "Inter-container communication (icc) deshabilitado", "PASS")
            else:
                return ("CIS 4.1", "icc está habilitado", "FAIL")
        else:
            return ("CIS 4.1", "daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 4.1", f"Error al verificar icc: {e}", "WARN")

def check_default_bridge_not_used():
    try:
        output = subprocess.check_output(["docker", "network", "ls"], encoding="utf-8")
        bridge_networks = [line.split()[1] for line in output.splitlines() if "bridge" in line and not line.startswith("NETWORK")]
        output_inspect = subprocess.check_output(["docker", "ps", "-q"], encoding="utf-8")
        container_ids = output_inspect.strip().splitlines()
        using_bridge = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"bridge"' in inspect:
                using_bridge.append(cid)
        if using_bridge:
            return ("CIS 4.2", f"Contenedores usando red bridge por defecto: {', '.join(using_bridge)}", "FAIL")
        else:
            return ("CIS 4.2", "Ningún contenedor usa red bridge por defecto", "PASS")
    except Exception as e:
        return ("CIS 4.2", f"Error al verificar uso de red bridge: {e}", "WARN")

def check_iptables_active():
    try:
        output = subprocess.check_output(["docker", "info"], encoding="utf-8")
        if "iptables: true" in output.lower():
            return ("CIS 4.3", "iptables está activado", "PASS")
        else:
            return ("CIS 4.3", "iptables no está activo", "FAIL")
    except Exception as e:
        return ("CIS 4.3", f"Error al verificar iptables desde docker info: {e}", "WARN")

def check_ports_not_exposed():
    try:
        output = subprocess.check_output(["docker", "ps", "--format", "{{.ID}}"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        exposed = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"HostPort":' in inspect:
                exposed.append(cid)
        if exposed:
            return ("CIS 4.4", f"Contenedores con puertos expuestos: {', '.join(exposed)}", "FAIL")
        else:
            return ("CIS 4.4", "Ningún contenedor expone puertos", "PASS")
    except Exception as e:
        return ("CIS 4.4", f"Error al verificar puertos expuestos: {e}", "WARN")

def check_containers_drop_all_capabilities():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        failures = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", cid], encoding="utf-8")
            if '"CapDrop": []' in inspect or '"CapDrop": null' in inspect:
                failures.append(cid)
        if failures:
            return ("CIS 5.1", f"Contenedores sin 'cap-drop ALL': {', '.join(failures)}", "FAIL")
        else:
            return ("CIS 5.1", "Todos los contenedores dropean capacidades (cap-drop)", "PASS")
    except Exception as e:
        return ("CIS 5.1", f"Error al verificar cap-drop: {e}", "WARN")

def check_containers_use_seccomp():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        missing = []
        for cid in container_ids:
            seccomp = subprocess.check_output(["docker", "inspect", "--format", "{{ .HostConfig.SecurityOpt }}", cid], encoding="utf-8")
            if "seccomp" not in seccomp:
                missing.append(cid)
        if missing:
            return ("CIS 5.2", f"Contenedores sin perfil seccomp: {', '.join(missing)}", "FAIL")
        else:
            return ("CIS 5.2", "Todos los contenedores usan perfil seccomp", "PASS")
    except Exception as e:
        return ("CIS 5.2", f"Error al verificar uso de seccomp: {e}", "WARN")

def check_containers_use_apparmor():
    try:
        output = subprocess.check_output(["docker", "ps", "--quiet"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        missing = []
        for cid in container_ids:
            apparmor = subprocess.check_output(["docker", "inspect", "--format", "{{ .AppArmorProfile }}", cid], encoding="utf-8").strip()
            if not apparmor or apparmor == "unconfined":
                missing.append(cid)
        if missing:
            return ("CIS 5.3", f"Contenedores sin perfil AppArmor: {', '.join(missing)}", "FAIL")
        else:
            return ("CIS 5.3", "Todos los contenedores usan perfil AppArmor", "PASS")
    except Exception as e:
        return ("CIS 5.3", f"Error al verificar uso de AppArmor: {e}", "WARN")

def check_docker_audit_logging_enabled():
    try:
        output = subprocess.check_output(["auditctl", "-l"], encoding="utf-8")
        if "/usr/bin/dockerd" in output or "docker" in output:
            return ("CIS 6.1", "Audit logging activo para Docker", "PASS")
        else:
            return ("CIS 6.1", "Audit logging para Docker NO está configurado", "FAIL")
    except Exception as e:
        return ("CIS 6.1", f"Error al verificar auditctl: {e}", "WARN")

def check_logging_driver_configured():
    path = "/etc/docker/daemon.json"
    try:
        if os.path.exists(path):
            with open(path) as f:
                config = json.load(f)
            if config.get("log-driver", "") not in ["", "json-file"]:
                return ("CIS 6.2", f"log-driver configurado: {config.get('log-driver')}", "PASS")
            else:
                return ("CIS 6.2", "log-driver no configurado o por defecto", "FAIL")
        else:
            return ("CIS 6.2", "Archivo daemon.json no encontrado", "WARN")
    except Exception as e:
        return ("CIS 6.2", f"Error al verificar log-driver: {e}", "WARN")

def check_containers_use_logging_driver():
    try:
        output = subprocess.check_output(["docker", "ps", "-q"], encoding="utf-8")
        container_ids = output.strip().splitlines()
        failures = []
        for cid in container_ids:
            inspect = subprocess.check_output(["docker", "inspect", "--format", "{{.HostConfig.LogConfig.Type}}", cid], encoding="utf-8").strip()
            if inspect in ["", "json-file"]:
                failures.append(cid)
        if failures:
            return ("CIS 6.3", f"Contenedores con log-driver por defecto o sin configurar: {', '.join(failures)}", "FAIL")
        else:
            return ("CIS 6.3", "Todos los contenedores usan logging driver configurado", "PASS")
    except Exception as e:
        return ("CIS 6.3", f"Error al verificar logging driver en contenedores: {e}", "WARN")
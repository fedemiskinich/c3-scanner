# 🛡️ CIS Compliance Checker (C3)

**CIS Compliance Checker (C3)** es una herramienta automatizada de auditoría para validar el cumplimiento de un sistema operativo (Windows/Linux) respecto al [CIS Benchmark](https://www.cisecurity.org/benchmark/windows), el estándar de seguridad más utilizado en ambientes regulados y corporativos.

Diseñado como el hermano complementario de Hunter, **C3** proporciona una **radiografía inmediata de configuración de seguridad**, sin necesidad de instalación, agentes ni dependencias externas.

---

## 🎯 Objetivo

- Identificar configuraciones débiles o inseguras en sistemas Windows (soporte completo) y Linux (próximamente).
- Facilitar auditorías internas, cumplimiento de normativas y preparación de sistemas ante certificaciones como **ISO 27001**, **PCI-DSS**, **HIPAA**, etc.
- Exportar resultados para análisis externo o integración con soluciones como **SC2 (Security Command Center)**.

---

## 🧠 ¿Qué hace?

✅ Evalúa más de **60 controles** del benchmark oficial CIS, incluyendo:

- Políticas de contraseñas y bloqueo de cuentas
- Configuración de firewall y puertos
- Seguridad de logs y eventos
- Servicios inseguros como Telnet, NetBIOS, LLMNR, SMBv1
- Restricciones de dispositivos (USB, CD-ROM)
- Integridad de Windows Defender y actualizaciones
- Cifrado con BitLocker y claves de recuperación

---

## ⚙️ Características técnicas

| Función                             | Estado     |
|------------------------------------|------------|
| ✅ Controles CIS 1 al 13 (Windows) | Implementado |
| 📄 Exportación                     | JSON + CSV |
| 🖥️ Visualización en consola       | Con soporte de colores (PASS/FAIL/WARN) |
| 📦 Listo para integrarse con SC2  | Formato JSON estructurado |
| 🔐 Sin agentes ni conexión externa| Ideal para entornos aislados |
| 🧩 Modular                         | Facilita futuras expansiones |

---

## 🚀 Cómo usar

```bash
python cis_checker.py --mostrar            # Muestra resultados con colores
python cis_checker.py --csv                # Exporta resultados a CSV
python cis_checker.py --json               # Exporta resultados a JSON
python cis_checker.py --mostrar --csv      # Muestra y exporta
```

---

## 📁 Estructura del proyecto

```
cis_checker/
├── cis_checker.py           # Script principal
├── windows_controls.py      # Controles para sistemas Windows
├── linux_controls.py        # (próximamente)
├── exporter.py              # Exportación JSON/CSV y vista color
├── utils.py                 # Utilidades y detección de OS
```

---

## 📊 Casos de uso

- Auditorías de seguridad internas
- Validación antes de certificaciones ISO/PCI
- Monitoreo de cumplimiento en endpoints
- Integración con plataformas de gestión (como SC2)

---

## 🤝 Contribuciones

Este proyecto está en desarrollo activo. Se aceptan contribuciones, nuevos módulos y mejoras.  
**C3** forma parte del ecosistema de herramientas de seguridad creadas por [@hablemosdehacking](https://instagram.com/hablemosdehacking).

---

## 🧩 ¿Por qué usar C3?

Porque:

- No requiere instalación ni conexión externa
- Funciona offline en entornos críticos
- Es extensible y fácil de integrar a pipelines
- Está diseñado por profesionales para profesionales

---

## 🧬 Integración futura

C3 exporta findings en formato JSON estructurado compatible con **SC2 (Security Command Center)** para visualización, alertado y trazabilidad continua.

---

## 📎 Licencia

MIT – Uso libre con fines educativos y corporativos. Compartí, adaptá, mejorá.

---

**Federico Miskinich | @hablemosdehacking **  
Instagram: [@hablemosdehacking](https://instagram.com/hablemosdehacking)

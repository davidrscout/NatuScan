import re


def extract_links(text):
    return set(re.findall(r'(?:href|src)=["\']([^"\']+)["\']', text, flags=re.IGNORECASE))


def analyze_html(text):
    issues = []
    links = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', text, flags=re.IGNORECASE)
    if "<form" in text:
        issues.append("- Formularios detectados: revisa validación y CSRF.")
    if "password" in text.lower():
        issues.append("- Campo 'password' encontrado: verifica transmisión segura (HTTPS).")
    if "eval(" in text or "onclick" in text.lower():
        issues.append("- Posibles JS inline: revisa XSS.")
    if "admin" in text.lower():
        issues.append("- Referencia a 'admin': podría revelar rutas sensibles.")
    summary = "Resumen rápido:\n"
    summary += f"- Archivos/enlaces detectados: {len(set(links))}\n"
    summary += ("\n".join(issues) if issues else "- No se detectaron patrones obvios.")
    return summary

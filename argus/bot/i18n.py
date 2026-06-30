"""Internationalization for Argus OSINT bot."""

TRANSLATIONS = {
    "en": {
        "welcome": "Welcome to Argus OSINT Bot! Send me a target to scan. Use /help for commands.",
        "help_text": "/scan <target> - Scan a target\n/investigations - List investigations\n/settings - Settings\n/language - Change language",
        "scanning": "Scanning {target}... ({current}/{total} plugins)",
        "results_header": "Results for {target}:",
        "error": "Error: {error}",
        "no_results": "No results found.",
        "language_changed": "Language changed to {lang}",
        "scan_complete": "Scan complete! {success} succeeded, {failed} failed.",
        "type_prompt": "Send a target to scan (domain, IP, email, username, URL, phone).",
        "classification": "Classified as: {type}",
        "page": "Page {current}/{total}",
    },
    "fr": {
        "welcome": "Bienvenue sur Argus OSINT! Envoyez une cible a scanner. /help pour les commandes.",
        "help_text": "/scan <cible> - Scanner\n/investigations - Enquetes\n/settings - Parametres\n/language - Langue",
        "scanning": "Scan de {target}... ({current}/{total} plugins)",
        "results_header": "Resultats pour {target}:",
        "error": "Erreur: {error}",
        "no_results": "Aucun resultat.",
        "language_changed": "Langue changee en {lang}",
        "scan_complete": "Scan termine! {success} reussis, {failed} echoues.",
        "type_prompt": "Envoyez une cible (domaine, IP, email, pseudo, URL, telephone).",
        "classification": "Classifie comme: {type}",
        "page": "Page {current}/{total}",
    },
    "ar": {
        "welcome": "مرحبا بكم في Argus OSINT! أرسلوا هدفا للفحص. /help للأوامر.",
        "help_text": "/scan <هدف> - فحص\n/investigations - التحقيقات\n/settings - الإعدادات\n/language - اللغة",
        "scanning": "فحص {target}... ({current}/{total} إضافات)",
        "results_header": "نتائج {target}:",
        "error": "خطأ: {error}",
        "no_results": "لا توجد نتائج.",
        "language_changed": "تم تغيير اللغة إلى {lang}",
        "scan_complete": "اكتمل الفحص! {success} نجح، {failed} فشل.",
        "type_prompt": "أرسلوا هدفا (نطاق، IP، بريد، اسم مستخدم، URL، هاتف).",
        "classification": "تم التصنيف: {type}",
        "page": "صفحة {current}/{total}",
    },
    "es": {
        "welcome": "Bienvenido a Argus OSINT! Envia un objetivo para escanear. /help para comandos.",
        "help_text": "/scan <objetivo> - Escanear\n/investigations - Investigaciones\n/settings - Configuracion\n/language - Idioma",
        "scanning": "Escaneando {target}... ({current}/{total} plugins)",
        "results_header": "Resultados para {target}:",
        "error": "Error: {error}",
        "no_results": "Sin resultados.",
        "language_changed": "Idioma cambiado a {lang}",
        "scan_complete": "Escaneo completo! {success} exitosos, {failed} fallidos.",
        "type_prompt": "Envia un objetivo (dominio, IP, correo, usuario, URL, telefono).",
        "classification": "Clasificado como: {type}",
        "page": "Pagina {current}/{total}",
    },
}

SUPPORTED_LANGUAGES = ["en", "fr", "ar", "es"]
LANGUAGE_NAMES = {"en": "English", "fr": "Francais", "ar": "Arabic", "es": "Espanol"}
LANGUAGE_FLAGS = {"en": "GB", "fr": "FR", "ar": "SA", "es": "ES"}


def t(key: str, lang: str = "en", **kwargs) -> str:
    texts = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    text = texts.get(key, TRANSLATIONS["en"].get(key, key))
    try:
        return text.format(**kwargs)
    except (KeyError, IndexError):
        return text

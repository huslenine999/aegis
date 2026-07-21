import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "app" / "templates" / "index.html"
STYLES = ROOT / "app" / "static" / "enhanced-dashboard.css"
SCRIPT = ROOT / "app" / "static" / "enhanced-dashboard.js"
REPORT_TEMPLATE = ROOT / "app" / "templates" / "report_template.html"
ADMIN_TEMPLATE = ROOT / "app" / "templates" / "admin.html"
PROJECTS_TEMPLATE = ROOT / "app" / "templates" / "projects.html"
LANDING_TEMPLATE = ROOT / "app" / "templates" / "landing.html"


def test_dashboard_has_accessible_application_shell():
    html = TEMPLATE.read_text()

    assert 'href="#workbench-main"' in html
    assert 'id="workbench-main"' in html
    assert 'role="tablist"' in html
    assert html.count('role="tab"') == 6
    assert html.count('role="tabpanel"') == 6
    assert 'aria-live="polite"' in html
    assert '<script nonce="{{ request.state.csp_nonce }}">' in html


def test_dashboard_ids_are_unique():
    html = TEMPLATE.read_text()
    ids = re.findall(r'\bid=["\']([^"\']+)', html)
    duplicates = [element_id for element_id, count in Counter(ids).items() if count > 1]

    assert not duplicates


def test_signature_visuals_and_reduced_motion_contract():
    html = TEMPLATE.read_text()
    css = STYLES.read_text()
    js = SCRIPT.read_text()

    for element_id in (
        "uxRiskOrbit",
        "uxTelemetryScanners",
        "uxTopologyMap",
        "uxToastRegion",
    ):
        assert f'id="{element_id}"' in html

    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "async function loadTopology()" in js
    assert "function renderTelemetry(data)" in js
    assert "function showToast(" in js


def test_dashboard_assets_share_cache_version():
    html = TEMPLATE.read_text()

    css_version = re.search(r"enhanced-dashboard\.css\?v=([^\"']+)", html)
    js_version = re.search(r"enhanced-dashboard\.js\?v=([^\"']+)", html)

    assert css_version
    assert js_version
    assert css_version.group(1) == js_version.group(1)


def test_scan_controlled_values_are_not_written_to_html_sinks():
    html = TEMPLATE.read_text()

    assert "msg.textContent = String(text ?? '')" in html
    assert "content.textContent += text.charAt(i)" in html
    assert "message.textContent = String(text ?? '')" in html
    assert "msg.innerHTML = text" not in html
    assert "content.innerHTML += text.charAt(i)" not in html
    assert "<span>${text}</span>" not in html
    for field in ("f.route", "f.status", "f.vuln_type", "f.description", "f.virus"):
        assert f"escapeHtml({field})" in html


def test_report_matches_workbench_design_contract():
    html = REPORT_TEMPLATE.read_text()

    assert '<body class="report-page">' in html
    assert 'href="#report-content"' in html
    assert 'id="report-content"' in html
    assert 'id="printReportBtn"' in html
    assert "Security assessment" in html
    assert "Back to workbench" in html
    assert '<body class="crt-glow">' not in html


def test_report_includes_print_and_reduced_motion_styles():
    html = REPORT_TEMPLATE.read_text()

    assert "@media print" in html
    assert "@media (prefers-reduced-motion: reduce)" in html
    assert "break-inside: avoid" in html


def test_operations_and_project_pages_have_accessible_status_regions():
    admin = ADMIN_TEMPLATE.read_text()
    projects = PROJECTS_TEMPLATE.read_text()

    assert 'role="status"' in admin
    assert 'role="alert"' in admin
    assert 'aria-live="polite"' in projects
    assert 'id="notification-form"' in projects


def test_public_landing_has_a_clear_pilot_offer_and_auth_boundary():
    html = LANDING_TEMPLATE.read_text()

    assert "Private-by-default release security" in html
    assert "Request a founding pilot" in html
    assert 'href="/login"' in html
    assert 'id="pricing"' in html
    assert "AEGIS_COMMERCIAL_CONTACT_URL" not in html

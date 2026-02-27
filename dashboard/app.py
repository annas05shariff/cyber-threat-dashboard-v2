"""
app.py — Module 4: Complete Plotly/Dash Dashboard
Integrates all Module 1 (data) + Module 2 (charts) + Module 3 (geo/hierarchical).
Run this file to launch the full dashboard locally or on Render.

Usage:
    python dashboard/app.py

Then open: http://localhost:8050
"""
def _tab_style():
    return {
        "padding": "10px",
        "fontWeight": "bold"
    }

def _tab_selected_style():
    return {
        "padding": "10px",
        "fontWeight": "bold",
        "backgroundColor": "#119DFF",
        "color": "white"
    }

import logging
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc

from config.settings import (
    DASH_HOST, DASH_PORT, DASH_DEBUG,
    REFRESH_INTERVAL_MS, BACKEND_URL
)
from config.database import (
    get_recent_events, get_attack_type_counts,
    get_hourly_counts, get_hourly_counts_by_type,
    get_country_counts, get_mitre_technique_counts,
    get_top_cves, get_severity_distribution,
    get_event_count, get_avg_severity_score, ensure_indexes
)
from visualizations.charts import (
    build_timeseries_chart, build_attack_type_bar,
    build_severity_donut, build_cve_chart,
    build_stacked_trend, build_stacked_trend_from_hourly,
    build_severity_heatmap, build_top_countries_bar,
    compute_kpi_stats,
)
from visualizations.geo_charts import (
    build_choropleth_map, build_scatter_geo_map,
    build_mitre_treemap, build_mitre_sunburst,
    build_country_attack_bubble,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── App Initialization ─────────────────────────────────────────────────────────

app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap",
    ],
    suppress_callback_exceptions=True,
    title="Cyber Threat Dashboard",
    update_title=None,
)
server = app.server   # expose for gunicorn: gunicorn app:server


# ── Styles ────────────────────────────────────────────────────────────────────

STYLE = {
    "bg":     {"backgroundColor": "#050a0f"},
    "panel":  {
        "backgroundColor": "#0a1520",
        "border": "1px solid #0f3a5c",
        "borderRadius": "8px",
        "padding": "16px",
    },
    "header": {
        "fontFamily": "Rajdhani, monospace",
        "color": "#c8e6f5",
        "letterSpacing": "1px",
    },
    "label":  {
        "fontFamily": "Share Tech Mono, monospace",
        "fontSize": "10px",
        "color": "#527a99",
        "letterSpacing": "2px",
        "textTransform": "uppercase",
        "marginBottom": "4px",
    },
    "value":  {
        "fontFamily": "Rajdhani, monospace",
        "fontSize": "2rem",
        "fontWeight": "700",
        "color": "#ffffff",
        "margin": "0",
    },
}

SEVERITY_COLORS = {
    "Critical": "#ff3355",
    "High":     "#ff6b35",
    "Medium":   "#ffd700",
    "Low":      "#00ff88",
}


# ── KPI Card Component ─────────────────────────────────────────────────────────

def kpi_card(card_id: str, label: str, default: str = "—", accent: str = "#00d4ff") -> html.Div:
    return html.Div([
        html.Div(label, style=STYLE["label"]),
        html.Div(id=card_id, children=default, style={**STYLE["value"], "color": accent}),
    ], style={**STYLE["panel"], "textAlign": "center", "minWidth": "120px"})


# ── Filter Controls ────────────────────────────────────────────────────────────

def filter_bar() -> html.Div:
    return html.Div([
        html.Div("Filters", style={**STYLE["label"], "marginRight": "16px", "alignSelf": "center"}),
        dcc.Dropdown(
            id          = "filter-hours",
            options     = [
                {"label": "Last 6 Hours",  "value": 6},
                {"label": "Last 24 Hours", "value": 24},
                {"label": "Last 48 Hours", "value": 48},
                {"label": "Last 7 Days",   "value": 168},
            ],
            value       = 24,
            clearable   = False,
            style       = {
                "width": "160px", "backgroundColor": "#0a1520",
                "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                "fontFamily": "Rajdhani, monospace", "fontSize": "13px",
            },
        ),
        dcc.Dropdown(
            id          = "filter-attack-type",
            options     = [
                {"label": "All Types",    "value": "all"},
                {"label": "DDoS",         "value": "DDoS"},
                {"label": "Ransomware",   "value": "Ransomware"},
                {"label": "Malware",      "value": "Malware"},
                {"label": "Phishing",     "value": "Phishing"},
                {"label": "Port Scan",    "value": "Port Scan"},
                {"label": "Brute Force",  "value": "Brute Force"},
                {"label": "Exploit",      "value": "Exploit"},
                {"label": "Botnet",       "value": "Botnet"},
            ],
            value       = "all",
            clearable   = False,
            style       = {
                "width": "160px", "backgroundColor": "#0a1520",
                "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                "fontFamily": "Rajdhani, monospace", "fontSize": "13px",
            },
        ),
        dcc.Dropdown(
            id          = "filter-severity",
            options     = [
                {"label": "All Severities", "value": "all"},
                {"label": "⚫ Critical",     "value": "Critical"},
                {"label": "🔴 High",        "value": "High"},
                {"label": "🟡 Medium",      "value": "Medium"},
                {"label": "🟢 Low",         "value": "Low"},
            ],
            value       = "all",
            clearable   = False,
            style       = {
                "width": "160px", "backgroundColor": "#0a1520",
                "color": "#c8e6f5", "border": "1px solid #0f3a5c",
                "fontFamily": "Rajdhani, monospace", "fontSize": "13px",
            },
        ),
        html.Button(
            "↺  Refresh",
            id="btn-refresh",
            n_clicks=0,
            style={
                "backgroundColor": "rgba(0,212,255,0.1)",
                "color": "#00d4ff", "border": "1px solid #00d4ff",
                "borderRadius": "4px", "padding": "6px 14px",
                "fontFamily": "Rajdhani, monospace", "fontSize": "12px",
                "cursor": "pointer", "letterSpacing": "1px",
            }
        ),
    ], style={
        "display": "flex", "gap": "12px", "alignItems": "center",
        "flexWrap": "wrap", "padding": "12px 0",
    })


# ── Live Feed Row Component ────────────────────────────────────────────────────

def live_feed_item(event: dict) -> html.Div:
    sev   = event.get("severity", "Low")
    color = SEVERITY_COLORS.get(sev, "#6272a4")
    atype = event.get("attack_type", "Unknown")
    ts    = str(event.get("timestamp", ""))[:19].replace("T", " ")
    geo   = event.get("source_geo") or {}
    country = geo.get("country", "Unknown") if isinstance(geo, dict) else "Unknown"
    ip    = event.get("source_ip", "—")
    desc  = (event.get("description") or "")[:80]

    return html.Div([
        html.Div([
            html.Span(f"● {sev}", style={
                "color": color, "fontFamily": "Share Tech Mono, monospace",
                "fontSize": "10px", "marginRight": "10px", "whiteSpace": "nowrap",
            }),
            html.Span(atype, style={
                "color": "#00d4ff", "fontFamily": "Rajdhani, monospace",
                "fontWeight": "700", "fontSize": "13px", "marginRight": "10px",
            }),
            html.Span(f"{country} · {ip}", style={
                "color": "#527a99", "fontFamily": "Share Tech Mono, monospace",
                "fontSize": "10px", "marginRight": "10px",
            }),
            html.Span(ts, style={
                "color": "#355a7a", "fontFamily": "Share Tech Mono, monospace",
                "fontSize": "10px", "marginLeft": "auto",
            }),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "2px"}),
        html.Div(desc, style={
            "color": "#527a99", "fontSize": "11px",
            "fontFamily": "Rajdhani, monospace", "paddingLeft": "4px",
        }),
    ], style={
        "padding": "8px 10px",
        "borderLeft": f"2px solid {color}",
        "marginBottom": "6px",
        "backgroundColor": "rgba(255,255,255,0.02)",
        "borderRadius": "0 4px 4px 0",
    })


# ── Tab Contents ───────────────────────────────────────────────────────────────

def tab_overview():
    return html.Div([
        # KPI Row
        html.Div([
            kpi_card("kpi-total",     "Total Events",      accent="#00d4ff"),
            kpi_card("kpi-critical",  "Critical",          accent="#ff3355"),
            kpi_card("kpi-high",      "High Severity",     accent="#ff6b35"),
            kpi_card("kpi-countries", "Countries",         accent="#a78bfa"),
            kpi_card("kpi-avg-sev",   "Avg Severity",      accent="#ffd700"),
            kpi_card("kpi-top-type",  "Top Attack Type",   accent="#00ff88"),
        ], style={
            "display": "grid",
            "gridTemplateColumns": "repeat(auto-fit, minmax(130px, 1fr))",
            "gap": "12px", "marginBottom": "16px",
        }),

        # Time series — full width
        html.Div([
            dcc.Graph(id="chart-timeseries", style={"height": "260px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"], "marginBottom": "16px"}),

        # Row: attack type bar + severity donut
        html.Div([
            html.Div([
                dcc.Graph(id="chart-attack-bar", style={"height": "280px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "2"}),
            html.Div([
                dcc.Graph(id="chart-severity-donut", style={"height": "280px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "1"}),
        ], style={"display": "flex", "gap": "16px", "marginBottom": "16px", "flexWrap": "wrap"}),

        # Row: top countries + stacked trend
        html.Div([
            html.Div([
                dcc.Graph(id="chart-countries-bar", style={"height": "280px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "1"}),
            html.Div([
                dcc.Graph(id="chart-stacked-trend", style={"height": "280px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "2"}),
        ], style={"display": "flex", "gap": "16px", "marginBottom": "0", "flexWrap": "wrap"}),
    ])


def tab_geo():
    return html.Div([
        html.Div([
            dcc.Graph(id="chart-choropleth", style={"height": "400px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"], "marginBottom": "16px"}),

        html.Div([
            dcc.Graph(id="chart-scatter-geo", style={"height": "380px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"], "marginBottom": "16px"}),

        html.Div([
            dcc.Graph(id="chart-country-bubble", style={"height": "400px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"]}),
    ])


def tab_mitre():
    return html.Div([
        html.Div([
            html.Div([
                dcc.Graph(id="chart-treemap", style={"height": "440px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "1"}),
            html.Div([
                dcc.Graph(id="chart-sunburst", style={"height": "440px"}, config={"displayModeBar": False}),
            ], style={**STYLE["panel"], "flex": "1"}),
        ], style={"display": "flex", "gap": "16px", "marginBottom": "16px", "flexWrap": "wrap"}),

        html.Div([
            dcc.Graph(id="chart-heatmap", style={"height": "380px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"]}),
    ])


def tab_cve():
    return html.Div([
        html.Div([
            dcc.Graph(id="chart-cve", style={"height": "520px"}, config={"displayModeBar": False}),
        ], style={**STYLE["panel"]}),
    ])


def tab_live_feed():
    return html.Div([
        html.Div(id="live-feed-container", style={
            "maxHeight": "700px", "overflowY": "auto",
            "paddingRight": "4px",
        }),
    ], style=STYLE["panel"])


# ══ Main Layout ════════════════════════════════════════════════════════════════

app.layout = html.Div([
    # Auto-refresh interval
    dcc.Interval(id="auto-refresh", interval=REFRESH_INTERVAL_MS, n_intervals=0),

    # Store for shared data (avoids repeated DB queries across callbacks)
    dcc.Store(id="store-events"),
    dcc.Store(id="store-country"),
    dcc.Store(id="store-hourly"),
    dcc.Store(id="store-hourly-by-type"),
    dcc.Store(id="store-attack-counts"),
    dcc.Store(id="store-mitre"),
    dcc.Store(id="store-cves"),
    dcc.Store(id="store-severity"),
    dcc.Store(id="store-total-count"),
    dcc.Store(id="store-avg-severity"),

    # Header
    html.Div([
        html.Div([
            html.Div("// CYBER THREAT INTELLIGENCE", style={
                "fontFamily": "Share Tech Mono, monospace", "fontSize": "10px",
                "color": "#527a99", "letterSpacing": "4px", "marginBottom": "4px",
            }),
            html.H1("Threat Visualization Dashboard", style={
                "fontFamily": "Rajdhani, monospace", "fontSize": "1.8rem",
                "fontWeight": "700", "color": "#ffffff", "margin": "0",
                "letterSpacing": "2px",
            }),
        ]),
        html.Div([
            html.Div(id="status-indicator", children="● LIVE", style={
                "fontFamily": "Share Tech Mono, monospace", "fontSize": "11px",
                "color": "#00ff88", "letterSpacing": "2px",
                "animation": "pulse 2s infinite",
            }),
            html.Div(id="last-update", style={
                "fontFamily": "Share Tech Mono, monospace", "fontSize": "10px",
                "color": "#355a7a", "marginTop": "4px",
            }),
        ], style={"textAlign": "right"}),
    ], style={
        "display": "flex", "justifyContent": "space-between", "alignItems": "flex-end",
        "padding": "20px 24px 12px",
        "borderBottom": "1px solid #0f3a5c",
        "background": "linear-gradient(180deg, rgba(0,212,255,0.03) 0%, transparent 100%)",
    }),

    # Filter Bar
    html.Div(filter_bar(), style={"padding": "0 24px"}),

    # ── PDF Export Button + Download component ──────────────────────────────
    html.Div([
        html.Div([
            html.Button(
                "⬇  Export PDF Report",
                id       = "btn-export-pdf",
                n_clicks = 0,
                style    = {
                    "backgroundColor": "rgba(0,255,136,0.08)",
                    "color":           "#00ff88",
                    "border":          "1px solid #00ff88",
                    "borderRadius":    "4px",
                    "padding":         "7px 18px",
                    "fontFamily":      "Rajdhani, monospace",
                    "fontSize":        "12px",
                    "cursor":          "pointer",
                    "letterSpacing":   "1px",
                }
            ),
            dcc.Download(id="download-pdf"),
        ], style={"marginLeft": "auto", "display": "flex", "alignItems": "center", "gap": "10px"}),

        # Loading wrapper — shows a spinner while PDF is generating
        dcc.Loading(
            id       = "loading-pdf",
            type     = "circle",
            color    = "#00ff88",
            children = html.Div(id="export-status", style={
                "fontFamily": "Share Tech Mono, monospace",
                "fontSize":   "10px",
                "color":      "#527a99",
                "textAlign":  "right",
                "marginTop":  "4px",
                "minHeight":  "14px",
            }),
        ),
    ], style={"padding": "0 24px 8px", "display": "flex", "flexDirection": "column"}),

    # Tabs — all content pre-rendered so chart IDs always exist in the DOM
    # This ensures dropdown filter callbacks always find their output components
    dcc.Tabs(id="tabs", value="overview", style={
        "fontFamily": "Rajdhani, monospace",
        "backgroundColor": "#050a0f",
    }, children=[
        dcc.Tab(label="Overview",  value="overview", style=_tab_style(), selected_style=_tab_selected_style(), children=tab_overview()),
        dcc.Tab(label="Geo Map",   value="geo",      style=_tab_style(), selected_style=_tab_selected_style(), children=tab_geo()),
        dcc.Tab(label="MITRE",     value="mitre",    style=_tab_style(), selected_style=_tab_selected_style(), children=tab_mitre()),
        dcc.Tab(label="CVEs",      value="cve",      style=_tab_style(), selected_style=_tab_selected_style(), children=tab_cve()),
        dcc.Tab(label="Live Feed", value="feed",     style=_tab_style(), selected_style=_tab_selected_style(), children=tab_live_feed()),
    ]),

], style={
    "backgroundColor": "#050a0f",
    "minHeight": "100vh",
    "fontFamily": "Rajdhani, monospace",
})


def _tab_style():
    return {
        "backgroundColor": "#050a0f", "color": "#527a99",
        "border": "none", "borderBottom": "2px solid transparent",
        "fontFamily": "Rajdhani, monospace", "fontSize": "13px",
        "letterSpacing": "1px", "padding": "10px 20px",
    }


def _tab_selected_style():
    return {
        "backgroundColor": "#050a0f", "color": "#00d4ff",
        "border": "none", "borderBottom": "2px solid #00d4ff",
        "fontFamily": "Rajdhani, monospace", "fontSize": "13px",
        "letterSpacing": "1px", "padding": "10px 20px",
        "fontWeight": "700",
    }


# ══ Callbacks ══════════════════════════════════════════════════════════════════

# 1. Load data into stores when filter changes or auto-refresh fires
@app.callback(
    Output("store-events",          "data"),
    Output("store-country",         "data"),
    Output("store-hourly",          "data"),
    Output("store-hourly-by-type",  "data"),
    Output("store-attack-counts",   "data"),
    Output("store-mitre",           "data"),
    Output("store-cves",            "data"),
    Output("store-severity",        "data"),
    Output("store-total-count",     "data"),
    Output("store-avg-severity",    "data"),
    Output("last-update",           "children"),
    Input("auto-refresh",           "n_intervals"),
    Input("btn-refresh",            "n_clicks"),
    Input("filter-hours",           "value"),
    Input("filter-attack-type",     "value"),
    Input("filter-severity",        "value"),
)
def load_data(n_intervals, n_clicks, hours, attack_type, severity):
    from datetime import datetime
    at = attack_type if attack_type and attack_type != "all" else None
    sv = severity    if severity    and severity    != "all" else None
    try:
        events_raw      = get_recent_events(limit=500, hours_back=hours, attack_type=at, severity=sv)
        country_raw     = get_country_counts(hours_back=hours, attack_type=at, severity=sv)
        hourly_raw      = get_hourly_counts(hours_back=hours, attack_type=at, severity=sv)
        hourly_type_raw = get_hourly_counts_by_type(hours_back=hours, attack_type=at, severity=sv)
        attack_raw      = get_attack_type_counts(hours_back=hours, severity=sv)
        mitre_raw       = get_mitre_technique_counts(hours_back=hours, attack_type=at, severity=sv)
        cves_raw        = get_top_cves(limit=25)
        severity_raw    = get_severity_distribution(hours_back=hours, attack_type=at, severity=sv)
        total_count     = get_event_count(hours_back=hours, attack_type=at, severity=sv)
        avg_severity    = get_avg_severity_score(hours_back=hours, attack_type=at, severity=sv)

        ts = datetime.utcnow().strftime("Updated %H:%M:%S UTC")
        return (events_raw, country_raw, hourly_raw, hourly_type_raw,
                attack_raw, mitre_raw, cves_raw, severity_raw, total_count, avg_severity, ts)

    except Exception as e:
        logger.error(f"Data load failed: {e}")
        return [], [], [], [], [], [], [], [], 0, 0.0, f"Error: {str(e)[:40]}"


# 2. (Tab content is pre-rendered inline in dcc.Tabs — no dynamic render callback needed)


# 3. KPI cards
@app.callback(
    Output("kpi-total",     "children"),
    Output("kpi-critical",  "children"),
    Output("kpi-high",      "children"),
    Output("kpi-countries", "children"),
    Output("kpi-avg-sev",   "children"),
    Output("kpi-top-type",  "children"),
    Input("store-events",        "data"),
    Input("store-country",       "data"),
    Input("store-total-count",   "data"),
    Input("store-severity",      "data"),
    Input("store-avg-severity",  "data"),
)
def update_kpis(events, country_data, total_count, severity_data, avg_severity):
    kpi = compute_kpi_stats(events or [])
    # Accurate total from DB count (no 500-event cap)
    real_total    = total_count if total_count else kpi["total_events"]
    # Accurate avg severity from direct MongoDB aggregation (no cap)
    real_avg_sev  = avg_severity if avg_severity else kpi["avg_severity"]
    # Country count from filtered geo data
    country_count = len(country_data) if country_data else kpi["unique_countries"]
    # Critical / High counts from filtered severity distribution
    critical_count = next((s["count"] for s in (severity_data or []) if s.get("severity") == "Critical"), 0)
    high_count     = next((s["count"] for s in (severity_data or []) if s.get("severity") == "High"),     0)
    return (
        f"{real_total:,}",
        f"{critical_count:,}",
        f"{high_count:,}",
        str(country_count),
        str(real_avg_sev),
        kpi["top_attack_type"],
    )


# 4. Overview charts
@app.callback(
    Output("chart-timeseries",   "figure"),
    Output("chart-attack-bar",   "figure"),
    Output("chart-severity-donut","figure"),
    Output("chart-countries-bar","figure"),
    Output("chart-stacked-trend","figure"),
    Input("store-hourly",           "data"),
    Input("store-attack-counts",    "data"),
    Input("store-severity",         "data"),
    Input("store-country",          "data"),
    Input("store-hourly-by-type",   "data"),
)
def update_overview_charts(hourly, attack_counts, severity, country, hourly_by_type):
    return (
        build_timeseries_chart(hourly or []),
        build_attack_type_bar(attack_counts or []),
        build_severity_donut(severity or []),
        build_top_countries_bar(country or []),
        build_stacked_trend_from_hourly(hourly_by_type or []),
    )


# 5. Geo tab charts
@app.callback(
    Output("chart-choropleth",    "figure"),
    Output("chart-scatter-geo",   "figure"),
    Output("chart-country-bubble","figure"),
    Input("store-country",        "data"),
    Input("store-events",         "data"),
)
def update_geo_charts(country, events):
    return (
        build_choropleth_map(country or []),
        build_scatter_geo_map(events or []),
        build_country_attack_bubble(events or []),
    )


# 6. MITRE tab charts
@app.callback(
    Output("chart-treemap",  "figure"),
    Output("chart-sunburst", "figure"),
    Output("chart-heatmap",  "figure"),
    Input("store-mitre",     "data"),
    Input("store-events",    "data"),
)
def update_mitre_charts(mitre, events):
    return (
        build_mitre_treemap(mitre or []),
        build_mitre_sunburst(mitre or []),
        build_severity_heatmap(events or []),
    )


# 7. CVE tab
@app.callback(Output("chart-cve", "figure"), Input("store-cves", "data"))
def update_cve_chart(cves):
    return build_cve_chart(cves or [])


# 8. Live feed tab
@app.callback(Output("live-feed-container", "children"), Input("store-events", "data"))
def update_live_feed(events):
    if not events:
        return html.Div("No events — run ingestion first.", style={
            "color": "#527a99", "fontFamily": "Share Tech Mono, monospace",
            "textAlign": "center", "padding": "40px",
        })
    return [live_feed_item(e) for e in events[:100]]


# 9. PDF Export
@app.callback(
    Output("download-pdf",   "data"),
    Output("export-status",  "children"),
    Input("btn-export-pdf",  "n_clicks"),
    State("filter-hours",    "value"),    # State — not a trigger, just reads current value
    prevent_initial_call = True,
)
def export_pdf(n_clicks, hours_back):
    if not n_clicks:
        return None, ""
    try:
        from dashboard.report_generator import generate_pdf_report

        pdf_path = generate_pdf_report(hours_back=hours_back or 24)

        if not pdf_path:
            return None, "⚠ Export failed — install reportlab: pip install reportlab"

        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        ts       = datetime.utcnow().strftime("%Y%m%d_%H%M")
        filename = f"threat_report_{ts}.pdf"

        return (
            dcc.send_bytes(pdf_bytes, filename),
            f"✓ Report exported — {filename}",
        )
    except ImportError as e:
        return None, f"⚠ Missing dependency: {str(e).split('No module named ')[-1]} — run: pip install reportlab"
    except Exception as e:
        logger.error(f"PDF export error: {e}", exc_info=True)
        return None, f"⚠ Export error: {str(e)[:60]}"


# ══ Entry Point ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Ensuring DB indexes...")
    ensure_indexes()
    logger.info(f"Starting dashboard on {DASH_HOST}:{DASH_PORT}")
    app.run(
        host  = DASH_HOST,
        port  = DASH_PORT,
        debug = DASH_DEBUG,
    )

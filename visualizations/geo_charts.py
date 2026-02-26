"""
geo_charts.py — Module 3: Geospatial & Hierarchical Visualizations
  - Choropleth world map (attack intensity by country)
  - Scatter geo map (individual attack origins with bubbles)
  - MITRE ATT&CK Treemap
  - MITRE ATT&CK Sunburst
  - Attack type × country bubble chart
"""

import logging
from typing import List, Dict, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

logger = logging.getLogger(__name__)

# Import shared design system from Module 2
from visualizations.charts import COLORS, BASE_LAYOUT, _apply_base, _empty_fig, FONT_FAMILY


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CHART 1: Choropleth World Map
# ══════════════════════════════════════════════════════════════════════════════

def build_choropleth_map(country_data: List[dict]) -> go.Figure:
    """
    Choropleth world map: countries colored by threat volume.
    Hover shows count + average severity.

    Args:
        country_data: Output of database.get_country_counts()
            [{"country": "Russia", "country_code": "RU", "count": 120, "avg_severity": 7.1}, ...]
    """
    if not country_data:
        return _empty_fig("No geographic data — geo enrichment may not have run yet")

    df = pd.DataFrame(country_data)

    # Custom red-threat colorscale
    threat_colorscale = [
        [0.00, COLORS["panel"]],
        [0.15, "#0a2a1a"],
        [0.35, "#1a5c2a"],
        [0.55, "#8b7000"],
        [0.75, COLORS["high"]],
        [1.00, COLORS["critical"]],
    ]

    fig = go.Figure(go.Choropleth(
        locations          = df["country_code"],
        z                  = df["count"],
        locationmode       = "ISO-3",
        colorscale         = threat_colorscale,
        autocolorscale     = False,
        reversescale       = False,
        marker_line_color  = COLORS["border"],
        marker_line_width  = 0.5,
        colorbar = dict(
            title     = dict(text="Threat Events", font=dict(size=10, color=COLORS["muted"])),
            tickfont  = dict(size=9, color=COLORS["muted"]),
            outlinewidth = 0,
            thickness = 12,
        ),
        customdata = df[["country", "avg_severity"]].values,
        hovertemplate = (
            "<b>%{customdata[0]}</b><br>"
            "Events: %{z:,}<br>"
            "Avg Severity: %{customdata[1]:.1f}<br>"
            "<extra></extra>"
        ),
    ))

    fig.update_geos(
        showframe       = False,
        showcoastlines  = True,
        coastlinecolor  = COLORS["border"],
        showland        = True,
        landcolor       = "#0d1f2d",
        showocean       = True,
        oceancolor      = COLORS["bg"],
        showlakes       = False,
        showrivers      = False,
        showgraticules  = True,
        graticulecolor  = "rgba(15,58,92,0.3)",
        bgcolor         = COLORS["bg"],
        projection_type = "natural earth",
    )

    fig.update_layout(
        paper_bgcolor = COLORS["bg"],
        plot_bgcolor  = COLORS["bg"],
        margin        = dict(l=0, r=0, t=36, b=0),
        title         = dict(
            text    = "Global Threat Origin Map",
            font    = dict(size=13, color=COLORS["text"], family=FONT_FAMILY),
            x       = 0.01, xanchor="left",
        ),
        geo           = dict(bgcolor=COLORS["bg"]),
    )

    return fig


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CHART 2: Bubble Scatter Map (individual events)
# ══════════════════════════════════════════════════════════════════════════════

def build_scatter_geo_map(events_data: List[dict], max_points: int = 500) -> go.Figure:
    """
    Scatter map with bubbles at attack origin coordinates.
    Bubble size = severity_score, color = attack type.

    Args:
        events_data: List of threat event dicts with source_geo lat/lon
    """
    if not events_data:
        return _empty_fig("No geo-tagged events")

    rows = []
    for e in events_data[:max_points]:
        geo = e.get("source_geo")
        if isinstance(geo, dict) and geo.get("latitude") and geo.get("longitude"):
            rows.append({
                "lat":         geo["latitude"],
                "lon":         geo["longitude"],
                "country":     geo.get("country", "Unknown"),
                "attack_type": e.get("attack_type", "Unknown"),
                "severity":    e.get("severity_score", 3.0),
                "description": (e.get("description") or "")[:80],
                "timestamp":   e.get("timestamp", ""),
            })

    if not rows:
        return _empty_fig("No events with geo coordinates. Run GeoIP enrichment.")

    df = pd.DataFrame(rows)

    # Normalize bubble size
    df["size"] = (df["severity"] / 10.0 * 15 + 4).clip(4, 20)

    fig = go.Figure()

    for atype in df["attack_type"].unique():
        sub = df[df["attack_type"] == atype]
        fig.add_trace(go.Scattergeo(
            lat         = sub["lat"],
            lon         = sub["lon"],
            mode        = "markers",
            name        = atype,
            marker      = dict(
                size        = sub["size"],
                color       = COLORS.get(atype, COLORS["Unknown"]),
                opacity     = 0.75,
                line        = dict(color="rgba(255,255,255,0.1)", width=0.5),
            ),
            text        = sub["country"] + " — " + sub["attack_type"],
            customdata  = sub[["country", "attack_type", "severity", "description"]].values,
            hovertemplate = (
                "<b>%{customdata[0]}</b><br>"
                "Type: %{customdata[1]}<br>"
                "Severity: %{customdata[2]:.1f}<br>"
                "<i>%{customdata[3]}</i>"
                "<extra></extra>"
            ),
        ))

    fig.update_geos(
        showframe       = False,
        showcoastlines  = True,
        coastlinecolor  = COLORS["border"],
        showland        = True,
        landcolor       = "#0d1f2d",
        showocean       = True,
        oceancolor      = COLORS["bg"],
        showgraticules  = True,
        graticulecolor  = "rgba(15,58,92,0.2)",
        bgcolor         = COLORS["bg"],
        projection_type = "natural earth",
    )

    fig.update_layout(
        paper_bgcolor = COLORS["bg"],
        legend        = dict(
            bgcolor     = "rgba(10,21,32,0.9)",
            bordercolor = COLORS["border"],
            borderwidth = 1,
            font        = dict(size=10, family=FONT_FAMILY, color=COLORS["text"]),
            orientation = "h",
            y           = -0.05,
        ),
        margin = dict(l=0, r=0, t=36, b=0),
        title  = dict(
            text    = f"Attack Origins — {len(df)} Events",
            font    = dict(size=13, color=COLORS["text"], family=FONT_FAMILY),
            x=0.01, xanchor="left",
        ),
    )

    return fig


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CHART 3: MITRE ATT&CK Treemap
# ══════════════════════════════════════════════════════════════════════════════

def build_mitre_treemap(mitre_data: List[dict]) -> go.Figure:
    """
    Treemap: MITRE ATT&CK tactic → technique hierarchy.
    Rectangle size = event count, color = avg severity.

    Args:
        mitre_data: Output of database.get_mitre_technique_counts()
            [{"tactic": "Initial Access", "technique_id": "T1190", "technique": "...", "count": 33}, ...]
    """
    if not mitre_data:
        return _empty_fig("No MITRE ATT&CK data. Check that events have mitre fields populated.")

    df = pd.DataFrame(mitre_data)

    # Build treemap paths: root → tactic → technique
    fig = go.Figure(go.Treemap(
        labels  = (
            ["MITRE ATT&CK"] +
            df["tactic"].unique().tolist() +
            (df["technique_id"] + ": " + df["technique"].fillna("Unknown")).tolist()
        ),
        parents = (
            [""] +
            ["MITRE ATT&CK"] * df["tactic"].nunique() +
            df["tactic"].tolist()
        ),
        values  = (
            [0] +
            df.groupby("tactic")["count"].sum().reindex(df["tactic"].unique()).tolist() +
            df["count"].tolist()
        ),
        customdata = (
            [["", "", ""]] +
            [[t, "", df[df["tactic"]==t]["count"].sum()] for t in df["tactic"].unique()] +
            df[["tactic", "technique_id", "avg_severity"]].values.tolist()
        ),
        hovertemplate = (
            "<b>%{label}</b><br>"
            "Events: %{value}<br>"
            "Tactic: %{customdata[0]}<br>"
            "Technique: %{customdata[1]}<br>"
            "Avg Severity: %{customdata[2]:.1f}"
            "<extra></extra>"
        ),
        marker = dict(
            colorscale = [
                [0.0, COLORS["panel"]],
                [0.3, "#1a5c2a"],
                [0.6, "#8b7000"],
                [0.8, COLORS["high"]],
                [1.0, COLORS["critical"]],
            ],
            colors = (
                [0] +
                list(df.groupby("tactic")["avg_severity"].mean().reindex(df["tactic"].unique())) +
                df["avg_severity"].tolist()
            ),
            cmin       = 0,
            cmax       = 10,
            showscale  = True,
            colorbar   = dict(
                title     = dict(text="Avg Sev", font=dict(size=9, color=COLORS["muted"])),
                tickfont  = dict(size=8, color=COLORS["muted"]),
                outlinewidth = 0,
                thickness = 10,
            ),
        ),
        textfont    = dict(family=FONT_FAMILY, size=11),
        pathbar     = dict(visible=True, edgeshape="<"),
        tiling      = dict(packing="squarify"),
    ))

    fig.update_layout(
        paper_bgcolor = COLORS["bg"],
        margin        = dict(l=0, r=0, t=36, b=0),
        title         = dict(
            text    = "MITRE ATT&CK Technique Coverage",
            font    = dict(size=13, color=COLORS["text"], family=FONT_FAMILY),
            x=0.01, xanchor="left",
        ),
    )

    return fig


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CHART 4: MITRE ATT&CK Sunburst
# ══════════════════════════════════════════════════════════════════════════════

def build_mitre_sunburst(mitre_data: List[dict]) -> go.Figure:
    """
    Sunburst chart: same data as treemap, radial layout.
    Inner ring = MITRE tactics, outer ring = techniques.
    Great for executive presentations.
    """
    if not mitre_data:
        return _empty_fig("No MITRE data")

    df = pd.DataFrame(mitre_data)

    # Tactic colors — consistent with MITRE official colors
    TACTIC_COLORS = {
        "Initial Access":       COLORS["critical"],
        "Execution":            COLORS["high"],
        "Persistence":          COLORS["medium"],
        "Privilege Escalation": "#a78bfa",
        "Defense Evasion":      "#00d4ff",
        "Credential Access":    COLORS["low"],
        "Discovery":            "#00ff88",
        "Lateral Movement":     "#ff79c6",
        "Collection":           "#ffb86c",
        "Command and Control":  "#ff5555",
        "Exfiltration":         "#f1fa8c",
        "Impact":               COLORS["critical"],
    }

    tactic_list     = df["tactic"].unique().tolist()
    technique_labels= (df["technique_id"] + ": " + df["technique"].fillna("")).tolist()

    fig = go.Figure(go.Sunburst(
        labels  = ["ATT&CK"] + tactic_list + technique_labels,
        parents = [""] + ["ATT&CK"] * len(tactic_list) + df["tactic"].tolist(),
        values  = (
            [0] +
            df.groupby("tactic")["count"].sum().reindex(tactic_list).tolist() +
            df["count"].tolist()
        ),
        marker  = dict(
            colors = (
                ["rgba(0,0,0,0)"] +
                [TACTIC_COLORS.get(t, COLORS["Unknown"]) for t in tactic_list] +
                [TACTIC_COLORS.get(t, COLORS["Unknown"]) for t in df["tactic"]]
            ),
            line   = dict(color=COLORS["bg"], width=1.5),
        ),
        branchvalues   = "total",
        textfont       = dict(family=FONT_FAMILY, size=10, color="white"),
        hovertemplate  = "<b>%{label}</b><br>Events: %{value}<extra></extra>",
        insidetextorientation = "radial",
    ))

    fig.update_layout(
        paper_bgcolor = COLORS["bg"],
        margin        = dict(l=0, r=0, t=36, b=0),
        title         = dict(
            text    = "ATT&CK Tactic & Technique Distribution",
            font    = dict(size=13, color=COLORS["text"], family=FONT_FAMILY),
            x=0.01, xanchor="left",
        ),
    )

    return fig


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — CHART 5: Attack Type × Country Bubble Chart
# ══════════════════════════════════════════════════════════════════════════════

def build_country_attack_bubble(events_data: List[dict], top_countries: int = 10) -> go.Figure:
    """
    Bubble chart: X = attack type, Y = country, bubble size = event count,
    color = average severity. Shows the exact combination of threats per nation.
    """
    if not events_data:
        return _empty_fig("No data")

    df = pd.DataFrame(events_data)

    if "source_geo" in df.columns:
        df["country"] = df["source_geo"].apply(
            lambda g: g.get("country", "Unknown") if isinstance(g, dict) else "Unknown"
        )
    elif "country" not in df.columns:
        return _empty_fig("Country data not available")

    df = df[df["country"] != "Unknown"]

    # Filter to top N countries
    top = df["country"].value_counts().head(top_countries).index
    df  = df[df["country"].isin(top)]

    agg = df.groupby(["country", "attack_type"]).agg(
        count        = ("attack_type", "count"),
        avg_severity = ("severity_score", "mean"),
    ).reset_index()

    fig = go.Figure(go.Scatter(
        x           = agg["attack_type"],
        y           = agg["country"],
        mode        = "markers",
        marker      = dict(
            size        = (agg["count"] / agg["count"].max() * 40 + 8).clip(8, 48),
            color       = agg["avg_severity"],
            colorscale  = [
                [0.0, COLORS["panel"]],
                [0.4, "#1a5c2a"],
                [0.7, COLORS["medium"]],
                [0.9, COLORS["high"]],
                [1.0, COLORS["critical"]],
            ],
            cmin        = 0,
            cmax        = 10,
            showscale   = True,
            colorbar    = dict(
                title     = dict(text="Avg Sev", font=dict(size=9, color=COLORS["muted"])),
                tickfont  = dict(size=9, color=COLORS["muted"]),
                outlinewidth=0, thickness=10,
            ),
            line        = dict(color="rgba(255,255,255,0.1)", width=0.5),
        ),
        customdata  = agg[["country", "attack_type", "count", "avg_severity"]].values,
        hovertemplate = (
            "<b>%{customdata[0]}</b><br>"
            "Attack: %{customdata[1]}<br>"
            "Events: %{customdata[2]}<br>"
            "Avg Severity: %{customdata[3]:.1f}"
            "<extra></extra>"
        ),
    ))

    fig.update_layout(
        xaxis = dict(
            showgrid   = True,
            gridcolor  = COLORS["grid"],
            tickangle  = -35,
            tickfont   = dict(size=10),
        ),
        yaxis = dict(
            showgrid  = True,
            gridcolor = COLORS["grid"],
            tickfont  = dict(size=10),
        ),
    )

    return _apply_base(fig, "Attack Type vs Country — Bubble Matrix")

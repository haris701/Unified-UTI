"""Theme and reusable presentation helpers for the Streamlit dashboard."""

from __future__ import annotations

from html import escape

import streamlit as st


STYLES = """
<style>
:root {
  --uti-bg: #09111f;
  --uti-surface: #0f1b2d;
  --uti-surface-raised: #132239;
  --uti-border: #22334a;
  --uti-text: #e7edf7;
  --uti-muted: #94a3b8;
  --uti-blue: #4b91ff;
  --uti-cyan: #53c7d7;
  --uti-green: #40c99a;
  --uti-amber: #e4ae5c;
  --uti-red: #ec7777;
}

html, body, [class*="css"] {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}
.stApp { background: var(--uti-bg); color: var(--uti-text); }
[data-testid="stAppViewContainer"] { background: var(--uti-bg); }
[data-testid="stHeader"] { background: rgba(9, 17, 31, .96); }
[data-testid="stMain"] { background: var(--uti-bg); }
[data-testid="stSidebar"] {
  background: #0b1525;
  border-right: 1px solid var(--uti-border);
}
[data-testid="stSidebar"] > div:first-child { padding: 1.15rem .85rem 1.5rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] > label { color: var(--uti-muted); font-size: .83rem; }
[data-testid="stSidebar"] [data-testid="stRadio"] label {
  padding: .52rem .62rem; border-radius: 9px; margin: .14rem 0;
  transition: background-color .15s ease, color .15s ease;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover { background: #12233a; }
[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
  background: #132a47; border-left: 3px solid var(--uti-blue); color: #eaf2ff;
}
[data-testid="stMainBlockContainer"] { padding: 2.75rem clamp(1.1rem, 3vw, 2.7rem) 3.5rem; max-width: 1560px; }

h1, h2, h3 { color: var(--uti-text); letter-spacing: -.025em; }
h1 { font-weight: 650; }
p, label, li { color: #c7d2e2; line-height: 1.55; }
[data-testid="stCaptionContainer"] p, .uti-muted { color: var(--uti-muted) !important; }

[data-testid="stMetric"] {
  background: var(--uti-surface);
  border: 1px solid var(--uti-border);
  border-radius: 12px;
  padding: 1rem 1.1rem;
  box-shadow: 0 8px 24px rgba(0, 0, 0, .08);
}
[data-testid="stMetricLabel"] { color: var(--uti-muted); }
[data-testid="stMetricValue"] { color: var(--uti-text); font-weight: 650; }

[data-testid="stTextInput"] input, [data-testid="stNumberInput"] input,
[data-testid="stSelectbox"] > div > div, [data-testid="stMultiSelect"] > div > div {
  background: #0d192a;
  border-color: #2a3c55;
  border-radius: 9px;
}
[data-testid="stTextInput"] input:focus { border-color: var(--uti-blue); box-shadow: 0 0 0 1px var(--uti-blue); }
[data-testid="stTextInput"] input::placeholder { color: #75869e; opacity: 1; }

div.stButton > button, div.stFormSubmitButton > button {
  min-height: 2.8rem;
  border-radius: 9px;
  border: 1px solid #3478dc;
  background: #2563c5;
  color: #fff;
  font-weight: 600;
  transition: background-color .15s ease, border-color .15s ease, transform .15s ease;
}
div.stButton > button:hover, div.stFormSubmitButton > button:hover {
  border-color: #67a2ff;
  background: #3175d4;
  color: #fff;
  transform: translateY(-1px);
}
[data-testid="stForm"] {
  background: var(--uti-surface);
  border: 1px solid var(--uti-border);
  border-radius: 16px;
  padding: clamp(1rem, 2vw, 1.5rem);
  box-shadow: 0 14px 38px rgba(0, 0, 0, .12);
}
[data-testid="stExpander"] {
  background: #0d192a;
  border: 1px solid var(--uti-border);
  border-radius: 11px;
}
[data-testid="stExpander"] summary { color: var(--uti-text); }
[data-testid="stDataFrame"] {
  border: 1px solid var(--uti-border);
  border-radius: 12px;
  overflow: hidden;
  background: var(--uti-surface);
}
[data-testid="stAlert"] { border-radius: 10px; }
[data-testid="stTabs"] [role="tablist"] { gap: .35rem; border-bottom: 1px solid var(--uti-border); }
[data-testid="stTabs"] button[role="tab"] {
  color: var(--uti-muted); border-radius: 8px 8px 0 0; padding: .55rem .85rem;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
  color: #dcecff; border-bottom: 2px solid var(--uti-blue); background: rgba(75, 145, 255, .08);
}
[data-testid="stLinkButton"] a {
  border-color: #315b8e; background: #122742; border-radius: 9px; color: #dcecff;
}
[data-testid="stLinkButton"] a:hover { border-color: var(--uti-cyan); color: #fff; }
hr { border-color: var(--uti-border); }

.uti-brand { display: flex; align-items: center; gap: .72rem; margin: .3rem 0 1.45rem; }
.uti-brand-mark {
  display: grid; place-items: center; width: 2.65rem; height: 2.65rem;
  border: 1px solid #315b8e; border-radius: 10px; color: #dcecff;
  background: #102746; font-weight: 750; font-size: 1.05rem;
}
.uti-brand-title { color: var(--uti-text); font-size: 1.02rem; font-weight: 700; line-height: 1.1; }
.uti-brand-subtitle { color: var(--uti-muted); font-size: .69rem; letter-spacing: .12em; margin-top: .26rem; text-transform: uppercase; }
.uti-section-label { color: var(--uti-muted); font-size: .68rem; font-weight: 650; letter-spacing: .13em; text-transform: uppercase; margin: .4rem 0 .65rem; }
.uti-eyebrow { color: var(--uti-cyan); display: block; font-size: .72rem; font-weight: 650; letter-spacing: .13em; line-height: 1.5; padding-top: .12rem; text-transform: uppercase; margin-bottom: .45rem; }
.uti-page-title { color: var(--uti-text); font-size: 2rem; line-height: 1.15; font-weight: 680; letter-spacing: -.035em; margin: 0 0 .45rem; }
.uti-page-subtitle { color: var(--uti-muted); font-size: .96rem; line-height: 1.5; max-width: 72rem; overflow-wrap: anywhere; margin: 0 0 1.35rem; }
.uti-help-copy { color: var(--uti-muted); font-size: .86rem; line-height: 1.6; max-width: 72rem; overflow-wrap: anywhere; margin: .35rem 0 .8rem; }
.uti-panel, .uti-metric-card, .uti-collector-card, .uti-empty {
  background: var(--uti-surface); border: 1px solid var(--uti-border); border-radius: 13px;
}
.uti-panel { padding: 1.15rem 1.25rem; margin: .4rem 0 .75rem; }
.uti-metric-card { padding: 1rem 1.05rem; min-height: 6.3rem; box-shadow: 0 8px 22px rgba(0, 0, 0, .08); }
.uti-metric-label { color: var(--uti-muted); font-size: .77rem; font-weight: 550; }
.uti-metric-value { color: var(--uti-text); font-size: 1.8rem; font-weight: 680; letter-spacing: -.04em; margin-top: .3rem; }
.uti-metric-note { color: var(--uti-muted); font-size: .73rem; margin-top: .18rem; }
.uti-collector-card { padding: 1rem 1.05rem; min-height: 6.7rem; box-shadow: 0 8px 22px rgba(0, 0, 0, .08); }
.uti-collector-head { display: flex; justify-content: space-between; align-items: center; gap: .7rem; }
.uti-collector-name { color: var(--uti-text); font-size: .98rem; font-weight: 650; }
.uti-collector-status { border-radius: 999px; padding: .18rem .55rem; font-size: .69rem; font-weight: 650; text-transform: uppercase; letter-spacing: .04em; }
.uti-status-ok { color: #a2f0d3; background: rgba(64, 201, 154, .13); }
.uti-status-warn { color: #f1d49e; background: rgba(228, 174, 92, .13); }
.uti-status-error { color: #ffc0c0; background: rgba(236, 119, 119, .13); }
.uti-status-idle { color: #bac6d7; background: rgba(148, 163, 184, .12); }
.uti-collector-meta { color: var(--uti-muted); font-size: .79rem; line-height: 1.5; margin-top: .7rem; overflow-wrap: anywhere; }
.uti-empty { text-align: center; padding: 2.4rem 1rem; margin: .65rem 0; box-shadow: 0 8px 24px rgba(0, 0, 0, .06); }
.uti-empty-mark { color: var(--uti-blue); font-size: 1.3rem; font-weight: 700; margin-bottom: .45rem; }
.uti-empty-title { color: var(--uti-text); font-size: 1rem; font-weight: 650; }
.uti-empty-copy { color: var(--uti-muted); font-size: .84rem; margin: .35rem auto 0; max-width: 34rem; }
.uti-inline-meta { color: var(--uti-muted); font-size: .78rem; }
.uti-evidence-card { background: #0d192a; border: 1px solid var(--uti-border); border-radius: 10px; padding: .95rem 1rem; margin: .5rem 0; }
.uti-evidence-value { color: #dce6f4; font-size: .87rem; line-height: 1.55; overflow-wrap: anywhere; }
.uti-badge { display: inline-block; padding: .19rem .55rem; border: 1px solid #315078; border-radius: 999px; color: #b9d6ff; background: rgba(53, 111, 183, .12); font-size: .72rem; }
.uti-disclaimer { border-left: 2px solid var(--uti-cyan); padding: .3rem 0 .3rem .75rem; color: var(--uti-muted); font-size: .8rem; margin: .7rem 0; }
.uti-help-copy { background: rgba(148, 163, 184, .055); border-left: 2px solid #315b8e; border-radius: 0 8px 8px 0; padding: .65rem .8rem; }
div[data-testid="stVerticalBlockBorderWrapper"] { border-color: var(--uti-border) !important; }
div.stDownloadButton > button { width: 100%; min-height: 2.65rem; border-radius: 8px; border-color: #315b8e; background: #122742; color: #dcecff; font-weight: 600; }
div.stDownloadButton > button:hover { border-color: var(--uti-cyan); background: #173452; color: #fff; }
[data-testid="stDataFrame"] [role="columnheader"] { color: #dce6f4; }
[data-testid="stDataFrame"] [role="row"]:hover { background: rgba(75, 145, 255, .06); }
.uti-brand-mark { position: relative; box-shadow: inset 0 0 0 1px rgba(83,199,215,.10); }
.uti-brand-mark:after { content: ""; width: .42rem; height: .42rem; position: absolute; right: .34rem; bottom: .32rem; border-radius: 50%; background: var(--uti-cyan); box-shadow: 0 0 9px rgba(83,199,215,.35); }

@media (max-width: 800px) {
  [data-testid="stMainBlockContainer"] { padding: 1.5rem .85rem 2.2rem; }
  [data-testid="stSidebar"] > div:first-child { padding-left: .55rem; padding-right: .55rem; }
  .uti-page-title { font-size: 1.55rem; line-height: 1.2; }
  .uti-page-subtitle { font-size: .9rem; }
  .uti-metric-card { min-height: auto; padding: .75rem; }
  .uti-metric-value { font-size: 1.45rem; }
  .uti-collector-card { min-height: auto; }
  [data-testid="stTabs"] [role="tablist"] { overflow-x: auto; }
}
</style>
"""


def apply_theme() -> None:
    """Inject restrained component polish on top of the Streamlit theme."""
    st.markdown(STYLES, unsafe_allow_html=True)


def page_header(eyebrow: str, title: str, subtitle: str) -> None:
    """Render a consistent page heading with escaped dynamic text."""
    st.markdown(
        '<div class="uti-eyebrow">{}</div><div class="uti-page-title">{}</div>'
        '<div class="uti-page-subtitle">{}</div>'.format(
            escape(eyebrow), escape(title), escape(subtitle)
        ),
        unsafe_allow_html=True,
    )


def empty_state(title: str, description: str) -> None:
    """Render an understated empty state without sample data."""
    st.markdown(
        '<div class="uti-empty"><div class="uti-empty-mark">UTI /</div>'
        '<div class="uti-empty-title">{}</div><div class="uti-empty-copy">{}</div></div>'.format(
            escape(title), escape(description)
        ),
        unsafe_allow_html=True,
    )

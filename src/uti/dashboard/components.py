"""Small reusable display components for Unified-UTI's Streamlit UI."""

from __future__ import annotations

from html import escape

import streamlit as st

from uti.services import CollectorExecutionSummary


def render_brand() -> None:
    """Display the product mark and name in the navigation sidebar."""
    st.markdown(
        '<div class="uti-brand"><div class="uti-brand-mark">U</div><div>'
        '<div class="uti-brand-title">Unified-UTI</div>'
        '<div class="uti-brand-subtitle">Intelligence workspace</div></div></div>',
        unsafe_allow_html=True,
    )


def section_label(label: str) -> None:
    st.markdown(f'<div class="uti-section-label">{escape(label)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value: str | int, note: str = "") -> None:
    st.markdown(
        '<div class="uti-metric-card"><div class="uti-metric-label">{}</div>'
        '<div class="uti-metric-value">{}</div><div class="uti-metric-note">{}</div></div>'.format(
            escape(label), escape(str(value)), escape(note)
        ),
        unsafe_allow_html=True,
    )


def collector_card(name: str, summary: CollectorExecutionSummary | None) -> None:
    if summary is None:
        label, css_class, details = "Not run", "uti-status-idle", "No execution in this session"
    elif summary.timed_out:
        label, css_class = "Timed out", "uti-status-warn"
        details = f"{summary.findings_count} findings · return code unavailable"
    elif summary.error:
        label, css_class = "Issue", "uti-status-error"
        details = f"{summary.findings_count} findings · {summary.error}"
    elif summary.returncode == 0:
        label, css_class = "Complete", "uti-status-ok"
        details = f"{summary.findings_count} findings · process exited successfully"
    elif summary.returncode is not None:
        label, css_class = "Non-zero exit", "uti-status-warn"
        details = f"{summary.findings_count} findings · return code {summary.returncode}"
    else:
        label, css_class = "No result", "uti-status-idle"
        details = "Collector returned no execution status"

    st.markdown(
        '<div class="uti-collector-card"><div class="uti-collector-head">'
        '<div class="uti-collector-name">{}</div><div class="uti-collector-status {}">{}</div>'
        '</div><div class="uti-collector-meta">{}</div></div>'.format(
            escape(name), css_class, escape(label), escape(details)
        ),
        unsafe_allow_html=True,
    )


def evidence_card(value: str, evidence_type: str, source_tool: str) -> None:
    st.markdown(
        '<div class="uti-evidence-card"><div class="uti-evidence-value">{}</div>'
        '<div style="margin-top:.65rem"><span class="uti-badge">{}</span> '
        '<span class="uti-inline-meta">via {}</span></div></div>'.format(
            escape(value), escape(evidence_type), escape(source_tool)
        ),
        unsafe_allow_html=True,
    )

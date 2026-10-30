#!/usr/bin/env python3

import os
import json
import argparse
from typing import List, Dict, Any

UI_COMMON_STYLES = """
    :root {
        --ui-bg: #0b0f19;
        --ui-paper: #111827;
        --ui-paper-elevated: #1f2937;
        --ui-paper-subtle: #162032;
        --ui-border: rgba(148, 163, 184, 0.14);
        --ui-border-hover: rgba(148, 163, 184, 0.28);
        --ui-text-primary: #f8fafc;
        --ui-text-secondary: #94a3b8;
        --ui-text-muted: #64748b;
        --ui-primary: #1976d2;
        --ui-primary-light: #42a5f5;
        --ui-primary-dark: #1565c0;
        --ui-primary-bg: rgba(25, 118, 210, 0.12);
        --ui-success: #2e7d32;
        --ui-success-light: #4caf50;
        --ui-success-bg: rgba(46, 125, 50, 0.14);
        --ui-warning: #ed6c02;
        --ui-warning-light: #ff9800;
        --ui-warning-bg: rgba(237, 108, 2, 0.14);
        --ui-error: #d32f2f;
        --ui-error-light: #ef5350;
        --ui-error-bg: rgba(211, 47, 47, 0.14);
        --ui-font: "Roboto", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        --ui-radius-sm: 6px;
        --ui-radius-md: 10px;
        --ui-radius-lg: 14px;
        --ui-radius-full: 9999px;
        --ui-shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.25);
        --ui-shadow-md: 0 4px 12px 0 rgba(0, 0, 0, 0.35);
        --ui-shadow-lg: 0 10px 24px -3px rgba(0, 0, 0, 0.45);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        background: var(--ui-bg);
        color: var(--ui-text-primary);
        font-family: var(--ui-font);
        line-height: 1.5;
        letter-spacing: 0.01em;
        padding: 32px 20px 48px;
        -webkit-font-smoothing: antialiased;
    }
    .ui-container {
        max-width: 1120px;
        margin: 0 auto;
    }
    .ui-app-bar {
        border-bottom: 1px solid var(--ui-border);
        padding-bottom: 20px;
        margin-bottom: 28px;
    }
    .ui-breadcrumbs {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 0.75rem;
        font-weight: 500;
        color: var(--ui-text-muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 8px;
    }
    .ui-breadcrumbs a {
        color: var(--ui-primary-light);
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    .ui-breadcrumbs a:hover {
        text-decoration: underline;
    }
    .ui-chevron {
        color: var(--ui-text-muted);
        flex-shrink: 0;
        display: inline-block;
        vertical-align: middle;
    }
    .ui-title {
        color: var(--ui-text-primary);
        font-size: 1.75rem;
        font-weight: 600;
        letter-spacing: -0.02em;
    }
    .ui-subtitle {
        color: var(--ui-text-secondary);
        font-size: 0.875rem;
        margin-top: 6px;
        line-height: 1.55;
    }
    .ui-paper {
        background: var(--ui-paper);
        border: 1px solid var(--ui-border);
        border-radius: var(--ui-radius-md);
        box-shadow: var(--ui-shadow-sm);
        margin-bottom: 24px;
        overflow: hidden;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .ui-paper:hover {
        border-color: var(--ui-border-hover);
    }
    .ui-card-header {
        padding: 18px 24px 14px;
        border-bottom: 1px solid var(--ui-border);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        flex-wrap: wrap;
    }
    .ui-card-header h2 {
        font-size: 1.0625rem;
        font-weight: 600;
        color: var(--ui-text-primary);
        letter-spacing: -0.01em;
    }
    .ui-card-content {
        padding: 22px 24px;
    }
    .ui-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        font-family: var(--ui-font);
        font-size: 0.8125rem;
        font-weight: 500;
        text-transform: none;
        letter-spacing: 0.02em;
        padding: 7px 16px;
        border-radius: var(--ui-radius-sm);
        border: 1px solid transparent;
        cursor: pointer;
        text-decoration: none;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        white-space: nowrap;
    }
    .ui-btn-primary {
        background: var(--ui-primary);
        color: #ffffff;
        box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }
    .ui-btn-primary:hover {
        background: var(--ui-primary-light);
        box-shadow: 0 2px 6px rgba(25, 118, 210, 0.4);
    }
    .ui-btn-outlined {
        background: transparent;
        border-color: var(--ui-border);
        color: var(--ui-text-secondary);
    }
    .ui-btn-outlined:hover {
        background: rgba(255, 255, 255, 0.04);
        color: var(--ui-text-primary);
        border-color: var(--ui-border-hover);
    }
    .ui-btn-outlined.active {
        background: var(--ui-primary-bg);
        color: var(--ui-primary-light);
        border-color: rgba(66, 165, 245, 0.5);
    }
    .ui-btn-icon {
        display: inline-block;
        vertical-align: middle;
        flex-shrink: 0;
    }
    .ui-icon-ext {
        display: inline-block;
        vertical-align: middle;
        margin-left: 4px;
        opacity: 0.75;
    }
    .ui-nav-link {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        color: var(--ui-primary-light);
        text-decoration: none;
        font-size: 0.8125rem;
        font-weight: 500;
    }
    .ui-nav-link:hover {
        text-decoration: underline;
    }
    .ui-chip {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        height: 24px;
        padding: 0 10px;
        font-size: 0.75rem;
        font-weight: 500;
        letter-spacing: 0.01em;
        border-radius: var(--ui-radius-full);
        border: 1px solid transparent;
        white-space: nowrap;
    }
    .ui-chip-default {
        background: #1f2937;
        color: var(--ui-text-secondary);
        border-color: var(--ui-border);
    }
    .ui-chip-primary {
        background: var(--ui-primary-bg);
        color: var(--ui-primary-light);
        border-color: rgba(66, 165, 245, 0.35);
    }
    .ui-chip-success {
        background: var(--ui-success-bg);
        color: var(--ui-success-light);
        border-color: rgba(76, 175, 80, 0.35);
    }
    .ui-chip-warning {
        background: var(--ui-warning-bg);
        color: var(--ui-warning-light);
        border-color: rgba(255, 152, 0, 0.35);
    }
    .ui-chip-error {
        background: var(--ui-error-bg);
        color: var(--ui-error-light);
        border-color: rgba(239, 83, 80, 0.35);
    }
    .ui-table-wrapper {
        overflow-x: auto;
    }
    table.ui-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        font-size: 0.8125rem;
    }
    table.ui-table th {
        background: #0d1424;
        color: var(--ui-text-secondary);
        font-weight: 600;
        text-align: left;
        padding: 12px 16px;
        border-bottom: 1px solid var(--ui-border);
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        white-space: nowrap;
    }
    table.ui-table td {
        padding: 13px 16px;
        border-bottom: 1px solid var(--ui-border);
        color: var(--ui-text-primary);
        position: relative;
    }
    table.ui-table tbody tr {
        transition: background-color 0.15s ease;
    }
    table.ui-table tbody tr:hover td {
        background: rgba(255, 255, 255, 0.025);
    }
    .ui-val-good { color: var(--ui-success-light); font-weight: 600; }
    .ui-val-warn { color: var(--ui-warning-light); font-weight: 600; }
    .ui-val-bad { color: var(--ui-error-light); font-weight: 600; }
    .ui-tooltip-anchor {
        position: relative;
        cursor: pointer;
        display: inline-block;
    }
    .ui-tooltip-anchor::after {
        content: attr(data-tooltip);
        position: absolute;
        bottom: 130%;
        left: 50%;
        transform: translateX(-50%);
        background: #1e293b;
        color: #ffffff;
        padding: 6px 11px;
        border-radius: var(--ui-radius-sm);
        font-size: 0.6875rem;
        font-weight: 500;
        white-space: nowrap;
        border: 1px solid rgba(148, 163, 184, 0.25);
        box-shadow: var(--ui-shadow-lg);
        opacity: 0;
        visibility: hidden;
        pointer-events: none;
        transition: opacity 0.15s ease, transform 0.15s ease, visibility 0.15s;
        z-index: 1000;
    }
    .ui-tooltip-anchor:hover::after {
        opacity: 1;
        visibility: visible;
        transform: translateX(-50%) translateY(-2px);
    }
    .ui-search-box {
        position: relative;
        width: 100%;
    }
    .ui-search-icon {
        position: absolute;
        left: 10px;
        top: 50%;
        transform: translateY(-50%);
        color: var(--ui-text-muted);
        pointer-events: none;
        display: inline-block;
    }
    .ui-search-input {
        width: 100%;
        background: #0d1424;
        border: 1px solid var(--ui-border);
        border-radius: var(--ui-radius-sm);
        padding: 8px 12px 8px 34px;
        color: var(--ui-text-primary);
        font-family: var(--ui-font);
        font-size: 0.8125rem;
        outline: none;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .ui-search-input:focus {
        border-color: var(--ui-primary-light);
        box-shadow: 0 0 0 3px rgba(25, 118, 210, 0.2);
    }
    .ui-footer {
        border-top: 1px solid var(--ui-border);
        padding-top: 20px;
        color: var(--ui-text-muted);
        font-size: 0.75rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-top: 24px;
    }
    .ui-footer a {
        color: var(--ui-primary-light);
        text-decoration: none;
    }
    .ui-footer a:hover {
        text-decoration: underline;
    }
"""


def _get_compliance_chip(tier: str) -> str:
    if "Grade A" in tier:
        return f'<span class="ui-chip ui-chip-success">{tier}</span>'
    elif "Grade B" in tier:
        return f'<span class="ui-chip ui-chip-primary">{tier}</span>'
    elif "Grade C" in tier:
        return f'<span class="ui-chip ui-chip-warning">{tier}</span>'
    else:
        return f'<span class="ui-chip ui-chip-error">{tier}</span>'


def _get_score_chip(score: float) -> str:
    if score >= 85.0:
        return f'<span class="ui-chip ui-chip-success">{score}%</span>'
    elif score >= 60.0:
        return f'<span class="ui-chip ui-chip-warning">{score}%</span>'
    else:
        return f'<span class="ui-chip ui-chip-error">{score}%</span>'


def _build_svg_chart(ranked: List[Dict[str, Any]]) -> str:
    width = 900
    bar_height = 32
    gap = 18
    top_margin = 28
    left_label_width = 220
    right_margin = 130
    chart_width = width - left_label_width - right_margin
    total_height = top_margin + len(ranked) * (bar_height + gap) + 40

    bars = []
    for i, r in enumerate(ranked):
        y = top_margin + i * (bar_height + gap)
        score_val = r.get("composite_privacy_score", 0.0)
        norm_val = max(0.0, min(100.0, score_val))
        bar_w = (norm_val / 100.0) * chart_width

        color = "#2e7d32" if norm_val >= 88 else ("#1976d2" if norm_val >= 72 else ("#ed6c02" if norm_val >= 50 else "#d32f2f"))
        det_name = r.get("detector_name", "Detector")
        res_val = r.get("adversarial_resilience", 0.0)
        exp_val = r.get("critical_exposure_index", 0.0)

        bars.append(f"""
        <g class="chart-row">
            <title>{det_name}: {score_val} CPS | {res_val}% Adversarial Resilience | {exp_val}% Exposure</title>
            <text x="{left_label_width - 14}" y="{y + 20}" fill="#f8fafc" font-size="12" font-weight="500" text-anchor="end" font-family="'Roboto', -apple-system, sans-serif">{det_name}</text>
            <rect class="bar-bg" x="{left_label_width}" y="{y}" width="{chart_width}" height="{bar_height}" rx="4" fill="#0d1424" stroke="rgba(148, 163, 184, 0.12)" stroke-width="1" />
            <rect class="bar-fill" x="{left_label_width}" y="{y}" width="{bar_w}" height="{bar_height}" rx="4" fill="{color}" />
            <text class="bar-score" x="{left_label_width + bar_w + 10}" y="{y + 21}" fill="#f8fafc" font-size="13" font-weight="700" font-family="'Roboto', -apple-system, sans-serif">{score_val}</text>
            <text class="bar-hover-detail" x="{left_label_width + bar_w + 50}" y="{y + 21}">CPS ({res_val}% res)</text>
        </g>
        """)

    bars_svg = "\n".join(bars)

    return f"""
    <svg width="100%" height="{total_height}" viewBox="0 0 {width} {total_height}" xmlns="http://www.w3.org/2000/svg">
        <line x1="{left_label_width}" y1="{top_margin - 8}" x2="{left_label_width}" y2="{total_height - 22}" stroke="rgba(148, 163, 184, 0.18)" stroke-width="1" />
        <line x1="{left_label_width + chart_width * 0.5}" y1="{top_margin - 8}" x2="{left_label_width + chart_width * 0.5}" y2="{total_height - 22}" stroke="rgba(148, 163, 184, 0.18)" stroke-dasharray="4" />
        <line x1="{left_label_width + chart_width}" y1="{top_margin - 8}" x2="{left_label_width + chart_width}" y2="{total_height - 22}" stroke="rgba(148, 163, 184, 0.18)" stroke-dasharray="4" />
        <text x="{left_label_width}" y="{total_height - 6}" fill="#64748b" font-size="10" font-family="'Roboto', sans-serif" text-anchor="middle">0</text>
        <text x="{left_label_width + chart_width * 0.5}" y="{total_height - 6}" fill="#64748b" font-size="10" font-family="'Roboto', sans-serif" text-anchor="middle">50 CPS</text>
        <text x="{left_label_width + chart_width}" y="{total_height - 6}" fill="#64748b" font-size="10" font-family="'Roboto', sans-serif" text-anchor="middle">100 CPS</text>
        {bars_svg}
    </svg>
    """


def generate_index_html(scores: List[Dict[str, Any]], specimens: List[Dict[str, Any]], output_path: str):
    ranked = sorted(scores, key=lambda s: -s.get("composite_privacy_score", 0.0))
    svg_chart = _build_svg_chart(ranked)

    table_rows = []
    for r in ranked:
        det_name = r.get("detector_name")
        cps = r.get("composite_privacy_score")
        res = r.get("adversarial_resilience")
        exp = r.get("critical_exposure_index")
        orr = r.get("over_redaction_rate")
        f1 = r.get("boundary_f1")
        lat = r.get("inference_latency_ms")
        badge = _get_compliance_chip(r.get("compliance_tier", ""))

        tooltip_text = f"CPS: {cps} | Resilience: {res}% | Exposure: {exp}%"
        table_rows.append(f"""
        <tr>
            <td style="font-weight: 600;">{det_name}</td>
            <td>
                <span class="ui-chip ui-chip-primary ui-tooltip-anchor" data-tooltip="{tooltip_text}">{cps}</span>
            </td>
            <td class="ui-val-bad">{exp}%</td>
            <td class="ui-val-warn">{orr}%</td>
            <td class="ui-val-good">{f1}%</td>
            <td class="ui-val-good">{res}%</td>
            <td style="color: var(--ui-text-secondary);">{lat} ms</td>
            <td>{badge}</td>
        </tr>
        """)
    table_rows_html = "\n".join(table_rows)

    gradient_rows = []
    for r in ranked:
        det_name = r.get("detector_name")
        tb = r.get("tier_breakdown", {})
        t1 = tb.get("1", {}).get("f1", 0.0) if "1" in tb else tb.get(1, {}).get("f1", 0.0)
        t2 = tb.get("2", {}).get("f1", 0.0) if "2" in tb else tb.get(2, {}).get("f1", 0.0)
        t3_fp = tb.get("3", {}).get("fp", 0) if "3" in tb else tb.get(3, {}).get("fp", 0)
        t4 = tb.get("4", {}).get("f1", 0.0) if "4" in tb else tb.get(4, {}).get("f1", 0.0)
        t5 = tb.get("5", {}).get("f1", 0.0) if "5" in tb else tb.get(5, {}).get("f1", 0.0)

        t3_badge = f'<span class="ui-chip ui-chip-success">0 FP</span>' if t3_fp == 0 else f'<span class="ui-chip ui-chip-error">{t3_fp} False Positives</span>'
        cps = r.get("composite_privacy_score")
        res = r.get("adversarial_resilience")
        tooltip_text = f"CPS: {cps} ({res}% res)"

        gradient_rows.append(f"""
        <tr>
            <td style="font-weight: 600;">{det_name}</td>
            <td>{_get_score_chip(t1)}</td>
            <td>{_get_score_chip(t2)}</td>
            <td>{t3_badge}</td>
            <td>{_get_score_chip(t4)}</td>
            <td>{_get_score_chip(t5)}</td>
            <td><span class="ui-chip ui-chip-primary ui-tooltip-anchor" data-tooltip="{tooltip_text}">{cps}</span></td>
        </tr>
        """)
    gradient_rows_html = "\n".join(gradient_rows)

    top = ranked[0]
    min_exp = min(r.get("critical_exposure_index", 100.0) for r in ranked)
    mean_lat = round(sum(r.get("inference_latency_ms", 0.0) for r in ranked) / len(ranked), 2)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PIID Technical Benchmark Scorecard</title>
    <style>
        {UI_COMMON_STYLES}
        .ui-kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 18px;
            margin-bottom: 24px;
        }}
        .ui-kpi-card {{
            background: var(--ui-paper);
            border: 1px solid var(--ui-border);
            border-radius: var(--ui-radius-md);
            padding: 20px 22px;
            box-shadow: var(--ui-shadow-sm);
        }}
        .ui-kpi-label {{
            color: var(--ui-text-secondary);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .ui-kpi-val {{
            color: var(--ui-text-primary);
            font-size: 1.625rem;
            font-weight: 700;
            margin: 6px 0 4px 0;
            letter-spacing: -0.02em;
        }}
        .ui-kpi-sub {{
            color: var(--ui-text-muted);
            font-size: 0.75rem;
        }}
        .ui-solutions-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 14px;
            margin-top: 14px;
        }}
        .ui-solution-card {{
            background: #0d1424;
            border: 1px solid var(--ui-border);
            border-radius: var(--ui-radius-sm);
            padding: 14px 16px;
        }}
        .ui-solution-card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 6px;
        }}
        .ui-solution-card-header a {{
            color: var(--ui-primary-light);
            font-size: 0.875rem;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
        }}
        .ui-solution-card-header a:hover {{
            text-decoration: underline;
        }}
        .ui-solution-desc {{
            color: var(--ui-text-secondary);
            font-size: 0.75rem;
            line-height: 1.45;
        }}
        .ui-solution-desc a {{
            color: var(--ui-primary-light);
            text-decoration: none;
        }}
        .ui-solution-desc a:hover {{
            text-decoration: underline;
        }}
        .chart-row {{
            cursor: pointer;
        }}
        .chart-row:hover .bar-fill {{
            filter: brightness(1.18);
        }}
        .bar-hover-detail {{
            fill: #94a3b8;
            font-size: 11px;
            font-family: var(--ui-font);
            opacity: 0;
            transition: opacity 0.2s cubic-bezier(0.4, 0, 0.2, 1), transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            transform: translateX(-4px);
            pointer-events: none;
        }}
        .chart-row:hover .bar-hover-detail {{
            opacity: 1;
            transform: translateX(0);
        }}
        .ui-inspector-banner {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            flex-wrap: wrap;
        }}
    </style>
</head>
<body>
    <div class="ui-container">
        <header class="ui-app-bar">
            <div class="ui-breadcrumbs">
                <span>Security</span>
                <svg class="ui-chevron" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
                <span>PIID Benchmark</span>
                <svg class="ui-chevron" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
                <span>Automated Telemetry</span>
            </div>
            <h1 class="ui-title">PIID Technical Benchmark Scorecard</h1>
            <p class="ui-subtitle">Empirical evaluation of PII detection models across a 5-tier difficulty gradient, risk-weighted exposure indexing, and adversarial resilience testing.</p>
        </header>

        <div class="ui-paper">
            <div class="ui-card-header">
                <h2>Benchmark Preface & Evaluated Solutions</h2>
                <span class="ui-chip ui-chip-primary">{len(specimens)} Test Specimens</span>
            </div>
            <div class="ui-card-content">
                <p style="color: var(--ui-text-secondary); font-size: 0.875rem; line-height: 1.6;">
                    This automated benchmark evaluates Personally Identifiable Information Detection (PIID) solutions across an automated test matrix stratified across 5 difficulty tiers. The evaluation measures canonical extraction, delimiter shifts, false-positive resistance against decoy identifiers, adversarial obfuscation (leetspeak, token-spaced digits), and prompt injection wrappers.
                </p>
                <div class="ui-solutions-grid">
                    <div class="ui-solution-card">
                        <div class="ui-solution-card-header">
                            <a href="https://github.com/microsoft/presidio" target="_blank" rel="noopener noreferrer">
                                <span>Microsoft Presidio</span>
                                <svg class="ui-icon-ext" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
                            </a>
                            <span class="ui-chip ui-chip-default">Open Source</span>
                        </div>
                        <p class="ui-solution-desc">Modular framework combining regex recognizers, context word boosters, and swappable NER backends.</p>
                    </div>
                    <div class="ui-solution-card">
                        <div class="ui-solution-card-header">
                            <a href="https://github.com/urchade/GLiNER" target="_blank" rel="noopener noreferrer">
                                <span>GLiNER (GLiNER-PII)</span>
                                <svg class="ui-icon-ext" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
                            </a>
                            <span class="ui-chip ui-chip-primary">Open Weight</span>
                        </div>
                        <p class="ui-solution-desc">Zero-shot bidirectional transformer model with high cross-domain and obfuscation resilience.</p>
                    </div>
                    <div class="ui-solution-card">
                        <div class="ui-solution-card-header">
                            <a href="https://github.com/protectai/llm-guard" target="_blank" rel="noopener noreferrer">
                                <span>LLM Guard</span>
                                <svg class="ui-icon-ext" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
                            </a>
                            <span class="ui-chip ui-chip-default">Open Source</span>
                        </div>
                        <p class="ui-solution-desc">Security scanner suite from Protect AI designed for AI prompt/response sanitization and injection boundaries.</p>
                    </div>
                    <div class="ui-solution-card">
                        <div class="ui-solution-card-header">
                            <a href="https://www.getlimina.ai/" target="_blank" rel="noopener noreferrer">
                                <span>Limina (formerly Private AI)</span>
                                <svg class="ui-icon-ext" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
                            </a>
                            <span class="ui-chip ui-chip-primary">Enterprise</span>
                        </div>
                        <p class="ui-solution-desc">Commercial PII/PHI de-identification engine with high-precision context filtering. Python SDK: <a href="https://github.com/privateai/pai-thin-client" target="_blank" rel="noopener noreferrer">privateai-client</a>.</p>
                    </div>
                    <div class="ui-solution-card">
                        <div class="ui-solution-card-header">
                            <span style="font-weight: 600; font-size: 0.875rem;">Regex Baseline</span>
                            <span class="ui-chip ui-chip-default">Baseline</span>
                        </div>
                        <p class="ui-solution-desc">Deterministic standard library regular expression matcher for structured tokens (SSN, email, phone, card).</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="ui-kpi-grid">
            <div class="ui-kpi-card">
                <div class="ui-kpi-label">Top Benchmark Performer</div>
                <div class="ui-kpi-val">{top.get("detector_name")}</div>
                <div class="ui-kpi-sub">Composite Score: {top.get("composite_privacy_score")} / 100 ({top.get("compliance_tier")})</div>
            </div>
            <div class="ui-kpi-card">
                <div class="ui-kpi-label">Min Critical Exposure</div>
                <div class="ui-kpi-val" style="color: var(--ui-success-light);">{min_exp}%</div>
                <div class="ui-kpi-sub">Lowest leaked payload volume under stress</div>
            </div>
            <div class="ui-kpi-card">
                <div class="ui-kpi-label">Mean Inference Latency</div>
                <div class="ui-kpi-val" style="color: var(--ui-primary-light);">{mean_lat} ms</div>
                <div class="ui-kpi-sub">Per-payload processing duration</div>
            </div>
        </div>

        <div class="ui-paper">
            <div class="ui-card-header">
                <h2>Composite Privacy Score Comparison</h2>
                <span class="ui-chip ui-chip-default">Hover bars for details</span>
            </div>
            <div class="ui-card-content">
                <div style="overflow-x: auto; text-align: center;">
                    {svg_chart}
                </div>
            </div>
        </div>

        <div class="ui-paper">
            <div class="ui-card-header">
                <h2>Difficulty Gradient Telemetry (Tier 1 to 5 Stress Curve)</h2>
            </div>
            <div class="ui-table-wrapper">
                <table class="ui-table">
                    <thead>
                        <tr>
                            <th>Detector Solution</th>
                            <th>Tier 1 (Canonical)</th>
                            <th>Tier 2 (Shifts)</th>
                            <th>Tier 3 (Decoys)</th>
                            <th>Tier 4 (Adversarial)</th>
                            <th>Tier 5 (Injections)</th>
                            <th>Overall CPS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {gradient_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ui-paper">
            <div class="ui-card-header">
                <h2>Technical Diagnostic Scoreboard</h2>
                <span class="ui-chip ui-chip-default">Hover scores for tooltip</span>
            </div>
            <div class="ui-table-wrapper">
                <table class="ui-table">
                    <thead>
                        <tr>
                            <th>Detector Solution</th>
                            <th>CPS Score</th>
                            <th>Critical Exposure</th>
                            <th>Over-Redaction</th>
                            <th>Boundary F1</th>
                            <th>Adversarial Resilience</th>
                            <th>Inference Latency</th>
                            <th>Compliance Readiness</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ui-paper">
            <div class="ui-card-content">
                <div class="ui-inspector-banner">
                    <div>
                        <h2 style="font-size: 1.125rem; font-weight: 600; color: var(--ui-text-primary);">Virtual Test Document Inspector</h2>
                        <p style="color: var(--ui-text-secondary); font-size: 0.8125rem; margin-top: 4px;">Inspect the exact test documents evaluated across all 5 tiers. Filter by tier, examine ground-truth entity spans, and review model-by-model diagnostic post-mortems.</p>
                    </div>
                    <a href="specimens.html" class="ui-btn ui-btn-primary">
                        <span>Open Document Inspector</span>
                        <svg class="ui-btn-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                            <path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/>
                        </svg>
                    </a>
                </div>
            </div>
        </div>

        <footer class="ui-footer">
            <span>Generated by <code>generate_report.py</code></span>
            <span>GitHub Pages & CI Actions Pipeline</span>
        </footer>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_specimens_html(scores: List[Dict[str, Any]], specimens: List[Dict[str, Any]], output_path: str):
    specimen_cards = []

    for sp in specimens:
        sp_id = sp.get("id", "SPEC")
        tier = sp.get("tier", 1)
        tier_label = sp.get("tier_label", f"Tier {tier}")
        raw_text = sp.get("text", "")
        gt_items = sp.get("ground_truth", [])
        tech_note = sp.get("technical_profile", "")

        highlighted_text = raw_text
        for gt in sorted(gt_items, key=lambda x: -len(x.get("value", ""))):
            val = gt.get("value", "")
            if val and val in highlighted_text:
                ent_type = gt.get("type", "PII")
                repl = f'<mark class="ui-gt-mark" title="{ent_type}">{val}<span class="ui-gt-badge">{ent_type}</span></mark>'
                highlighted_text = highlighted_text.replace(val, repl, 1)

        model_results = []
        has_failure = False
        has_decoy_fp = False

        for sc in scores:
            det_name = sc.get("detector_name")
            evals = sc.get("specimen_evaluations", [])
            det_eval = next((e for e in evals if e.get("id") == sp_id), None)
            if not det_eval:
                continue

            missed = det_eval.get("missed_entities", 0)
            fp = det_eval.get("false_positives", 0)

            if missed > 0:
                has_failure = True
                status_pill = f'<span class="ui-chip ui-chip-error">EXPOSURE ({missed} missed)</span>'
            elif fp > 0:
                has_decoy_fp = True
                status_pill = f'<span class="ui-chip ui-chip-warning">OVER-REDACTED ({fp} FP)</span>'
            else:
                status_pill = '<span class="ui-chip ui-chip-success">CLEAN PASS</span>'

            model_results.append(f"""
            <div class="ui-detector-row">
                <span style="font-weight: 600; font-size: 0.75rem; color: var(--ui-text-primary);">{det_name}</span>
                {status_pill}
            </div>
            """)

        model_rows_html = "\n".join(model_results)

        if has_failure:
            outcome_class = "outcome-exposure"
            outcome_chip = '<span class="ui-chip ui-chip-error">Has Exposure</span>'
        elif has_decoy_fp:
            outcome_class = "outcome-fp"
            outcome_chip = '<span class="ui-chip ui-chip-warning">Has False Positive</span>'
        else:
            outcome_class = "outcome-pass"
            outcome_chip = '<span class="ui-chip ui-chip-success">Clean Pass</span>'

        gt_pills = " ".join([f'<span class="ui-chip ui-chip-default">{g.get("type")}: <code style="margin-left: 4px; color: var(--ui-primary-light);">{g.get("value")}</code> (Risk: {g.get("risk_weight", 1.0)})</span>' for g in gt_items]) if gt_items else '<span style="color: var(--ui-text-muted); font-size: 0.75rem;">No PII present (decoy test specimen)</span>'

        specimen_cards.append(f"""
        <div class="ui-paper doc-card {outcome_class}" data-tier="{tier}">
            <div class="ui-card-header">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <code style="color: var(--ui-primary-light); font-size: 0.8125rem; font-weight: 700;">{sp_id}</code>
                    <span class="ui-chip ui-chip-default">{tier_label}</span>
                </div>
                {outcome_chip}
            </div>

            <div class="ui-card-content">
                <div class="ui-specimen-text">
                    {highlighted_text}
                </div>

                <div style="margin-bottom: 14px;">
                    <div style="font-size: 0.75rem; font-weight: 600; color: var(--ui-text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">Expected Entities:</div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">{gt_pills}</div>
                </div>

                <div class="ui-postmortem-box">
                    <div style="font-size: 0.75rem; font-weight: 600; color: var(--ui-text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px;">Diagnostic Profile & Root Cause:</div>
                    <p style="color: var(--ui-text-muted); font-size: 0.75rem; line-height: 1.45; margin-bottom: 10px;">{tech_note}</p>
                    <div class="ui-model-grid">
                        {model_rows_html}
                    </div>
                </div>
            </div>
        </div>
        """)

    cards_html = "\n".join(specimen_cards)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virtual Test Document Inspector</title>
    <style>
        {UI_COMMON_STYLES}
        .ui-controls-paper {{
            background: #111827;
            border: 1px solid var(--ui-border);
            border-radius: var(--ui-radius-md);
            padding: 14px 18px;
            margin-bottom: 24px;
            position: sticky;
            top: 16px;
            z-index: 100;
            box-shadow: var(--ui-shadow-md);
        }}
        .ui-controls-flex {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }}
        .ui-btn-group {{
            display: inline-flex;
            gap: 4px;
            flex-wrap: wrap;
        }}
        .ui-specimen-text {{
            background: #0d1424;
            border: 1px solid var(--ui-border);
            border-radius: var(--ui-radius-sm);
            padding: 14px 16px;
            font-size: 0.875rem;
            line-height: 1.6;
            color: var(--ui-text-primary);
            margin-bottom: 14px;
        }}
        .ui-gt-mark {{
            background: rgba(25, 118, 210, 0.16);
            color: #90caf9;
            border-bottom: 2px solid var(--ui-primary-light);
            padding: 1px 4px;
            border-radius: 3px;
            font-weight: 500;
        }}
        .ui-gt-badge {{
            font-size: 0.625rem;
            background: var(--ui-primary);
            color: #ffffff;
            font-weight: 700;
            border-radius: 3px;
            padding: 1px 4px;
            margin-left: 4px;
            vertical-align: middle;
            text-transform: uppercase;
        }}
        .ui-postmortem-box {{
            background: #0d1424;
            border: 1px solid var(--ui-border);
            border-radius: var(--ui-radius-sm);
            padding: 12px 14px;
        }}
        .ui-model-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 8px;
        }}
        .ui-detector-row {{
            background: #111827;
            border: 1px solid var(--ui-border);
            padding: 6px 10px;
            border-radius: var(--ui-radius-sm);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
    </style>
</head>
<body>
    <div class="ui-container">
        <header class="ui-app-bar">
            <div class="ui-breadcrumbs">
                <a href="./" class="ui-nav-link">
                    <svg class="ui-btn-icon" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                        <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/>
                    </svg>
                    <span>Back to Benchmark Scorecard</span>
                </a>
                <svg class="ui-chevron" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
                <span>Document Inspector</span>
            </div>
            <h1 class="ui-title">Virtual Test Document Inspector</h1>
            <p class="ui-subtitle">Interactive inspection tool for test specimens evaluated across all 5 difficulty tiers. Filter by tier, examine ground-truth entity spans, and review model-by-model diagnostic post-mortems.</p>
        </header>

        <div class="ui-controls-paper">
            <div class="ui-controls-flex">
                <div class="ui-btn-group" id="tier-filters">
                    <button class="ui-btn ui-btn-outlined active" data-filter="all">All Tiers</button>
                    <button class="ui-btn ui-btn-outlined" data-filter="1">Tier 1: Canonical</button>
                    <button class="ui-btn ui-btn-outlined" data-filter="2">Tier 2: Delimiters</button>
                    <button class="ui-btn ui-btn-outlined" data-filter="3">Tier 3: Decoys</button>
                    <button class="ui-btn ui-btn-outlined" data-filter="4">Tier 4: Adversarial</button>
                    <button class="ui-btn ui-btn-outlined" data-filter="5">Tier 5: Injections</button>
                </div>
                <div class="ui-btn-group" id="outcome-filters">
                    <button class="ui-btn ui-btn-outlined active" data-outcome="all">All Outcomes</button>
                    <button class="ui-btn ui-btn-outlined" data-outcome="outcome-exposure">Exposure Leaks</button>
                    <button class="ui-btn ui-btn-outlined" data-outcome="outcome-fp">False Positives</button>
                    <button class="ui-btn ui-btn-outlined" data-outcome="outcome-pass">Clean Passes</button>
                </div>
                <div style="flex: 1; min-width: 220px;">
                    <div class="ui-search-box">
                        <svg class="ui-search-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                            <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 14z"/>
                        </svg>
                        <input type="text" id="docSearch" class="ui-search-input" placeholder="Filter by keyword, entity, or ID..." />
                    </div>
                </div>
            </div>
        </div>

        <div id="documents-container">
            {cards_html}
        </div>

        <footer class="ui-footer">
            <span>Virtual Test Document Inspector</span>
            <a href="./" class="ui-nav-link">
                <span>Back to Benchmark Scorecard</span>
                <svg class="ui-btn-icon" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                    <path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/>
                </svg>
            </a>
        </footer>
    </div>

    <script>
        const tierButtons = document.querySelectorAll('#tier-filters .ui-btn');
        const outcomeButtons = document.querySelectorAll('#outcome-filters .ui-btn');
        const searchInput = document.getElementById('docSearch');
        const cards = document.querySelectorAll('.doc-card');

        let activeTier = 'all';
        let activeOutcome = 'all';
        let searchQuery = '';

        function applyFilters() {{
            cards.forEach(card => {{
                const cardTier = card.getAttribute('data-tier');
                const cardText = card.textContent.toLowerCase();

                const tierMatch = (activeTier === 'all' || cardTier === activeTier);
                const outcomeMatch = (activeOutcome === 'all' || card.classList.contains(activeOutcome));
                const searchMatch = (searchQuery === '' || cardText.includes(searchQuery));

                if (tierMatch && outcomeMatch && searchMatch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        tierButtons.forEach(btn => {{
            btn.addEventListener('click', () => {{
                tierButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeTier = btn.getAttribute('data-filter');
                applyFilters();
            }});
        }});

        outcomeButtons.forEach(btn => {{
            btn.addEventListener('click', () => {{
                outcomeButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeOutcome = btn.getAttribute('data-outcome');
                applyFilters();
            }});
        }});

        searchInput.addEventListener('input', (e) => {{
            searchQuery = e.target.value.toLowerCase().trim();
            applyFilters();
        }});
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="benchmark_results.json")
    parser.add_argument("--output-dir", default=".")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input JSON {args.input} not found.")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    scores = data.get("scores", [])
    specimens = data.get("specimens", [])

    index_path = os.path.join(args.output_dir, "index.html")
    specimens_path = os.path.join(args.output_dir, "specimens.html")

    generate_index_html(scores, specimens, index_path)
    generate_specimens_html(scores, specimens, specimens_path)

    print(f"Report generated: {index_path} and {specimens_path}")


if __name__ == "__main__":
    main()

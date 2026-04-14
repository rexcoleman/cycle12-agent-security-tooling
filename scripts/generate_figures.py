#!/usr/bin/env python3
"""Generate figures for Phase 3 analysis."""
import csv
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

BASE_DIR = os.path.expanduser('~/cycle12-agent-security-tooling')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs/figures')
ANALYSIS_DIR = os.path.join(BASE_DIR, 'outputs/analysis')

def load_detection_profiles():
    profiles = []
    with open(os.path.join(ANALYSIS_DIR, 'detection_profiles.csv')) as f:
        reader = csv.DictReader(f)
        for row in reader:
            for k in ['TP', 'FP', 'TN', 'FN']:
                row[k] = int(row[k])
            for k in ['TPR', 'FPR', 'Youden', 'TPR_CI_lo', 'TPR_CI_hi', 'FPR_CI_lo', 'FPR_CI_hi', 'CI_width_TPR']:
                row[k] = float(row[k])
            profiles.append(row)
    return profiles

def detection_heatmap(profiles):
    """Generate detection heatmap: scanners x categories"""
    categories = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05']
    cat_labels = ['ASI01\nGoal\nHijack', 'ASI02\nTool\nMisuse', 'ASI03\nIdentity\nPrivilege',
                  'ASI04\nSupply\nChain', 'ASI05\nCode\nExec']

    # Best OP per scanner (max Youden on ALL)
    best_ops = {}
    for p in profiles:
        if p['category'] == 'ALL':
            s = p['scanner']
            if s not in best_ops or p['Youden'] > best_ops[s][0]:
                best_ops[s] = (p['Youden'], p['operating_point'])

    scanners = sorted(best_ops.keys())
    scanner_labels = []
    for s in scanners:
        op = best_ops[s][1]
        scanner_labels.append(f"{s}\n({op})")

    # Build heatmap data
    data = np.zeros((len(scanners), len(categories)))
    for i, s in enumerate(scanners):
        op = best_ops[s][1]
        for j, cat in enumerate(categories):
            for p in profiles:
                if p['scanner'] == s and p['operating_point'] == op and p['category'] == cat:
                    data[i, j] = p['TPR']
                    break

    fig, ax = plt.subplots(figsize=(10, 5))
    im = ax.imshow(data, cmap='RdYlGn', vmin=0, vmax=1, aspect='auto')

    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels(cat_labels, fontsize=9)
    ax.set_yticks(range(len(scanners)))
    ax.set_yticklabels(scanner_labels, fontsize=9)

    # Annotate cells
    for i in range(len(scanners)):
        for j in range(len(categories)):
            val = data[i, j]
            color = 'white' if val < 0.3 or val > 0.7 else 'black'
            ax.text(j, i, f'{val:.0%}', ha='center', va='center', color=color, fontsize=11, fontweight='bold')

    plt.colorbar(im, label='True Positive Rate (TPR)')
    ax.set_title('Scanner Detection Rate by OWASP Category (Best Operating Point)', fontsize=12, fontweight='bold')
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'detection_heatmap.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Saved {path}")


def oc_curves(profiles):
    """Generate OC curves per scanner."""
    scanner_data = defaultdict(list)
    for p in profiles:
        if p['category'] == 'ALL':
            scanner_data[p['scanner']].append({
                'op': p['operating_point'],
                'TPR': p['TPR'],
                'FPR': p['FPR'],
                'Youden': p['Youden'],
                'TPR_CI_lo': p['TPR_CI_lo'],
                'TPR_CI_hi': p['TPR_CI_hi'],
            })

    colors = {'cisco': '#e74c3c', 'medusa': '#3498db', 'sigil': '#2ecc71'}

    # Combined OC curve plot
    fig, ax = plt.subplots(figsize=(10, 7))

    for scanner, points in sorted(scanner_data.items()):
        # Sort by FPR for ROC-like curve
        points_sorted = sorted(points, key=lambda x: x['FPR'])
        fprs = [p['FPR'] for p in points_sorted]
        tprs = [p['TPR'] for p in points_sorted]
        ci_lo = [p['TPR_CI_lo'] for p in points_sorted]
        ci_hi = [p['TPR_CI_hi'] for p in points_sorted]
        ops = [p['op'] for p in points_sorted]

        color = colors.get(scanner, '#666666')
        ax.plot(fprs, tprs, 'o-', color=color, linewidth=2, markersize=8, label=scanner)

        # CI bars
        for fp, tp, lo, hi, op in zip(fprs, tprs, ci_lo, ci_hi, ops):
            ax.vlines(fp, lo, hi, color=color, alpha=0.3, linewidth=2)
            # Label operating point
            ax.annotate(op.split('_')[-1], (fp, tp), textcoords="offset points",
                       xytext=(5, 5), fontsize=7, color=color)

    # Diagonal reference
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random')
    ax.set_xlabel('False Positive Rate (FPR)', fontsize=12)
    ax.set_ylabel('True Positive Rate (TPR)', fontsize=12)
    ax.set_title('Operating Characteristic Curves: All Scanners', fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'oc_curves_combined.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Saved {path}")

    # Individual scanner OC curves
    for scanner, points in sorted(scanner_data.items()):
        fig, ax = plt.subplots(figsize=(8, 6))
        points_sorted = sorted(points, key=lambda x: x['FPR'])
        fprs = [p['FPR'] for p in points_sorted]
        tprs = [p['TPR'] for p in points_sorted]
        ci_lo = [p['TPR_CI_lo'] for p in points_sorted]
        ci_hi = [p['TPR_CI_hi'] for p in points_sorted]
        ops = [p['op'] for p in points_sorted]

        color = colors.get(scanner, '#666666')
        ax.plot(fprs, tprs, 'o-', color=color, linewidth=2, markersize=10)
        for fp, tp, lo, hi, op in zip(fprs, tprs, ci_lo, ci_hi, ops):
            ax.vlines(fp, lo, hi, color=color, alpha=0.3, linewidth=3)
            ax.annotate(op, (fp, tp), textcoords="offset points",
                       xytext=(10, -10), fontsize=9, color=color)

        ax.plot([0, 1], [0, 1], 'k--', alpha=0.3)
        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title(f'Operating Characteristic Curve: {scanner}', fontsize=13, fontweight='bold')
        ax.set_xlim(-0.05, 1.05)
        ax.set_ylim(-0.05, 1.05)
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        path = os.path.join(OUTPUT_DIR, f'oc_curves_{scanner}.png')
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"Saved {path}")


def youden_comparison(profiles):
    """Bar chart comparing Youden indices"""
    scanner_ops = {}
    for p in profiles:
        if p['category'] == 'ALL':
            key = f"{p['scanner']}\n{p['operating_point']}"
            scanner_ops[key] = p['Youden']

    fig, ax = plt.subplots(figsize=(12, 5))
    keys = list(scanner_ops.keys())
    vals = list(scanner_ops.values())
    colors_list = []
    for k in keys:
        if 'cisco' in k: colors_list.append('#e74c3c')
        elif 'medusa' in k: colors_list.append('#3498db')
        elif 'sigil' in k: colors_list.append('#2ecc71')
        else: colors_list.append('#666666')

    bars = ax.bar(range(len(keys)), vals, color=colors_list, alpha=0.8)
    ax.set_xticks(range(len(keys)))
    ax.set_xticklabels(keys, fontsize=8, rotation=45, ha='right')
    ax.set_ylabel('Youden Index (TPR - FPR)', fontsize=11)
    ax.set_title('Youden Index Comparison Across All Scanner Operating Points', fontsize=12, fontweight='bold')
    ax.axhline(y=0, color='black', linestyle='-', alpha=0.3)
    ax.grid(True, alpha=0.2, axis='y')

    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{val:.2f}', ha='center', fontsize=8)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, 'youden_comparison.png')
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"Saved {path}")


if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    profiles = load_detection_profiles()
    detection_heatmap(profiles)
    oc_curves(profiles)
    youden_comparison(profiles)
    print("All figures generated.")

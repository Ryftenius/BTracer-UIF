"""Workflow categories; source references are listed in README.md."""
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
ROWS = [
    ('Log selected API calls', ['Built-in [S1]', 'Built-in [F1]', 'Client [D1]', 'Commands [X1]']),
    ('Symbolized stacks at API hits', ['Built-in [S1]', 'Script [F2]', 'Client* [D2]', 'Commands [X1, X2]']),
    ('Deny a selected NT call', ['Built-in [S1]', 'Script [F2]', 'Client [D1]', 'Commands* [X1, X3]']),
    ('Memory-region behavior summary', ['Built-in [S1]', 'Script* [F2]', 'Client* [D1, D3]', 'Commands* [X1]']),
    ('General instruction-event tracing', ['Outside scope [S2]', 'Script [F2]', 'Client [D3]', 'Built-in [X4]']),
    ('Edit executable bytes live', ['Outside scope [S2]', 'Script [F2]', 'Client [D1, D3]', 'Built-in [X3]']),
]


def main():
    fig, ax = plt.subplots(figsize=(14, 6.5), dpi=180)
    fig.patch.set_alpha(0)
    ax.patch.set_alpha(0)
    ax.set(xlim=(-3.35, 8.2), ylim=(-1.2, 6.35))
    ax.axis('off')
    ink = '#7F8B9C'
    colors = {'Built-in': '#12B8A6', 'Script': '#6B98DE', 'Client': '#AE89CC',
              'Commands': '#CB9A50', 'Outside': '#7F8B9C'}
    for c, tool in enumerate(['SKUGGA 1.0.0', 'Frida + frida-trace', 'DynamoRIO', 'x64dbg']):
        ax.text(c*2.05+0.95, 5.95, tool, ha='center', color=ink, weight='bold', fontsize=11)
    for r, (task, cells) in enumerate(ROWS):
        y = 5.1-r*0.82
        ax.text(-0.17, y, task, ha='right', va='center', fontsize=10, color=ink)
        for c, label in enumerate(cells):
            color = colors[label.split()[0].rstrip('*')]
            box = FancyBboxPatch((c*2.05, y-0.29), 1.9, .58,
                                 boxstyle='round,pad=0.02,rounding_size=0.06',
                                 facecolor='none', edgecolor=color, linewidth=1.3)
            ax.add_patch(box)
            ax.text(c*2.05+.95, y, label, ha='center', va='center', color=color, fontsize=9.5)
    ax.text(-3.2, -.3, 'Built-in = supplied flag/tool/view   •   Script = JavaScript   •   Client = native code   •   Commands = debugger automation',
            color=ink, fontsize=9)
    ax.text(-3.2, -.78, '* Custom integration/inference: Windows stack walking in DynamoRIO needs a different path; drcallstack is Linux-only.\n'
            'Alternative-tool memory-summary equivalence and debugger NT-denial were not implemented or runtime-validated.',
            color=ink, fontsize=9, linespacing=1.7)
    fig.subplots_adjust(left=.015, right=.99, top=.99, bottom=.02)
    output = ROOT/'Docs/media/tooling-comparison.png'
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, transparent=True)
    plt.close(fig)
    print(output)


if __name__ == '__main__':
    main()

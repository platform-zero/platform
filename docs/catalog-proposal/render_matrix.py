#!/usr/bin/env python3
"""Render the audited row ledger as separate per-module markdown tables."""
import re
from pathlib import Path
source = Path('MATRIX.md').read_text()
header = '| Service ID | Mode | Surface | Android/client | Proposed real route on datamancy.net | Persistent state / backup scope | Meaningful action / restore evidence |\n|---|---|---|---|---|---|---|\n'
assert source.count(header) == 1
source = source.replace(header, '')
source, count = re.subn(r'(^## [^\n]+\n)', lambda m: m.group(1) + '\n' + header, source, flags=re.M)
assert count == 46
Path('MATRIX_TABLE.md').write_text('<!-- Generated from MATRIX.md by render_matrix.py; edit the source ledger, then rerun. -->\n' + source)
print('Rendered MATRIX_TABLE.md:', count, 'tables')

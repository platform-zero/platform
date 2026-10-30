#!/usr/bin/env python3
"""Read-only inventory reconciliation; optionally render markdown sections as real tables.
Run from research/: python3 verify_matrix.py
"""
import json
import re
from pathlib import Path

source = Path('../../src/main/resources/services.json')
manifest = json.loads(source.read_text())
modules = manifest['modules']
expected = {m['id']: m['services'] for m in modules}
assert len(expected) == 46 and sum(map(len, expected.values())) == 89
ids = [s for services in expected.values() for s in services]
assert len(ids) == len(set(ids)), 'duplicate manifest ID'
text = Path('MATRIX.md').read_text()
sections = re.findall(r'^## ([\w-]+) — [^\n]*\n(.*?)(?=^## |\Z)', text, re.M | re.S)
rows = re.findall(r'^\| ([\w-]+) \| ([DJB?][^|]*) \|', text, re.M)
actual_ids = [name for name, _ in rows]
assert len(actual_ids) == len(set(actual_ids)), 'duplicate matrix ID'
assert set(actual_ids) == set(ids), f'missing={set(ids)-set(actual_ids)}, extra={set(actual_ids)-set(ids)}'
assert {name for name, _ in sections} == set(expected), f'module mismatch {{name for name, _ in sections}} ^ {set(expected)}'
for module, body in sections:
    got = re.findall(r'^\| ([\w-]+) \|', body, re.M)
    assert got == expected[module], f'{module}: expected={expected[module]} got={got}'
assert all(line.count('|') == 8 for line in text.splitlines() if re.match(r'^\| [\w-]+ \|', line)), 'expected 7 matrix fields'
print(f'PASS: {len(expected)} modules, {len(ids)} distinct IDs; same module and order as {source}')

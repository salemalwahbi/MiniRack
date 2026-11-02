#!/usr/bin/env python3
"""Merge this V1 source into an existing, known-working PlatformIO project.
Read-only by default. Does NOT copy secrets or mutate platformio.ini.
Usage: python tools/merge_into_existing_platformio.py <project_dir> [--apply]
"""
from pathlib import Path
import argparse
import datetime
import shutil
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('project', type=Path)
p.add_argument('--apply', action='store_true', help='Create backup then merge .cpp/.h sources')
a = p.parse_args()
source = Path(__file__).resolve().parents[1]
target = a.project.resolve()
if not target.is_dir() or not (target/'platformio.ini').is_file():
    p.error('Target must be an existing PlatformIO project with platformio.ini')
if target == source or source in target.parents:
    p.error('Do not merge into the package itself')
items = []
for folder in ('src', 'include'):
    if not (target/folder).is_dir(): p.error(f'Missing project {folder}/')
    for f in sorted((source/folder).glob('*')):
        if not f.is_file(): continue
        # The unified PRIVATE archive may contain original secret headers.
        # Never copy them into another project: keep the target's local keys.
        if 'secret' in f.name.lower() or f.name in ('Classifier.h',):
            continue
        items.append((f, target/folder/f.name))
print('Will merge', len(items), 'public source files into', target)
for _, dest in items:
    print(('UPDATE ' if dest.exists() else 'ADD    ') + str(dest.relative_to(target)))
if not a.apply:
    print('READ ONLY. Rerun with --apply to create a timestamped backup and merge.')
    sys.exit(0)
stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
backup = target.parent / (target.name + '-backup-before-v1-' + stamp)
if backup.exists(): p.error('Backup name collision')
# Copy full tree, including working local secrets/build settings. Never upload
# this backup, and never include it in the redistributed ZIP.
shutil.copytree(target, backup, ignore=shutil.ignore_patterns('.pio', '.git', '.venv'))
for f, dest in items:
    shutil.copy2(f, dest)
print('Merged. Private keys/config preserved. Backup:', backup)
print('NEXT: review diff, PlatformIO Build, THEN hardware Upload.')

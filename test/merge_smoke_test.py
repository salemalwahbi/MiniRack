from pathlib import Path
from tempfile import TemporaryDirectory
from subprocess import run
root=Path(__file__).resolve().parents[1]
with TemporaryDirectory() as directory:
    project=Path(directory)/'project';(project/'include').mkdir(parents=True);(project/'src').mkdir()
    (project/'platformio.ini').write_text('[env:working]\n')
    (project/'src'/'main.cpp').write_text('KEEP_ORIGINAL')
    (project/'include'/'wg_secrets.h').write_text('VERY_PRIVATE')
    script=root/'tools'/'merge_into_existing_platformio.py'
    r=run(['python3',str(script),str(project)],capture_output=True,text=True)
    assert r.returncode==0 and 'READ ONLY' in r.stdout,r.stderr
    assert (project/'src'/'main.cpp').read_text()=='KEEP_ORIGINAL'
    r=run(['python3',str(script),str(project),'--apply'],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    assert (project/'include'/'wg_secrets.h').read_text()=='VERY_PRIVATE'
    assert (project/'platformio.ini').read_text()=='[env:working]\n'
    assert (project/'src'/'main.cpp').read_text().startswith('// MINI RACK STAGE 8')
    matches=list(project.parent.glob('project-backup-before-v1-*'))
    assert len(matches)==1 and (matches[0]/'src'/'main.cpp').read_text()=='KEEP_ORIGINAL'
print('PASS: dry-run, backup, preserving secret and build settings, public file merge')

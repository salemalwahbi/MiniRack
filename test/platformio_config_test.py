import configparser
from pathlib import Path

root=Path(__file__).resolve().parents[1]
config=configparser.ConfigParser(interpolation=None)
config.read(root/'platformio.ini')
assert 'env:esp32-s3-devkitc-1' in config.sections()
assert 'workspace_dir' not in config['platformio']
flags=config['env:esp32-s3-devkitc-1'].get('build_flags','')
assert 'C:/Users/' not in flags
assert 'esp32-s3-devkitc-1' in config['env:esp32-s3-devkitc-1']['board']
print('portable public config OK')

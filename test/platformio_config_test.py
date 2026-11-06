#!/usr/bin/env python3
"""Static configuration guard: not an ESP32 compile test."""
import configparser
from pathlib import Path
p = Path(__file__).resolve().parent.parent
config = configparser.ConfigParser(interpolation=None)
config.read(p / 'platformio.ini', encoding='utf-8')
assert not config.has_option('platformio','workspace_dir')
env = 'env:esp32-s3-devkitc-1'
assert config.get(env,'board') == 'esp32-s3-devkitc-1'
assert config.get(env,'framework') == 'arduino'
assert config.get(env,'platform').endswith('55.03.35/platform-espressif32.zip')
assert config.get(env,'monitor_speed') == '115200'
flags = config.get(env,'build_flags')
assert '-DARDUINO_USB_CDC_ON_BOOT=1' in flags
assert '-Iprivate' in flags
libs = config.get(env,'lib_deps')
for expected in ('moononournation/GFX Library for Arduino@1.4.7', 'rweather/Crypto', 'rweather/CryptoLW', 'WireGuard-ESP32-Arduino.git#feature/esp-netif'):
    assert expected in libs
assert not any((p / n).exists() for n in ('wg_secrets.h', 'minirack-bridge-secrets.h', 'Classifier.h'))
assert (p / 'src/main.cpp').exists()
print('PASS: portable PlatformIO metadata; source structure present; no private header bundled')

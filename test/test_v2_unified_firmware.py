"""Source wiring checks only; hardware build / networking still require tests."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class UnifiedFirmwareContract(unittest.TestCase):
    def test_main_calls_v2_after_vpn(self):
        source=(ROOT/'src/main.cpp').read_text()
        self.assertIn('#include "minirack_v2_client.h"',source)
        self.assertIn('MiniRackV2::tick(',source)
        self.assertLess(source.index('vpnService(); // User-controlled WireGuard'),source.index('MiniRackV2::tick('))
        self.assertLess(source.index('MiniRackV2::tick('),source.index('miniNatService();'))

    def test_same_default_build_autodetects_enrollment(self):
        config=(ROOT/'platformio.ini').read_text()
        self.assertIn('default_envs = esp32-s3-devkitc-1',config)
        source=(ROOT/'src/minirack_v2_client.cpp').read_text()
        self.assertIn('__has_include("minirack_v2_private.h")',source)
        self.assertIn('#define MINIRACK_V2_CLIENT_ENABLED 1',source)
        self.assertIn('#define MINIRACK_V2_CLIENT_ENABLED 0',source)
        self.assertIn('V2 enabled without a private enrollment header',source)

    def test_core_and_relay_in_one_tree(self):
        for f in ('pi/v2_subscription_core.py', 'pi/v2_gateway_relay.py','include/minirack_v2_client.h'):
            self.assertTrue((ROOT/f).exists(),f)

if __name__ == '__main__': unittest.main()

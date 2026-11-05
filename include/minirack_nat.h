#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <stdint.h>

// ESP32 AP-to-uplink NAT; not VPN routing, device authentication or guest isolation.
namespace MiniRackNat {
class Controller {
public:
  bool active = false;
  uint32_t lastAttempt = 0;
  void stop();
  void poll(bool sharingEnabled, bool apEnabled,
            const IPAddress &apIp, uint32_t retryMs,
            bool routeHome = false);
private:
  bool overlapsApSubnet(const IPAddress &apIp) const;
  IPAddress boundIP=IPAddress(0,0,0,0);
  IPAddress boundGateway=IPAddress(0,0,0,0);
  bool boundHomeMode=false;
};
}

#include "minirack_nat.h"
#include "minirack_home_route.h"

namespace MiniRackNat {
bool Controller::overlapsApSubnet(const IPAddress &apIp) const {
  IPAddress sta=WiFi.localIP();
  IPAddress mask=WiFi.subnetMask();
  for (uint8_t i=0; i<4; ++i) {
    if ((sta[i] & mask[i]) != (apIp[i] & mask[i])) return false;
  }
  return true;
}
void Controller::stop() {
  if (active) {
    WiFi.AP.enableNAPT(false);
    active=false;
    Serial.println("MINIRACK NAT OFF");
  }
}
void Controller::poll(bool sharingEnabled, bool apEnabled,
                      const IPAddress &apIp, uint32_t retryMs, bool routeHome) {
  if (!sharingEnabled || !apEnabled || WiFi.status()!=WL_CONNECTED || !WiFi.STA.hasIP()) {
    stop();
    lastAttempt=0;
    return;
  }
  // If the experimental home route stops being the default or its WG link
  // drops, disable global AP NAPT immediately on this poll. This is a
  // software guard, not a proven packet-level kill-switch.
  if (routeHome && !MiniRackHomeRoute::linkReady()) {
    stop(); lastAttempt=0; return;
  }
  if (active) return;
  const uint32_t now=millis();
  if (lastAttempt && (uint32_t)(now-lastAttempt)<retryMs) return;
  lastAttempt=now;
  if (overlapsApSubnet(apIp)) {
    Serial.println("MINIRACK NAT BLOCKED: uplink overlaps 192.168.4.0/24");
    return;
  }
  if (routeHome) {
    if (!MiniRackHomeRoute::linkReady()) {
      Serial.println("MINIRACK HOME ROUTE NOT VERIFIED: NAT BLOCKED");
      return;
    }
    // WireGuard-ESP32 has already installed wg0 as the default netif.
    // Do NOT call STA.setDefault(), which would undo the home route.
  } else if (!WiFi.STA.setDefault()) {
    Serial.println("MINIRACK NAT FAILED: uplink default route unavailable");
    return;
  }
  active=WiFi.AP.enableNAPT(true);
  Serial.printf("MINIRACK NAT %s - uplink %s -> clients %s\n",
      active?"ON":"FAILED",
      routeHome?"WIREGUARD HOME EXPERIMENT":WiFi.localIP().toString().c_str(),
      WiFi.AP.localIP().toString().c_str());
}
} // namespace MiniRackNat

#include "minirack_nat.h"
#include "minirack_home_route.h"
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <lwip/netif.h>

namespace {
// The bundled WireGuard implementation calls lwIP netif_set_default(wg0)
// directly. ESP-IDF's default-interface bookkeeping (and STA.isDefault())
// can therefore still say STA while the actual IPv4 default route is wg0.
// Compare the real lwIP pointers, not ESP-IDF's cached default choice.
bool directStaIsLwipDefault() {
  esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  struct netif *lwipSta = sta ? static_cast<struct netif *>(
      esp_netif_get_netif_impl(sta)) : nullptr;
  return lwipSta != nullptr && netif_default == lwipSta;
}
} // namespace

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
  // A new authorization / Wi-Fi lease must not inherit the previous
  // NAPT retry interval or a stale uplink binding.
  lastAttempt=0;
  boundIP=IPAddress(0,0,0,0);
  boundGateway=IPAddress(0,0,0,0);
  boundHomeMode=false;
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
  // A DHCP lease or roaming change can occur without the AP dropping.
  // Existing NAT sessions must not silently continue on a stale uplink.
  if (active && (WiFi.localIP()!=boundIP ||
                 WiFi.gatewayIP()!=boundGateway ||
                 routeHome!=boundHomeMode)) {
    Serial.println("MINIRACK NAT: uplink/egress changed; rebinding");
    stop();
  }
  if (active) {
    // Crucial: WireGuard::begin() sets lwIP's DEFAULT route to wg0 even in
    // normal direct-WAN mode. Restoring STA keeps GUEST/OWNER ordinary NAT
    // usable while the WG 10.10.0.0/24 on-link control tunnel remains up.
    // This is NOT per-station MAIN/GUEST home routing.
    if (!routeHome && !directStaIsLwipDefault()) {
      if (!WiFi.STA.setDefault() || !directStaIsLwipDefault()) {
        Serial.println("MINIRACK NAT: STA not verified as lwIP default; stopping NAT");
        stop();
        return;
      }
      Serial.println("MINIRACK NAT: verified direct Wi-Fi WAN default");
    }
    return;
  }
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
  // Do not announce AP Internet as ready if the egress netif switched
  // during the NAPT enable call. Failure is safer than guest-to-home leakage.
  active=WiFi.AP.enableNAPT(true);
  if (active && (routeHome ? !MiniRackHomeRoute::linkReady()
                           : !directStaIsLwipDefault())) {
    Serial.println("MINIRACK NAT: route changed during NAPT start; fail closed");
    stop();
    return;
  }
  if (active) {
    boundIP=WiFi.localIP();
    boundGateway=WiFi.gatewayIP();
    boundHomeMode=routeHome;
  }
  Serial.printf("MINIRACK NAT %s - uplink %s -> clients %s\n",
      active?"ON":"FAILED",
      routeHome?"WIREGUARD HOME EXPERIMENT":WiFi.localIP().toString().c_str(),
      WiFi.AP.localIP().toString().c_str());
}
} // namespace MiniRackNat

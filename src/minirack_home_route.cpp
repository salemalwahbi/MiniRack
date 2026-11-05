#include "minirack_home_route.h"
#include <Arduino.h>
#include <esp_netif.h>
#include <lwip/netif.h>

// The WireGuard lwIP interface name is wg<number>. Its number is assigned
// dynamically by lwIP, so netif_find("wg0") is not reliable in AP+STA mode.
// Read lwIP netif_list only in the TCPIP thread; never change the route here.
namespace {
struct RouteState {
  bool found = false;
  bool up = false;
  bool isDefault = false;
  int wgNumber = -1;
};
esp_err_t inspectRoute(void *ctx) {
  auto *s = static_cast<RouteState *>(ctx);
  for (struct netif *n = netif_list; n != nullptr; n = n->next) {
    if (n->name[0] == 'w' && n->name[1] == 'g') {
      s->found = true;
      s->up = netif_is_up(n) && netif_is_link_up(n);
      s->isDefault = (netif_default == n);
      s->wgNumber = (int)n->num;
      break;
    }
  }
  return ESP_OK;
}
} // namespace

namespace MiniRackHomeRoute {
bool linkReady() {
  RouteState state;
  if (esp_netif_tcpip_exec(inspectRoute, &state) != ESP_OK)
    return false;
  const bool ready = state.found && state.up && state.isDefault;
  static uint32_t lastLog = 0;
  if (!ready && (uint32_t)(millis() - lastLog) >= 10000U) {
    lastLog = millis();
    Serial.printf("MR WG ROUTE CHECK: found=%d index=%d up=%d default=%d\n",
                  state.found, state.wgNumber, state.up, state.isDefault);
  }
  return ready;
}
} // namespace MiniRackHomeRoute
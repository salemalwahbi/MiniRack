#include "minirack_home_route.h"
#include <lwip/netif.h>
// Do not change lwIP's default route from an arbitrary application thread.
// WireGuard-ESP32 chooses the wg interface as default in begin().
// We only permit home-only AP NAPT when it is STILL the default and link-up.
namespace MiniRackHomeRoute {
bool linkReady() {
  struct netif* n = netif_find("wg0");
  return n != nullptr && netif_is_up(n) && netif_is_link_up(n) && netif_default == n;
}
}

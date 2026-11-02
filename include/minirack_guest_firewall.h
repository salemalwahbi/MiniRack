#pragma once
#include <Arduino.h>
#include <stdint.h>
#include "minirack_guest_policy.h"

// AP ingress filter. Must be installed in TCP/IP thread before approving a
// GUEST or allowing mixed-station NAT. Fails closed if no hook installed.
namespace MiniRackGuestFirewall {
constexpr uint8_t kMaxKnown=16;
struct KnownStation {
  uint8_t mac[6];
  MiniRackGuestPolicy::Role role;
  uint8_t leasedIP[4]; // ESP DHCP station mapping; zero means unassigned
};
void updateKnown(const KnownStation *known, uint8_t count);
void beginInstall();
bool ready();
void resetAfterApStop();
uint32_t dropped();
}

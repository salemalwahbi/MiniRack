#pragma once
// Conservative link-level evidence only: not a proof of Pi exit routing.
// Caller must still validate Pi forwarding, NAT, IPv4 DNS and tunnel loss.
namespace MiniRackHomeRoute {
  bool linkReady();
}

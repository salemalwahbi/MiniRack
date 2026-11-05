#pragma once
// V2: signed entitlement permits AP NAT only while authorization is fresh.
// Disabled/unprovisioned builds retain the frozen V1 NAT behavior.
namespace MiniRackV2 {
  void tick(bool wgReady);
  bool internetPermit();
}

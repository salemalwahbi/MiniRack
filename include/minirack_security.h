#pragma once

#include <stdint.h>

// Mini Rack Stage 11 security decision policy.
// Local observations only; NOT an IDS trained on network packet traces and
// NOT a replacement for authenticated client identities / guest firewall.
namespace MiniRackSecurity {

enum class Event : uint8_t {
  UnregisteredStation = 0,
  RejectedProtectedProfile = 1,
  InvalidPiBridgeAuth = 2,
  InvalidSetupPin = 3,
  BlockedRegisteredStation = 4
};

struct Snapshot {
  uint8_t score;
  bool alert;
  uint32_t observedEvents;
  Event lastEvent;
};

class Engine {
public:
  // nowMs is the monotonic Arduino millis(); sourceTag is only a local
  // non-secret hash of an AP MAC or source IP, never an authorization token.
  void observe(Event event, uint32_t sourceTag, uint32_t nowMs);
  void tick(uint32_t nowMs);
  Snapshot snapshot() const;
  bool alert() const { return alert_; }
  bool sensitiveOperationsLocked() const { return alert_; }

private:
  struct Recent { uint32_t tag = 0; uint32_t when = 0; Event event = Event::UnregisteredStation; bool valid = false; };
  Recent recent_[12] = {};
  uint8_t recentNext_ = 0;
  uint8_t risk_ = 0;
  uint32_t observed_ = 0;
  Event lastEvent_ = Event::UnregisteredStation;
  bool alert_ = false;
  uint32_t alertUntil_ = 0;
  uint32_t lastDecay_ = 0;
  bool decayStarted_ = false;
};

// Security monitoring drives temporary access restrictions and alerts.
// Adaptive cipher selection is handled independently by MiniRackAdaptive::Policy.
// This avoids the false claim that selecting Ascon during an attack is inherently safer.

} // namespace MiniRackSecurity

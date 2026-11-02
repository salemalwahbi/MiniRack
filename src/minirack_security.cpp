#include "minirack_security.h"

namespace MiniRackSecurity {
namespace {
constexpr uint8_t kThreshold = 6;
constexpr uint32_t kAlertHoldMs = 90000U;
constexpr uint32_t kDecayEveryMs = 20000U;
uint8_t severity(Event event) {
  switch (event) {
    case Event::InvalidPiBridgeAuth: return 8; // Signed channel tamper: immediate.
    case Event::RejectedProtectedProfile: return 3;
    case Event::InvalidSetupPin: return 2;
    case Event::BlockedRegisteredStation: return 1;
    case Event::UnregisteredStation: return 1;
  }
  return 1;
}
uint32_t cooldown(Event event) {
  switch (event) {
    case Event::InvalidPiBridgeAuth: return 1000U;
    case Event::RejectedProtectedProfile: return 3500U;
    case Event::InvalidSetupPin: return 3500U;
    case Event::BlockedRegisteredStation: return 60000U;
    case Event::UnregisteredStation: return 60000U;
  }
  return 8000U;
}
}

void Engine::tick(uint32_t nowMs) {
  if (!decayStarted_) {
    decayStarted_ = true;
    lastDecay_ = nowMs;
  }
  const uint32_t elapsed = nowMs - lastDecay_;
  if (elapsed >= kDecayEveryMs) {
    uint32_t steps = elapsed / kDecayEveryMs;
    risk_ = (steps >= risk_) ? 0 : static_cast<uint8_t>(risk_ - steps);
    lastDecay_ += steps * kDecayEveryMs;
  }
  // The flag recovers automatically; never permanently ban by score.
  if (alert_ && static_cast<int32_t>(nowMs - alertUntil_) >= 0) {
    alert_ = false;
  }
}

void Engine::observe(Event event, uint32_t sourceTag, uint32_t nowMs) {
  tick(nowMs);
  const uint32_t wait = cooldown(event);
  for (const Recent &entry : recent_) {
    if (entry.valid && entry.event == event && entry.tag == sourceTag &&
        (nowMs - entry.when) < wait) {
      return; // De-auth checks run 5 times/sec: don't count every iteration.
    }
  }
  Recent &slot = recent_[recentNext_];
  slot.tag = sourceTag;
  slot.when = nowMs;
  slot.event = event;
  slot.valid = true;
  recentNext_ = (recentNext_ + 1U) % 12U;
  ++observed_;
  lastEvent_ = event;
  uint16_t newRisk = static_cast<uint16_t>(risk_) + severity(event);
  risk_ = newRisk > 12 ? 12 : static_cast<uint8_t>(newRisk);
  if (risk_ >= kThreshold) {
    alert_ = true;
    alertUntil_ = nowMs + kAlertHoldMs;
  }
}

Snapshot Engine::snapshot() const {
  return {risk_, alert_, observed_, lastEvent_};
}

} // namespace MiniRackSecurity

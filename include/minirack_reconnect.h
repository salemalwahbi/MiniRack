#pragma once
#include <stdint.h>
// Deterministic, bounded reconnect schedule for an upstream Wi-Fi source.
// This controls ONLY WiFi.reconnect() timing, never the MiniRack AP state.
namespace MiniRackReconnect {
  constexpr uint8_t kMaxAttempts = 5;
  inline uint32_t delayMs(uint8_t attempts) {
    // 20s / 30s / 45s / 60s / 90s. Cap at 90 seconds.
    static const uint32_t delays[] = {20000u,30000u,45000u,60000u,90000u,90000u};
    return delays[attempts>kMaxAttempts?kMaxAttempts:attempts];
  }
  inline bool due(uint32_t now, uint32_t lastAttempt, uint8_t attempts) {
    return (uint32_t)(now-lastAttempt) >= delayMs(attempts);
  }
}

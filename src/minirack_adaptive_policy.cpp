#include "minirack_adaptive_policy.h"

namespace MiniRackAdaptive {
namespace {
constexpr uint16_t kInitialSamples = 2;
constexpr uint16_t kProbeEvery = 12;
constexpr float kHysteresis = 0.10f; // Avoid thrashing on measurement noise.
}
uint8_t Policy::bucket(size_t bytes) {
  if (bytes <= 128) return 0;
  if (bytes <= 512) return 1;
  return 2;
}
void Policy::reset() {
  for (uint8_t b=0; b<3; ++b) {
    calls_[b] = 0;
    for (uint8_t a=0; a<2; ++a) stats_[b][a] = BucketStats{};
  }
}
uint16_t Policy::samples(int algorithm, size_t bytes) const {
  return (algorithm == 0 || algorithm == 1) ? stats_[bucket(bytes)][algorithm].count : 0;
}
uint32_t Policy::predictedUs(int algorithm, size_t bytes) const {
  if (algorithm != 0 && algorithm != 1) return 0;
  const BucketStats &s = stats_[bucket(bytes)][algorithm];
  return s.count ? static_cast<uint32_t>(s.emaUs + 0.5f) : 0;
}
void Policy::record(int algorithm, size_t bytes, uint32_t elapsedUs) {
  if ((algorithm != 0 && algorithm != 1) || !elapsedUs) return;
  BucketStats &s = stats_[bucket(bytes)][algorithm];
  const float value = static_cast<float>(elapsedUs);
  s.emaUs = s.count ? (s.emaUs * 0.80f + value * 0.20f) : value;
  if (s.count < UINT16_MAX) ++s.count;
}
int Policy::select(int classifierDecision, size_t bytes) {
  if (classifierDecision != 0 && classifierDecision != 1) return -1;
  const uint8_t b = bucket(bytes);
  ++calls_[b];
  const BucketStats &c = stats_[b][0], &a = stats_[b][1];
  // Initial exploration keeps the original classifier as the default but
  // samples the alternative periodically to learn actual measured cost.
  if (c.count < kInitialSamples || a.count < kInitialSamples) {
    if ((calls_[b] % 4U) == 0U) return c.count <= a.count ? 0 : 1;
    return classifierDecision;
  }
  // Refresh alternative measurements occasionally as battery/CPU load changes.
  if ((calls_[b] % kProbeEvery) == 0U)
    return (c.count <= a.count) ? 0 : 1;

  // Require a meaningful advantage over the other option; keep the original
  // classifier choice when measured difference is small.
  if (c.emaUs < a.emaUs * (1.0f - kHysteresis)) return 0;
  if (a.emaUs < c.emaUs * (1.0f - kHysteresis)) return 1;
  return classifierDecision;
}
} // namespace MiniRackAdaptive

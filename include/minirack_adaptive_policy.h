#pragma once
#include <stdint.h>
#include <stddef.h>

// A small, bounded on-device feedback policy for authenticated telemetry only.
// Does NOT claim one authenticated cipher is universally more secure than the other.
namespace MiniRackAdaptive {

class Policy {
public:
  // The original on-device Classifier remains the cold-start decision maker.
  // Once both algorithms have enough measured samples for this payload size,
  // prefer the measured faster complete encrypt+authenticate operation.
  // Security threat policy independently locks sensitive operations; it never
  // silently changes WireGuard/IKEv2 or cryptographic security parameters.
  int select(int classifierDecision, size_t payloadBytes);
  void record(int algorithm, size_t payloadBytes, uint32_t elapsedUs);
  void reset();
  uint16_t samples(int algorithm, size_t payloadBytes) const;
  uint32_t predictedUs(int algorithm, size_t payloadBytes) const;
private:
  struct BucketStats { float emaUs = 0; uint16_t count = 0; };
  BucketStats stats_[3][2] = {};
  uint32_t calls_[3] = {};
  static uint8_t bucket(size_t payloadBytes);
};

} // namespace MiniRackAdaptive

#pragma once
#include <Arduino.h>

// One-time URL approval token for the *existing* Stage 8 QR workflow.
// HTTP profile delivery remains a development-only security limitation.
namespace MiniRackQrToken {
class Approval {
public:
  String token;
  String url;
  bool ready = false; // set true by caller only if QR encoding succeeds

  void create(bool forRelink);
  void clear();
  bool matches(const String &candidate) const;
};
} // namespace MiniRackQrToken

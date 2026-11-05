#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include "minirack_transport_policy_core.h"

// V2 exhibition transport settings (configuration only).
// There is no 4G/5G or satellite device driver in this build.
// Never report either transport as CONNECTED without real hardware/authorization.
namespace MiniRackTransport {
enum class Rat : uint8_t { Auto = 0, LTE = 1, NR5G = 2 };
struct Config {
  Policy policy{};
  Rat rat = Rat::Auto;
  String apn;                 // Empty until an authorized modem/SIM is configured.
  String operatorPlmn;        // Empty: automatic network selection; no simulated registration.
  String satProvider;         // Empty until a provider/terminal is configured.
  String satTerminalId;       // Empty: no satellite hardware.
  unsigned long failoverHoldMs = 20000;   // Future physical-link stabilisation delay.
  unsigned long failbackHoldMs = 60000;
};
inline Config &settings() { static Config data; return data; }
inline void load(Preferences &nv) {
  Config &c = settings();
  c.policy.cellularProfile = nv.getBool("tr_cell", true);
  c.policy.satelliteProfile = nv.getBool("tr_sat", true);
  c.policy.failoverRequested = nv.getBool("tr_fail", true);
  const uint8_t rat = nv.getUChar("tr_rat", 0);
  c.rat = (rat <= 2) ? static_cast<Rat>(rat) : Rat::Auto;
  c.apn = nv.getString("tr_apn", "");
  c.operatorPlmn = nv.getString("tr_plmn", "");
  c.satProvider = nv.getString("tr_satp", "");
  c.satTerminalId = nv.getString("tr_satid", "");
  // No modem driver -> no hardware readiness signal is generated.
}
inline void toggleCellular(Preferences &nv) {
  auto &c = settings();
  const bool v = !c.policy.cellularProfile;
  if (nv.putBool("tr_cell", v)) c.policy.cellularProfile = v;
}
inline void nextRat(Preferences &nv) {
  auto &c = settings();
  const uint8_t v = (static_cast<uint8_t>(c.rat) + 1) % 3;
  if (nv.putUChar("tr_rat", v)) c.rat = static_cast<Rat>(v);
}
inline void toggleSatellite(Preferences &nv) {
  auto &c = settings();
  const bool v = !c.policy.satelliteProfile;
  if (nv.putBool("tr_sat", v)) c.policy.satelliteProfile = v;
}
inline void toggleFailover(Preferences &nv) {
  auto &c = settings();
  const bool v = !c.policy.failoverRequested;
  if (nv.putBool("tr_fail", v)) c.policy.failoverRequested = v;
}
inline const char *ratName(Rat r) {
  switch (r) {
    case Rat::LTE: return "LTE";
    case Rat::NR5G: return "NR 5G";
    default: return "AUTO";
  }
}
}

#pragma once
// MiniRack V2: priority policy for the exhibition prototype.
// This is a *recommendation*, never a route change or a fabricated data link.
// A transport is eligible only after the relevant hardware has a real data link.
namespace MiniRackTransport {

enum class Candidate : unsigned char { None, LabWifi, Cellular, Satellite };

struct Policy {
  bool cellularProfile = true;
  bool satelliteProfile = true;
  bool failoverRequested = true;
};

struct LinkSignals {
  // True only if the Raspberry Pi home path is confirmed ready, not merely a Wi-Fi RSSI.
  bool labWifiAvailable = false;
  // These MUST stay false unless real transport drivers report an established IP link.
  bool cellularDataEstablished = false;
  bool satelliteDataEstablished = false;
  // Must come from the authenticated HOME-001 entitlement logic.
  bool home001Allowed = false;
};

// Priority: near home (Pi Wi-Fi) > 4G/5G > satellite.
// On lost home service, a fallback can be recommended only when enabled and ONLINE.
// The real failover implementation must additionally validate stable link/route,
// rebuild WireGuard over the new transport, and keep NAT blocked until verified.
inline Candidate recommend(const Policy &p, const LinkSignals &s) {
  if (!s.home001Allowed) return Candidate::None;
  if (s.labWifiAvailable) return Candidate::LabWifi;
  if (!p.failoverRequested) return Candidate::None;
  if (p.cellularProfile && s.cellularDataEstablished) return Candidate::Cellular;
  if (p.satelliteProfile && s.satelliteDataEstablished) return Candidate::Satellite;
  return Candidate::None;
}

inline const char *candidateName(Candidate c) {
  switch (c) {
    case Candidate::LabWifi: return "HOME PI WIFI";
    case Candidate::Cellular: return "4G/5G";
    case Candidate::Satellite: return "SATELLITE";
    default: return "NONE";
  }
}
} // namespace MiniRackTransport

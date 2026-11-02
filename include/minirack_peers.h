#pragma once

#include <Arduino.h>
#include <Preferences.h>
#include <stdint.h>

// Stage 9.02: MAC-based Wi-Fi association registry, NOT a cryptographic identity.
// A stable authenticated OWNER identity and per-client firewall are separate work.
namespace MiniRackPeers {
constexpr uint8_t kMaxPeers = 16;

String formatMac(const uint8_t *mac);
bool parseMac(const String &text, uint8_t *mac);
String peerKey(uint8_t slot);
String accessKey(uint8_t slot);
String nameKey(uint8_t slot);
String ownerDeviceKey(uint8_t slot);
String defaultName(uint8_t slot);

class Registry {
public:
  String macs[kMaxPeers];
  String labels[kMaxPeers];
  bool allowed[kMaxPeers] = {};
  bool ownerDevices[kMaxPeers] = {};
  bool transient[kMaxPeers] = {}; // PENDING/GUEST sessions only in RAM, no NVS writes // extra MY DEVICES, manually approved; MAC-bound preview
  String primary;                 // current Wi-Fi station MAC (mutable)
  String ownerBridgeId;           // persistent Pi account binding (legacy MAC string)

  void load(Preferences &prefs);
  String name(uint8_t slot) const;
  bool setReportedHostname(uint8_t slot, const char* hostname); // optional client DHCP name
  int find(const uint8_t *mac) const;
  uint8_t count() const;
  bool isPrimary(uint8_t slot) const;
  bool isOwnerDevice(uint8_t slot) const;
  bool isOwnerAuthorized(uint8_t slot) const;
  bool setOwnerDevice(uint8_t slot, bool owned);
  bool setAllowed(uint8_t slot, bool permit);
  bool setGuestSession(uint8_t slot, bool permit); // ephemeral Wi-Fi admission
  bool isTransient(uint8_t slot) const;
  bool setPrimary(uint8_t slot);
  bool transferPrimary(uint8_t slot); // physical-screen approval only; Pi credentials unchanged
  bool relinkPrimary(uint8_t slot); // legacy physical one-time QR approval; preserves Pi ID
  // Physically authorized QR rebind for MAIN or an extra owned device.
  // Preserves the same saved slot/name/role and the Pi account identity.
  // Does NOT recognize MAC rotation automatically on Wi-Fi association.
  bool rebindAuthorizedDevice(uint8_t slot, const uint8_t* newMac);
  bool clearPrimary();
  int addPending(const uint8_t *mac);
  bool remove(uint8_t slot);
  // Called when a Wi-Fi station disconnects; never erases persistent owner entries.
  bool expireDisconnected(uint8_t slot);

private:
  Preferences *db_ = nullptr; // owned and opened by the application's setup()
  bool persistCandidate(uint8_t slot); // called ONLY when owner taps MY DEVICE or MAIN
};
} // namespace MiniRackPeers

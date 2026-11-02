#include "minirack_peers.h"
#include <stdio.h>
#include <ctype.h>

namespace MiniRackPeers {
String formatMac(const uint8_t *mac) {
  if (!mac) return String("");
  char out[18];
  snprintf(out, sizeof(out), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(out);
}

// Reject truncated, overly long, or malformed addresses (sscanf alone accepts
// trailing garbage). This function identifies a station; it proves no ownership.
bool parseMac(const String &text, uint8_t *mac) {
  if (!mac || text.length() != 17) return false;
  for (uint8_t i = 0; i < 17; ++i) {
    char c = text[i];
    if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
      if (c != ':') return false;
    } else if (!isxdigit((unsigned char)c)) return false;
  }
  unsigned int b[6] = {};
  if (sscanf(text.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
  for (uint8_t i=0; i<6; ++i) mac[i] = (uint8_t)b[i];
  return true;
}
String peerKey(uint8_t i) { return String("p") + String(i); }
String accessKey(uint8_t i) { return String("allow") + String(i); }
String nameKey(uint8_t i) { return String("name") + String(i); }
String ownerDeviceKey(uint8_t i) { return String("mine") + String(i); }
String defaultName(uint8_t i) {
  char buf[17];
  snprintf(buf, sizeof(buf), "DEVICE %02u", (unsigned)(i+1));
  return String(buf);
}
void Registry::load(Preferences &prefs) {
  db_ = &prefs;
  for (uint8_t i=0; i<kMaxPeers; ++i) {
    macs[i] = prefs.getString(peerKey(i).c_str(), "");
    labels[i] = prefs.getString(nameKey(i).c_str(), "");
    // Preserve Stage8 NVS behavior for already registered devices.
    allowed[i] = !macs[i].isEmpty() && prefs.getBool(accessKey(i).c_str(), true);
    ownerDevices[i] = !macs[i].isEmpty() && prefs.getBool(ownerDeviceKey(i).c_str(), false);
  }
  primary = prefs.getString("primary", "");
  // Keep the existing Raspberry Pi account identifier across private-MAC
  // rotation. Old installations used the original MAIN MAC as that ID.
  ownerBridgeId = prefs.getString("ownerid", "");
  if (ownerBridgeId.isEmpty() && !primary.isEmpty()) {
    ownerBridgeId = primary;
    prefs.putString("ownerid", ownerBridgeId); // compatibility migration
  }
  // Old firmware saved GUEST/PENDING devices permanently. Remove them NOW:
  // only MAIN and explicitly owned devices belong in NVS. Retain the prior
  // MAIN slot. The Pi account ID is stored separately; it must NOT keep a
  // stale offline GUEST visible as WAITING just because MAC == ownerBridgeId.
  for(uint8_t i=0;i<kMaxPeers;i++) {
    if(macs[i].isEmpty() || isPrimary(i) || ownerDevices[i])continue;
    prefs.remove(peerKey(i).c_str());prefs.remove(accessKey(i).c_str());
    prefs.remove(nameKey(i).c_str());prefs.remove(ownerDeviceKey(i).c_str());
    macs[i]="";labels[i]="";allowed[i]=false;ownerDevices[i]=false;
  }
}
String Registry::name(uint8_t i) const {
  if (i>=kMaxPeers) return String("");
  return labels[i].isEmpty() ? defaultName(i) : labels[i];
}
// A network hostname is optional and UNTRUSTED. Use only as a display label,
// never as an ownership proof. Keep a deterministic name if the client sends none.
bool Registry::setReportedHostname(uint8_t i, const char* hostname) {
  if(!db_ || i>=kMaxPeers || macs[i].isEmpty() || !hostname)return false;
  char cleaned[24]={};
  size_t j=0;
  for(size_t k=0;hostname[k] && k<64 && j<20;k++){
    unsigned char c=(unsigned char)hostname[k];
    if((c>='a'&&c<='z') || (c>='A'&&c<='Z') ||
       (c>='0'&&c<='9') || c=='-' || c=='_') cleaned[j++]=(char)c;
    else if(c=='.' || c==' ')cleaned[j++]='-';
  }
  if(j<2)return false;
  const String next(cleaned);
  if(labels[i]==next)return false;
  if(!transient[i] && !db_->putString(nameKey(i).c_str(),next))return false;
  labels[i]=next;
  return true;
}
int Registry::find(const uint8_t *mac) const {
  const String id=formatMac(mac);
  for (uint8_t i=0; i<kMaxPeers; ++i)
    if (!macs[i].isEmpty() && macs[i].equalsIgnoreCase(id)) return i;
  return -1;
}
uint8_t Registry::count() const {
  uint8_t n=0;
  for (uint8_t i=0; i<kMaxPeers; ++i) if (!macs[i].isEmpty()) ++n;
  return n;
}
bool Registry::isPrimary(uint8_t i) const {
  return i<kMaxPeers && !macs[i].isEmpty() && !primary.isEmpty()
      && primary.equalsIgnoreCase(macs[i]);
}
// Extra personally-owned devices are approved by the owner on the physical
// touchscreen during a short pairing window. This is still a MAC-based AP
// allow-list, NOT cryptographic authentication or resilient MAC rotation.
bool Registry::isOwnerDevice(uint8_t i) const {
  return i<kMaxPeers && !macs[i].isEmpty() && ownerDevices[i];
}
bool Registry::isTransient(uint8_t i) const {return i<kMaxPeers && transient[i];}
bool Registry::isOwnerAuthorized(uint8_t i) const {
  return isPrimary(i) || (isOwnerDevice(i) && allowed[i]);
}
bool Registry::setOwnerDevice(uint8_t i, bool owned) {
  if (!db_ || i>=kMaxPeers || macs[i].isEmpty() || isPrimary(i)) return false;
  if(owned && !persistCandidate(i))return false;
  const bool previousAllowed=allowed[i];
  if (owned && !setAllowed(i,true)) return false;
  if (!db_->putBool(ownerDeviceKey(i).c_str(),owned)) {
    if (owned && !previousAllowed) setAllowed(i,false);
    return false;
  }
  ownerDevices[i]=owned;
  if (!owned) {
    allowed[i]=false;
    transient[i]=true;
    // Demotion is now temporary: remove persistent association at once.
    db_->remove(peerKey(i).c_str());db_->remove(accessKey(i).c_str());
    db_->remove(nameKey(i).c_str());db_->remove(ownerDeviceKey(i).c_str());
  }
  return true;
}
bool Registry::persistCandidate(uint8_t i) {
  if(!db_ || i>=kMaxPeers || macs[i].isEmpty())return false;
  if(!transient[i])return true;
  if(!db_->putString(peerKey(i).c_str(),macs[i]))return false;
  if(!db_->putString(nameKey(i).c_str(),labels[i])) {
    db_->remove(peerKey(i).c_str());return false;
  }
  transient[i]=false;
  return true;
}
bool Registry::setGuestSession(uint8_t i,bool permit) {
  if(!db_ || i>=kMaxPeers || macs[i].isEmpty() || isOwnerAuthorized(i) ||
     !transient[i])return false;
  allowed[i]=permit;
  return true; // intentionally NO Preferences write
}
bool Registry::setAllowed(uint8_t i, bool permit) {
  if (!db_ || i>=kMaxPeers || macs[i].isEmpty()) return false;
  if (!permit && (isPrimary(i) || isOwnerDevice(i))) return false;
  if (!db_->putBool(accessKey(i).c_str(), permit)) return false;
  allowed[i] = permit;
  return true;
}
bool Registry::setPrimary(uint8_t i) {
  if (!db_ || i>=kMaxPeers || macs[i].isEmpty()) return false;
  if (!persistCandidate(i) || !setAllowed(i,true)) return false;
  // When MAIN was only unassigned (not explicitly transferred), restore its
  // stable Pi account ID, even if iOS gave this phone a different MAC.
  // Do NOT silently reprovision/revoke the working iPhone IKEv2 account.
  // A deliberate change from one active MAIN to another still creates a
  // distinct bridge ID; that transition requires Pi-side reconciliation.
  const bool restorePreviousAccount=primary.isEmpty() && !ownerBridgeId.isEmpty();
  const String nextId=restorePreviousAccount ? ownerBridgeId : macs[i];
  const String previousId=ownerBridgeId;
  if (!db_->putString("ownerid",nextId)) return false;
  if (!db_->putString("primary",macs[i])) {
    if (!previousId.isEmpty())db_->putString("ownerid",previousId);
    else db_->remove("ownerid");
    return false;
  }
  primary=macs[i];
  ownerBridgeId=nextId;
  return true;
}
// A physical, two-tap confirmation on the Mini Rack screen is the
// only entry path for changing MAIN. It is deliberately NOT called on connect.
// The Pi account ID is retained to avoid unexpectedly breaking the existing
// VPN installation. This is NOT Pi IKEv2 credential revocation.
bool Registry::transferPrimary(uint8_t i) {
  if(!db_ || i>=kMaxPeers || macs[i].isEmpty())return false;
  if(isPrimary(i))return true;
  if(!persistCandidate(i))return false;
  if(primary.isEmpty())return setPrimary(i);
  int oldSlot=-1;
  for(uint8_t k=0;k<kMaxPeers;k++)if(isPrimary(k)){oldSlot=k;break;}
  const String oldMain=primary;
  const bool newAllowed=allowed[i];
  const bool newMine=ownerDevices[i];
  const bool oldAllowed=(oldSlot>=0)?allowed[oldSlot]:false;
  // Update persistent role flags first, retaining the active old MAIN until
  // the final 'primary' write commits. Unchanged old MAIN remains owner if a
  // later write fails; the new station's allowance is rolled back where possible.
  if(oldSlot>=0 && !db_->putBool(accessKey((uint8_t)oldSlot).c_str(),false))return false;
  if(!db_->putBool(accessKey(i).c_str(),true)){
    if(oldSlot>=0)db_->putBool(accessKey((uint8_t)oldSlot).c_str(),oldAllowed);
    return false;
  }
  if(!db_->putBool(ownerDeviceKey(i).c_str(),false)){
    db_->putBool(accessKey(i).c_str(),newAllowed);
    if(oldSlot>=0)db_->putBool(accessKey((uint8_t)oldSlot).c_str(),oldAllowed);
    return false;
  }
  if(!db_->putString("primary",macs[i])){
    db_->putBool(ownerDeviceKey(i).c_str(),newMine);
    db_->putBool(accessKey(i).c_str(),newAllowed);
    if(oldSlot>=0)db_->putBool(accessKey((uint8_t)oldSlot).c_str(),oldAllowed);
    return false;
  }
  primary=macs[i];
  allowed[i]=true;
  ownerDevices[i]=false;
  if(oldSlot>=0)allowed[oldSlot]=false;
  (void)oldMain;
  return true;
}
bool Registry::relinkPrimary(uint8_t i) {
  if (!db_ || i>=kMaxPeers || macs[i].isEmpty() ||
      primary.isEmpty() || ownerBridgeId.isEmpty()) return false;
  if(!persistCandidate(i)) return false;
  // This function is ONLY called after explicit physical, one-use QR approval.
  // It is not authentication by MAC and must not run on Wi-Fi association.
  if (!setAllowed(i,true)) return false;
  if (!db_->putString("primary",macs[i])) return false;
  primary=macs[i];
  // ownerBridgeId stays unchanged: preserve the existing IKEv2 credentials.
  return true;
}
// The firmware calls this ONLY after an owner physically opens a one-time
// QR link on the touchscreen and the HTTP client is mapped to its AP station.
// Wi-Fi MAC is a locator, not an authentication secret. The trusted identity
// stays in the same local slot; the authorized new address is recorded only
// after the physical authorization succeeds.
bool Registry::rebindAuthorizedDevice(uint8_t slot, const uint8_t* newMac) {
  if (!db_ || !newMac || slot >= kMaxPeers || macs[slot].isEmpty() ||
      !isOwnerAuthorized(slot)) return false;
  const String candidate=formatMac(newMac);
  // A current AP station must have a unicast, nonzero 802.11 address.
  bool allZero=true;
  for (uint8_t i=0;i<6;i++) if (newMac[i]!=0) allZero=false;
  if ((newMac[0]&1u) || allZero) return false;
  if (macs[slot].equalsIgnoreCase(candidate)) return true;
  const int other=find(newMac);
  if (other>=0 && other!=slot) {
    // Never steal an already approved second owner device or MAIN. A pending
    // or revoked GUEST address can be re-used after its stale record is erased.
    if (isOwnerAuthorized((uint8_t)other) || !remove((uint8_t)other)) return false;
  }
  const String previous=macs[slot];
  const bool primaryRole=isPrimary(slot);
  if (db_->putString(peerKey(slot).c_str(),candidate)==0) return false;
  // Fail closed across power loss: if only the MAC was saved before power
  // failure, the previous primary does not match any registered new device.
  if (primaryRole && db_->putString("primary",candidate)==0) {
    db_->putString(peerKey(slot).c_str(),previous);
    return false;
  }
  macs[slot]=candidate;
  if (primaryRole) primary=candidate;
  // ownerBridgeId NEVER changes: keep working Pi IKEv2 credential linkage.
  return true;
}

bool Registry::clearPrimary() {
  if (!db_ || !db_->remove("primary")) return false;
  primary="";
  // Stage13: UNASSIGN is NOT a remote credential revocation. Preserve the Pi
  // account identity in NVS until a deliberately distinct transfer. This also
  // enables re-binding the same account after an iOS private-MAC change.
  // Removing a local MAC does not guarantee revocation on the Raspberry Pi.
  return true;
}
int Registry::addPending(const uint8_t *mac) {
  if (!db_ || !mac) return -1;
  const int known=find(mac);
  if (known>=0) return known;
  const String id=formatMac(mac);
  for (uint8_t i=0; i<kMaxPeers; ++i) {
    if (!macs[i].isEmpty()) continue;
    // Do not store unapproved stations or guests in Preferences (NVS).
    macs[i]=id;
    labels[i]=defaultName(i);
    allowed[i]=false;
    ownerDevices[i]=false;
    transient[i]=true;
    return (int)i;
  }
  return -1;
}
bool Registry::remove(uint8_t i) {
  if (!db_ || i>=kMaxPeers || macs[i].isEmpty()) return false;
  // Explicit removal is a touchscreen-confirmed action. Disallow removing the
  // primary silently: main.cpp clears PRIMARY with the same confirmation first.
  if (isPrimary(i)) return false;
  if(!transient[i]) {
    if(!db_->remove(peerKey(i).c_str()))return false;
    db_->remove(accessKey(i).c_str());
    db_->remove(nameKey(i).c_str());
    db_->remove(ownerDeviceKey(i).c_str());
  }
  macs[i]="";labels[i]="";allowed[i]=false;ownerDevices[i]=false;transient[i]=false;
  return true;
}
bool Registry::expireDisconnected(uint8_t i) {
  if(i>=kMaxPeers || !transient[i] || macs[i].isEmpty())return false;
  return remove(i);
}
} // namespace MiniRackPeers


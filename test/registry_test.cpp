#include "minirack_peers.h"
#include <cassert>
#include <iostream>
using namespace MiniRackPeers;
static const uint8_t oldmac[]={0x02,0x11,0x22,0x33,0x44,0x55};
static const uint8_t newmac[]={0x06,0x91,0x82,0x73,0x64,0x55};
static const uint8_t another[]={0x02,0x41,0x42,0x43,0x44,0x45};
int main(){
  Preferences nvs;
  nvs.putString("primary",String("02:11:22:33:44:55"));
  nvs.putString("p0",String("02:11:22:33:44:55"));
  Registry r;r.load(nvs);
  assert(r.ownerBridgeId==String("02:11:22:33:44:55"));
  assert(r.find(oldmac)==0);
  assert(r.isPrimary(0));
  // Unassign is not revocation: keep Pi identifier, including after reload.
  assert(r.clearPrimary());
  assert(r.primary.isEmpty());
  assert(r.ownerBridgeId==String("02:11:22:33:44:55"));
  Registry afterReload;afterReload.load(nvs);
  assert(afterReload.primary.isEmpty());
  assert(afterReload.ownerBridgeId==String("02:11:22:33:44:55"));
  // New randomized MAC can be physically assigned without changing Pi ID.
  int slot=afterReload.addPending(newmac);assert(slot>=0);
  assert(afterReload.setPrimary(slot));
  assert(afterReload.isPrimary(slot));
  assert(afterReload.ownerBridgeId==String("02:11:22:33:44:55"));
  Registry afterReboot;afterReboot.load(nvs);
  assert(afterReboot.ownerBridgeId==String("02:11:22:33:44:55"));
  assert(afterReboot.find(newmac)==slot);
  // Re-link QR preserves Pi identity, even when the new station has a new MAC.
  const int other=afterReboot.addPending(another);
  assert(other>=0 && afterReboot.relinkPrimary(other));
  assert(afterReboot.ownerBridgeId==String("02:11:22:33:44:55"));
  assert(afterReboot.isPrimary(other));
  // Direct transfer to distinct actively assigned owner rotates account ID.
  assert(afterReboot.setPrimary(slot));
  assert(afterReboot.ownerBridgeId==String("06:91:82:73:64:55"));
  // Explicit remove does not delete the identity of currently bound owner.
  assert(afterReboot.clearPrimary());
  assert(afterReboot.remove(other));
  assert(afterReboot.ownerBridgeId==String("06:91:82:73:64:55"));
  std::cout << "PASS: NVS migration, unassign, reassign, relink, active transfer, remove\n";
}

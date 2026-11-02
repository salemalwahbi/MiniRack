#include "minirack_peers.h"
#include <cassert>
#include <iostream>
using namespace MiniRackPeers;
static const uint8_t mainMac[]={0x02,0x11,0x22,0x33,0x44,0x55};
static const uint8_t laptopMac[]={0x06,0x10,0x20,0x30,0x40,0x50};
static const uint8_t guestMac[]={0x08,0x10,0x20,0x30,0x40,0x60};
static const uint8_t laptopRotated[]={0x0A,0x10,0x20,0x30,0x40,0x50};
static const uint8_t mainRotated[]={0x0C,0x11,0x22,0x33,0x44,0x55};
int main(){
  Preferences db;
  Registry r;r.load(db);
  const int mainSlot=r.addPending(mainMac);
  assert(mainSlot>=0 && r.setPrimary(mainSlot));
  const String originalBridge=r.ownerBridgeId;
  const int laptop=r.addPending(laptopMac);
  assert(laptop>=0 && !r.isOwnerAuthorized(laptop));
  assert(r.setOwnerDevice(laptop,true));
  assert(r.isOwnerAuthorized(laptop) && r.isOwnerDevice(laptop));
  assert(r.ownerBridgeId==originalBridge && r.isPrimary(mainSlot));
  const int guest=r.addPending(guestMac);
  assert(guest>=0 && !r.isOwnerAuthorized(guest));
  Registry rebooted;rebooted.load(db);
  assert(rebooted.isPrimary(mainSlot));
  assert(rebooted.isOwnerDevice(laptop));
  assert(rebooted.isOwnerAuthorized(laptop));
  assert(!rebooted.isOwnerAuthorized(guest));
  assert(rebooted.ownerBridgeId==originalBridge);
  // A physical QR approval lets the same saved device slot adopt a new MAC.
  assert(rebooted.rebindAuthorizedDevice(laptop,laptopRotated));
  assert(rebooted.isOwnerDevice(laptop));
  assert(rebooted.find(laptopRotated)==laptop);
  assert(rebooted.find(laptopMac)==-1);
  assert(rebooted.ownerBridgeId==originalBridge);
  // A second owned device cannot be silently taken over by the first.
  assert(!rebooted.rebindAuthorizedDevice(mainSlot,laptopRotated));
  // MAIN rebind preserves the original Raspberry Pi account identity.
  // A stale unapproved station entry with the new randomized MAC is removed.
  const int pendingNewMain=rebooted.addPending(mainRotated);
  assert(pendingNewMain>=0 && pendingNewMain!=mainSlot);
  assert(!rebooted.isOwnerAuthorized(pendingNewMain));
  const auto countBefore=rebooted.count();
  assert(rebooted.rebindAuthorizedDevice(mainSlot,mainRotated));
  assert(rebooted.count()==countBefore-1);
  assert(rebooted.isPrimary(mainSlot));
  assert(rebooted.find(mainMac)==-1);
  assert(rebooted.ownerBridgeId==originalBridge);
  assert(!rebooted.rebindAuthorizedDevice((uint8_t)pendingNewMain,mainMac));
  Registry reloaded;reloaded.load(db);
  assert(reloaded.isPrimary(mainSlot));
  assert(reloaded.isOwnerAuthorized(laptop));
  assert(reloaded.ownerBridgeId==originalBridge);
  assert(rebooted.setOwnerDevice(laptop,false));
  assert(!rebooted.isOwnerDevice(laptop));
  assert(!rebooted.isOwnerAuthorized(laptop));
  Registry twice;twice.load(db);
  assert(!twice.isOwnerDevice(laptop));
  assert(!twice.isOwnerAuthorized(laptop));
  // The V1-final rule intentionally removes demoted devices from NVS.
  // An offline/reloaded guest cannot silently regain OWNER rights:
  // it must reconnect and be physically promoted again.
  assert(!twice.setOwnerDevice(laptop,true));
  const int rejoined=twice.addPending(laptopRotated);
  assert(rejoined>=0);
  assert(twice.setOwnerDevice(rejoined,true));
  assert(twice.ownerBridgeId==originalBridge);
  assert(twice.remove(rejoined));
  Registry afterDelete;afterDelete.load(db);
  assert(!afterDelete.isOwnerDevice(laptop));
  assert(!afterDelete.isOwnerAuthorized(laptop));
  assert(afterDelete.ownerBridgeId==originalBridge);
  std::cout<<"PASS: multiple owner AP devices, NVS persistence, demotion, removal, Pi ID stable\n";
}

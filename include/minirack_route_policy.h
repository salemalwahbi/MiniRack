#pragma once
#include <stddef.h>
#include <stdint.h>
// Shared ESP AP NAPT may be enabled with GUEST stations ONLY if a working
// AP-ingress packet filter exists. Unknown/revoked stations never get NAPT.
// This is L3 filtering, not confirmed Wi-Fi intra-BSS L2 isolation.
namespace MiniRackRoutePolicy {
enum class Role : uint8_t { OWNER=1, GUEST=2, UNAPPROVED=3 };
inline bool allowNat(const Role *roles, size_t stations, bool enumerationOk,
                     bool packetFilterReady=false) {
  if(!enumerationOk || stations==0 || stations>8 || !roles) return false;
  bool approved=false;
  for(size_t i=0;i<stations;++i) {
    if(roles[i]==Role::OWNER){approved=true;continue;}
    if(roles[i]==Role::GUEST && packetFilterReady){approved=true;continue;}
    // An unapproved station is isolated by the packet hook (DHCP and
    // local provisioning only), so it must not interrupt MAIN's internet.
    if(roles[i]==Role::UNAPPROVED && packetFilterReady)continue;
    return false;
  }
  return approved;
}
}

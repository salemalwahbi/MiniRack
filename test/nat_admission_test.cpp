#include <cassert>
#include "minirack_route_policy.h"
using MiniRackRoutePolicy::Role;
using MiniRackRoutePolicy::allowNat;
int main() {
 Role owner[]={Role::OWNER};
 Role guest[]={Role::GUEST};
 Role mixed[]={Role::OWNER,Role::GUEST};
 Role rogue[]={Role::OWNER,Role::UNAPPROVED};
 assert(allowNat(owner,1,true));
 assert(!allowNat(guest,1,true));
 assert(allowNat(guest,1,true,true));
 assert(!allowNat(mixed,2,true));
 assert(allowNat(mixed,2,true,true));
 // Unknown station is blocked by packet ingress filter, so OWNER NAT stays up.
 assert(allowNat(rogue,2,true,true));
 assert(!allowNat(rogue,2,true,false));
 assert(!allowNat(nullptr,0,true,true));
 assert(!allowNat(owner,1,false,true));
 assert(!allowNat(owner,9,true,true));
 return 0;
}

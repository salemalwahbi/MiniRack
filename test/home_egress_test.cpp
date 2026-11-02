#include "minirack_egress_policy.h"
#include <cassert>
#include <iostream>
int main(){
  using namespace MiniRackEgressPolicy;
  assert(!allowHomeNat(false,true,true,true,true,true));
  assert(!allowHomeNat(true,false,true,true,true,true));
  assert(!allowHomeNat(true,true,false,true,true,true));
  assert(!allowHomeNat(true,true,true,false,true,true));
  assert(!allowHomeNat(true,true,true,true,false,true));
  assert(!allowHomeNat(true,true,true,true,true,false));
#if MINIRACK_HOME_EGRESS_REQUIRED == 1 && MINIRACK_HOME_TUNNEL_EXPERIMENT == 1
  assert(allowHomeNat(true,true,true,true,true,true));
  assert(!allowDirectNat(true,true,true,true));
#elif MINIRACK_HOME_EGRESS_REQUIRED == 1
  assert(!allowHomeNat(true,true,true,true,true,true));
  assert(!allowDirectNat(true,true,true,true));
#else
  assert(!allowHomeNat(true,true,true,true,true,true));
  assert(allowDirectNat(true,true,true,true));
#endif
  std::cout << "PASS: safe home egress gating\n";
}

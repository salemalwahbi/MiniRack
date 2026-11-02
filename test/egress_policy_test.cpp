#include "minirack_egress_policy.h"
#include <cassert>
#include <iostream>
int main() {
  using namespace MiniRackEgressPolicy;
#if MINIRACK_HOME_EGRESS_REQUIRED == 1
  assert(!allowDirectNat(true,true,true,true));
#else
  assert(allowDirectNat(true,true,true,true));
  assert(!allowDirectNat(false,true,true,true));
  assert(!allowDirectNat(true,false,true,true));
  assert(!allowDirectNat(true,true,false,true));
  assert(!allowDirectNat(true,true,true,false));
#endif
  std::cout << "PASS: direct-WAN NAPT gating (home-only is fail-closed)\n";
}

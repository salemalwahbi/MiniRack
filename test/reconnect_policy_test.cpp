#include "minirack_reconnect.h"
#include <assert.h>
int main(){
  using namespace MiniRackReconnect;
  assert(!due(19000,0,0)); assert(due(20000,0,0));
  assert(delayMs(1)==30000);assert(delayMs(5)==90000);assert(delayMs(99)==90000);
  assert(!due(47000,20000,1)); assert(due(50000,20000,1));
  // Tick counter wrap is intentional with unsigned elapsed duration.
  assert(due(25000u,0xFFFFFF00u,0));
  return 0;
}

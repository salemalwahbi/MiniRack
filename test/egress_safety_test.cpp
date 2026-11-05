#include <cassert>
#include <cstdint>
#include <cstring>
#include "minirack_guest_policy.h"
using namespace MiniRackGuestPolicy;

static void packet(uint8_t *f, uint32_t dest, uint8_t proto=6,
                   uint16_t sp=50000, uint16_t dp=443){
  memset(f,0,82); memset(f,0x11,6); memset(f+6,0x22,6);
  f[12]=8; f[13]=0; f[14]=0x45; f[17]=40; f[23]=proto;
  f[26]=192; f[27]=168; f[28]=4; f[29]=2;
  for(int i=0;i<4;i++) f[30+i]=uint8_t(dest >> (24-8*i));
  f[34]=sp>>8; f[35]=sp&255; f[36]=dp>>8; f[37]=dp&255;
}
int main(){
  uint8_t f[82];
  packet(f,0x08080808U);
  assert(allowFrameForEgress(f,82,Role::GUEST,false)); // direct internet
  assert(!allowFrameForEgress(f,82,Role::GUEST,true)); // no home leak
  assert(allowFrameForEgress(f,82,Role::OWNER,true)); // owner permitted
  assert(!allowFrameForEgress(f,82,Role::UNKNOWN,false));
  packet(f,0xffffffffU,17,68,67);
  assert(allowFrameForEgress(f,82,Role::GUEST,true)); // DHCP still works
  packet(f,0xc0a80401U,6,50000,80);
  assert(!allowFrameForEgress(f,82,Role::GUEST,true));
  packet(f,0x08080808U,17,50000,53);
  assert(!allowFrameForEgress(f,82,Role::GUEST,true)); // block DNS egress
  return 0;
}

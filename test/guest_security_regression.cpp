#include "minirack_guest_policy.h"
#include <cassert>
#include <cstring>
#include <cstdio>
using MiniRackGuestPolicy::Role;
using MiniRackGuestPolicy::allowFrame;
static void packet(uint8_t f[82], uint8_t proto=6) {
  memset(f,0,82);memset(f,0x51,6);memset(f+6,0x22,6);
  f[12]=8;f[13]=0;f[14]=0x45;f[16]=0;f[17]=40;
  f[23]=proto;f[26]=192;f[27]=168;f[28]=4;f[29]=11;
  f[30]=1;f[31]=1;f[32]=1;f[33]=1;
  f[34]=0x20;f[35]=0xff;f[36]=1;f[37]=187;
}
int main(){
  uint8_t f[82];packet(f);
  assert(allowFrame(f,82,Role::GUEST));
  f[30]=192;f[31]=168;f[32]=4;f[33]=1;
  assert(!allowFrame(f,82,Role::GUEST)); // ESP management
  f[30]=1;f[31]=1;f[32]=1;f[33]=1;
  f[14]=0x44;assert(!allowFrame(f,82,Role::GUEST)); // invalid IP header length
  f[14]=0x45;f[16]=0;f[17]=25;
  assert(!allowFrame(f,82,Role::GUEST)); // short TCP header
  f[17]=40;f[20]=0x20;assert(!allowFrame(f,82,Role::GUEST)); // MF fragmentation
  f[20]=0;f[23]=47;assert(!allowFrame(f,82,Role::GUEST)); // GRE not allowed
  f[23]=6;f[26]=10;assert(!allowFrame(f,82,Role::GUEST)); // spoof source subnet
  packet(f); f[12]=0x86;f[13]=0xdd;
  assert(!allowFrame(f,82,Role::GUEST)); // IPv6 closed
  printf("PASS: guest security regressions (host policy only)\n");
}

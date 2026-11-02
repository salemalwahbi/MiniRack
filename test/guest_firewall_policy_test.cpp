#include <cassert>
#include <cstdint>
#include <cstring>
#include "minirack_guest_policy.h"
#include <initializer_list>
using namespace MiniRackGuestPolicy;

static void ipv4(uint8_t *f,uint32_t dst,uint8_t proto=6,uint16_t sport=5555,
                 uint16_t dport=443,uint16_t frag=0,uint32_t src=0xc0a80402U){
  memset(f,0,82);
  memset(f,0x23,6); // AP Ethernet destination placeholder
  memset(f+6,0x18,6);
  f[12]=0x08; f[13]=0x00;
  f[14]=0x45; f[16]=0; f[17]=40;
  f[20]=frag>>8;f[21]=frag&255;
  f[23]=proto;
  for(int i=0;i<4;i++){
    f[26+i]=(uint8_t)(src>>(24-8*i));
    f[30+i]=(uint8_t)(dst>>(24-8*i));
  }
  f[34]=sport>>8; f[35]=sport&255;
  f[36]=dport>>8; f[37]=dport&255;
}
int main(){
  uint8_t f[82];
  ipv4(f,0x08080808);
  assert(allowFrame(f,82,Role::GUEST));
  assert(allowFrame(f,82,Role::OWNER));
  assert(!allowFrame(f,82,Role::UNKNOWN));
  for(uint32_t dst:{0x0a000001U,0xac100005U,0xc0a80101U,0xc0a80401U,
                    0x64400001U,0xa9fe0101U,0x7f000001U,0xe00000fbU,
                    0xc6336401U,0xcb007109U}){
     ipv4(f,dst);assert(!allowFrame(f,82,Role::GUEST));
  }
  ipv4(f,0x01010101,17,61234,53);
  assert(allowFrame(f,82,Role::GUEST));
  ipv4(f,0x08080808,6,5555,443,0x2000);
  assert(!allowFrame(f,82,Role::GUEST));
  ipv4(f,0xc0a80401,6,5555,80);
  assert(allowFrame(f,82,Role::UNKNOWN));
  assert(!allowFrame(f,82,Role::GUEST));
  ipv4(f,0xc0a80401,6,5555,22);
  assert(!allowFrame(f,82,Role::UNKNOWN));
  ipv4(f,0xffffffff,17,68,67,0,0);
  assert(allowFrame(f,82,Role::GUEST));
  assert(allowFrame(f,82,Role::UNKNOWN));
  memset(f,0,82);f[12]=0x86;f[13]=0xdd;
  assert(!allowFrame(f,82,Role::GUEST));
  assert(allowFrame(f,82,Role::OWNER));
  memset(f,0,82); memset(f,0xff,6);
  memset(f+6,0x18,6); memset(f+22,0x18,6);
  f[12]=0x08;f[13]=0x06;f[15]=1;f[16]=8;f[18]=6;f[19]=4;f[21]=1;
  f[38]=192;f[39]=168;f[40]=4;f[41]=1;
  assert(allowFrame(f,82,Role::GUEST));
  f[41]=2; assert(!allowFrame(f,82,Role::GUEST));
  f[41]=1;f[21]=2;assert(!allowFrame(f,82,Role::GUEST));
  f[21]=1;f[22]=0x19;assert(!allowFrame(f,82,Role::GUEST)); // spoofed ARP sender
  assert(!allowFrame(nullptr,0,Role::GUEST));
  return 0;
}

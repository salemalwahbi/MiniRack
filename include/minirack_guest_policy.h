#pragma once
#include <stddef.h>
#include <stdint.h>

// Strict IPv4 guest egress policy, applied BEFORE lwIP NAT on the AP ingress.
// Owner is separate. This does not claim Wi-Fi L2 client isolation or strong
// station identity; both require additional hardware-level validation.
namespace MiniRackGuestPolicy {
enum class Role : uint8_t { UNKNOWN=0, OWNER=1, GUEST=2 };

inline bool publicIPv4(uint32_t ip) {
  const uint8_t a=(uint8_t)(ip>>24), b=(uint8_t)(ip>>16);
  const uint8_t c=(uint8_t)(ip>>8);
  if(a==0 || a==10 || a==127 || a>=224) return false;
  if(a==100 && b>=64 && b<=127) return false;  // carrier-grade NAT
  if(a==169 && b==254) return false;             // link local
  if(a==172 && b>=16 && b<=31) return false;   // RFC1918
  if(a==192 && b==168) return false;
  if(a==192 && b==0 && c==0) return false;
  if(a==192 && b==0 && c==2) return false;      // documentation
  if(a==192 && b==88 && c==99) return false;    // former 6to4 relay
  if(a==198 && (b==18 || b==19)) return false;  // benchmarks
  if(a==198 && b==51 && c==100) return false;
  if(a==203 && b==0 && c==113) return false;
  return true;
}

// Frame starts at Ethernet header (14 bytes); encapsulated VLAN frames are
// intentionally rejected, never transparently bridged.
inline bool allowFrame(const uint8_t *f, size_t n, Role role) {
  if (role==Role::OWNER) return true;
  if (!f || n<14) return false;
  const uint16_t eth=(uint16_t(f[12])<<8)|f[13];
  // A non-owner must send to the AP (unicast), not directly another client.
  // Broadcast Ethernet is allowed only for ARP/DHCP below.
  const bool broadcast=f[0]==0xff && f[1]==0xff && f[2]==0xff &&
                       f[3]==0xff && f[4]==0xff && f[5]==0xff;
  if (eth==0x0806) { // ARP: only ask for the AP gateway, no spoofed replies
    if(n<42 || f[14]!=0 || f[15]!=1 || f[16]!=0x08 || f[17]!=0 ||
       f[18]!=6 || f[19]!=4 || f[20]!=0 || f[21]!=1) return false;
    if(!broadcast) return false;
    // ARP hardware sender must equal Ethernet sender. Otherwise a station
    // could forge gateway ARP responses or poison neighbours' cache.
    for(size_t i=0;i<6;i++)if(f[22+i]!=f[6+i])return false;
    // Sender IP may be 0.0.0.0 while probing, or its 192.168.4.x lease.
    const bool probe=f[28]==0 && f[29]==0 && f[30]==0 && f[31]==0;
    const bool local=f[28]==192 && f[29]==168 && f[30]==4 &&
                     f[31]>=2 && f[31]<=254;
    if(!probe && !local)return false;
    // ARP target protocol address at Ethernet offset 38.
    return f[38]==192 && f[39]==168 && f[40]==4 && f[41]==1;
  }
  if (eth!=0x0800 || n<34) return false; // block IPv6, all other protocols
  const uint8_t ver=f[14]>>4, hlen=(f[14]&15)*4;
  if(ver!=4 || hlen<20 || n<size_t(14+hlen)) return false;
  const uint16_t iplen=(uint16_t(f[16])<<8)|f[17];
  if(iplen<hlen || iplen>1500) return false; // reject invalid/Jumbo IPv4
  // A bare TCP/UDP header is not a valid routed packet.
  if((f[23]==6 && iplen<hlen+20) || (f[23]==17 && iplen<hlen+8)) return false;
  // All fragmented IPv4 frames are blocked for guests: no fragment bypass.
  const uint16_t frag=(uint16_t(f[20])<<8)|f[21];
  if((frag&0x3fff)!=0) return false;
  const uint32_t src=(uint32_t(f[26])<<24)|(uint32_t(f[27])<<16)|
                     (uint32_t(f[28])<<8)|f[29];
  const uint32_t dst=(uint32_t(f[30])<<24)|(uint32_t(f[31])<<16)|
                     (uint32_t(f[32])<<8)|f[33];
  const uint8_t proto=f[23];
  // DHCP: bootstrap is required for both guests and QR-pending devices.
  if(proto==17 && n>=size_t(14+hlen+4) && iplen>=hlen+8) {
    const size_t u=14+hlen;
    const uint16_t sp=(uint16_t(f[u])<<8)|f[u+1];
    const uint16_t dp=(uint16_t(f[u+2])<<8)|f[u+3];
    if(sp==68 && dp==67 &&
       (dst==0xffffffffU || dst==0xc0a80401U)) return true;
  }
  // Pending QR re-link and owner first-time pairing: only ESP local HTTP.
  // The web server separately validates the one-use physical QR token.
  if(role==Role::UNKNOWN) {
    if(proto!=6 || dst!=0xc0a80401U || n<size_t(14+hlen+4)) return false;
    const size_t t=14+hlen;
    const uint16_t dp=(uint16_t(f[t+2])<<8)|f[t+3];
    return dp==80;
  }
  // Guests get routed public IPv4 only, no local router/home/VPN/admin/LAN.
  if(role!=Role::GUEST) return false;
  if(src>>24!=192 || ((src>>16)&255)!=168 || ((src>>8)&255)!=4 ||
     (src&255)<2 || (src&255)>254) return false;
  if(!publicIPv4(dst)) return false;
  return proto==6 || proto==17 || proto==1; // TCP, UDP, ICMP
}

// Shared NAPT cannot put MAIN and GUEST on different uplinks. In the opt-in
// home-tunnel experiment, do not allow a GUEST to reach the Internet through
// the HOME tunnel. Permit only DHCP bootstrap so the Wi-Fi client can receive
// a lease. Normal/direct-WAN mode retains its existing guest IPv4 policy.
// This is deliberate temporary containment, NOT simultaneous split routing.
inline bool allowFrameForEgress(const uint8_t *f, size_t n, Role role,
                                bool homeEgress) {
  if (!allowFrame(f, n, role)) return false;
  if (!homeEgress || role != Role::GUEST) return true;
  if (!f || n < 42 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 17)
    return false;
  const uint8_t ihl = (f[14] & 0x0f) * 4;
  if (ihl < 20 || n < size_t(14 + ihl + 4)) return false;
  const size_t u = 14 + ihl;
  const uint16_t sourcePort = (uint16_t(f[u]) << 8) | f[u + 1];
  const uint16_t destPort = (uint16_t(f[u + 2]) << 8) | f[u + 3];
  return sourcePort == 68 && destPort == 67;
}
}

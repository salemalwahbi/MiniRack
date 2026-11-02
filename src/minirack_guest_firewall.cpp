#include "minirack_guest_firewall.h"
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <string.h>

namespace MiniRackGuestFirewall {
namespace {
portMUX_TYPE mux=portMUX_INITIALIZER_UNLOCKED;
KnownStation stations[kMaxKnown]={};
uint8_t number=0;
volatile bool installed=false;
volatile bool scheduled=false;
volatile uint32_t drops=0;
struct netif *hooked=nullptr;
netif_input_fn original=nullptr;

static err_t filterInput(struct pbuf *p, struct netif *n) {
  // If misconfigured or installing/restarting, reject input instead of
  // allowing new guest packets during a transition. The ESP driver frees
  // pbuf on non-ERR_OK; do NOT free it ourselves.
  if(!p || !installed || n!=hooked || !original) return ERR_VAL;
  uint8_t frame[82]={};
  const u16_t copied=pbuf_copy_partial(p,frame,
                     (u16_t)((p->tot_len<sizeof(frame))?p->tot_len:sizeof(frame)),0);
  if(copied<14) { ++drops; return ERR_VAL; }
  MiniRackGuestPolicy::Role role=MiniRackGuestPolicy::Role::UNKNOWN;
  uint8_t ipLease[4]={};
  portENTER_CRITICAL(&mux);
  for(uint8_t i=0;i<number;i++){
    if(memcmp(stations[i].mac,frame+6,6)==0){
      role=stations[i].role;
      memcpy(ipLease,stations[i].leasedIP,4);
      break;
    }
  }
  portEXIT_CRITICAL(&mux);
  const bool broadcast=frame[0]==0xff && frame[1]==0xff && frame[2]==0xff &&
                       frame[3]==0xff && frame[4]==0xff && frame[5]==0xff;
  // Reject even syntactically valid IPv4 traffic addressed to a station's
  // L2 MAC when it reaches lwIP. Direct Wi-Fi intra-BSS forwarding must
  // still be separately tested on the actual ESP driver.
  // Reject truncated IP packets (only a bounded header prefix is copied).
  if(frame[12]==0x08 && frame[13]==0x00 && copied>=34) {
    const uint16_t iplen=(uint16_t(frame[16])<<8)|frame[17];
    if(iplen+14 > p->tot_len) { ++drops; return ERR_VAL; }
  }
  // A guest cannot choose arbitrary source addresses or impersonate the AP.
  // DHCP before getting a lease is exempt; non-DHCP guest traffic needs a
  // nonzero Wi-Fi station lease matching the IPv4 source exactly.
  if(role==MiniRackGuestPolicy::Role::GUEST &&
     frame[12]==0x08 && frame[13]==0x00 && copied>=38) {
    const bool dhcp=frame[23]==17 && copied>=42 &&
      frame[34]==0 && frame[35]==68 && frame[36]==0 && frame[37]==67;
    if(!dhcp && (ipLease[0]==0 || memcmp(frame+26,ipLease,4)!=0)) {
      ++drops; return ERR_VAL;
    }
  }
  if((role!=MiniRackGuestPolicy::Role::OWNER &&
      !broadcast && (n->hwaddr_len!=6 || memcmp(frame,n->hwaddr,6)!=0)) ||
     !MiniRackGuestPolicy::allowFrame(frame,copied,role)) {
    ++drops;
    return ERR_VAL;
  }
  return original(p,n);
}

// Called on lwIP TCP/IP core thread. No custom lwIP compile flags required.
static void installOnTcpipThread(void *) {
  esp_netif_t *ap=esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  struct netif *n=ap ? static_cast<struct netif *>(esp_netif_get_netif_impl(ap)) : nullptr;
  portENTER_CRITICAL(&mux);
  if(n && n->input && n->input!=filterInput) {
    hooked=n;
    original=n->input;
    // Start rejecting unknown stations before publishing readiness.
    n->input=filterInput;
    installed=true;
  } else if(n && n->input==filterInput && original) {
    hooked=n;
    installed=true;
  } else {
    installed=false;
  }
  scheduled=false;
  portEXIT_CRITICAL(&mux);
}
} // namespace

void updateKnown(const KnownStation *src, uint8_t count) {
  if(count>kMaxKnown)count=kMaxKnown;
  portENTER_CRITICAL(&mux);
  number=0;
  if(src)for(uint8_t i=0;i<count;i++)stations[number++]=src[i];
  portEXIT_CRITICAL(&mux);
}
void beginInstall() {
  if(installed || scheduled)return;
  scheduled=true;
  if(tcpip_callback(installOnTcpipThread,nullptr)!=ERR_OK)scheduled=false;
}
bool ready() { return installed && hooked && hooked->input==filterInput; }
uint32_t dropped(){return drops;}
void resetAfterApStop() {
  // AP teardown is performed only after stopping NAT; the callback is not
  // dereferenced here, as esp_netif may have released the underlying netif.
  installed=false;
  hooked=nullptr;
  // Preserve the original callback in case Arduino reuses the same lwIP
  // AP netif across a stop/start; a brand-new netif replaces it on install.
  number=0;
}
} // namespace MiniRackGuestFirewall

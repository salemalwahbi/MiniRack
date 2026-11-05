// MINI RACK STAGE 8: approved navigation + controls redesign.
// STAGE 5: scrollable OWNER/device details; explicit VPN setup feedback.
// MINI RACK V8 - touchscreen usability update based on the recovered V7 firmware.
// - Smaller HOME navigation icons (same touch targets).
// V8.1: recognizable gear, independent "إغلاق الجهاز" button in Settings;
//       device diagnostics are no longer mixed with power controls.
// - V8.1 VPN toggle: enable/disable WireGuard from Secure Link screen; Wi-Fi/AP unaffected.
// - No automatic display-off.
// - Short press on power pill: LCD off; touch to wake (network keeps running).
// - Long press on power pill: existing power options / confirmed deep sleep.
#include <Arduino.h>
#include <WiFi.h>
#include <Network.h>
#include <esp_arduino_version.h>
#include <WireGuard-ESP32.h>
#include "wg_secrets.h"
#include "minirack-bridge-secrets.h"  // generated privately on Pi; never commit
// The working 2.x firmware is preserved in backup_original.
// NAPT requires the dedicated Arduino-ESP32 3.x PlatformIO environment.
#if !defined(ESP_ARDUINO_VERSION_MAJOR) || ESP_ARDUINO_VERSION_MAJOR < 3
  #error "MINI RACK NAT requires Arduino-ESP32 3.x and pioarduino 55.03.35"
#endif
#include <WebServer.h>
#include <HTTPClient.h>
#include <esp_netif.h>  // DHCP captive-portal Option 114 (ESP-IDF 5.x)
#include <esp_event.h>
#include <esp_wifi_ap_get_sta_list.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <esp_sleep.h>
#include <ESPmDNS.h>

// ======================================================
// DISPLAY
// ======================================================

#include <Arduino_GFX_Library.h>  // required: fail build if missing, never a fake black screen

// ======================================================
// CRYPTO + AI
// ======================================================

#include <Wire.h>
#include "crypto_ai.h"
#include "minirack_peers.h"
#include "minirack_nat.h"
#include "minirack_route_policy.h"
#include "minirack_egress_policy.h"
#include "minirack_home_route.h"
#include "minirack_reconnect.h"
#include "minirack_qr_token.h"
#include "minirack_security.h"
#include "minirack_guest_firewall.h"
#include "minirack_v2_client.h"
#include "minirack_transport_v2.h"
#include "ui_minirack_expo_ar.h"


// ======================================================
// LCD PINS
// ======================================================

#define TFT_CS   10
#define TFT_DC   46
#define TFT_SCK  12
#define TFT_MOSI 11
#define TFT_MISO 13
#define TFT_BL   45

#define BATTERY_PIN 1

// ======================================================
// COLORS
// ======================================================

// RGB565 basic colors (BLACK/WHITE) come from Arduino_GFX_Library.h.
// The interface uses grayscale only; no duplicated GFX color macros.

// ======================================================
// DISPLAY OBJECTS
// ======================================================

Arduino_DataBus *bus = new Arduino_ESP32SPI(
  TFT_DC,
  TFT_CS,
  TFT_SCK,
  TFT_MOSI,
  TFT_MISO
);

Arduino_GFX *gfx = new Arduino_ILI9341(
  bus,
  -1,
  0,
  true
);

#include "ui_assets_legacy.h"
#include "ui_owner_ux.h"

static constexpr uint8_t TOUCH_ADDR=0x38;
static constexpr uint8_t MAX_PEERS=16;
static constexpr uint8_t MAX_ONLINE=8;  // simultaneous Wi-Fi stations
static constexpr uint8_t PEERS_PER_PAGE=4; // separate category pages; touch targets remain >= 32 px
static const char *AP_NAME="MiniRack-Secure";
// iPhone-inspired monochrome UI. RGB565: only black, white and neutral greys.
static const uint16_t BG=0x0000;       // black OLED-style background
static const uint16_t PANEL=0x18C3;    // charcoal cards
static const uint16_t PANEL_2=0x2945;  // elevated graphite cards
static const uint16_t BORDER=0x630C;   // grey hairline
static const uint16_t ACCENT=0xFFFF;   // primary white
static const uint16_t MUTED=0xB596;    // secondary soft grey
static const uint16_t DANGER=0xFFFF;   // black-white confirmation, no red
static const uint16_t POWER_WHITE=0xFFFF;
static const int PWR_X=201, PWR_Y=18;
static const uint32_t PWR_HOLD_MS=1250; // V8: short=LCD off, long=power options

static Preferences prefsNet,prefsPeers;
// Earlier firmware stored persistent REJECT entries in NVS. Rejection is now
// ONLY a decision about the current connection. Remove old blacklist entries
// on boot, including upgrades from the persistent-rejection firmware.
static void clearLegacyRejections(){
  for(uint8_t slot=0;slot<16;++slot){
    const String key=String("rej")+String(slot);
    if(prefsNet.isKey(key.c_str()))prefsNet.remove(key.c_str());
  }
}
// Persistent allow-list mirrored in RAM: avoids Preferences/NVS reads on every
// 200 ms station check, and on every screen paint.
// Keep Stage 8 UI accessors while the registry's NVS and MAC handling
// move to a separately compiled C++ translation unit.
static_assert(MAX_PEERS == MiniRackPeers::kMaxPeers, "peer slot count mismatch");
static MiniRackPeers::Registry peerRegistry;
// DHCP hostname reporting is optional in the selected ESP-IDF build.
// Cache only the last few entries; NVS writes happen from main loop.
#if defined(CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME) && CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME
static constexpr uint8_t kDhcpNames=8;
struct DhcpName{uint8_t mac[6];char hostname[33];bool pending;};
static DhcpName dhcpNames[kDhcpNames]={};
static portMUX_TYPE dhcpNameMux=portMUX_INITIALIZER_UNLOCKED;
static void mrDhcpNameEvent(void*,esp_event_base_t,int32_t,void*data){
  const auto *info=static_cast<const ip_event_ap_staipassigned_t*>(data);
  if(!info || !info->hostname[0])return;
  portENTER_CRITICAL(&dhcpNameMux);
  int slot=-1;
  for(int j=0;j<kDhcpNames;j++)
    if(memcmp(dhcpNames[j].mac,info->mac,6)==0){slot=j;break;}
  if(slot<0)for(int j=0;j<kDhcpNames;j++)
    if(!dhcpNames[j].pending){slot=j;break;}
  if(slot>=0){
    memcpy(dhcpNames[slot].mac,info->mac,6);
    size_t q=0;
    while(q<32 && info->hostname[q]){dhcpNames[slot].hostname[q]=info->hostname[q];q++;}
    dhcpNames[slot].hostname[q]=0;
    dhcpNames[slot].pending=true;
  }
  portEXIT_CRITICAL(&dhcpNameMux);
}
static bool mrApplyDhcpNames(){
  bool changed=false;
  for(int j=0;j<kDhcpNames;j++){
    DhcpName item={};
    bool got=false;
    portENTER_CRITICAL(&dhcpNameMux);
    if(dhcpNames[j].pending){item=dhcpNames[j];dhcpNames[j].pending=false;got=true;}
    portEXIT_CRITICAL(&dhcpNameMux);
    if(!got)continue;
    const int slot=peerRegistry.find(item.mac);
    if(slot>=0 && peerRegistry.setReportedHostname((uint8_t)slot,item.hostname))changed=true;
  }
  return changed;
}
#else
static bool mrApplyDhcpNames(){return false;}
#endif

static String (&peerMacs)[MAX_PEERS] = peerRegistry.macs;
static String (&peerLabels)[MAX_PEERS] = peerRegistry.labels;
static bool (&peerAllowed)[MAX_PEERS] = peerRegistry.allowed;
static String &primaryMac = peerRegistry.primary; // current association MAC only
static String &ownerBridgeId = peerRegistry.ownerBridgeId; // stable Pi VPN account ID


static WebServer portal(80);
// Stage 11: threat-aware adaptive telemetry and protected profile delivery.
static MiniRackSecurity::Engine securityMonitor;
static bool securityLastAlert=false;
// Counts HTTP requests received by the ESP32 (does not expose credentials).
static uint32_t portalHttpRequests=0;
static bool arabicLanguage=true;
static String savedSSID,savedPassword,chosenSSID,apPassword;
static bool touchscreenReady=false,wasPressed=false;
// Display sleep is NOT CPU deep sleep: Wi-Fi, NAT, pairing and encrypted telemetry
// continue running.  The touch controller stays powered and any tap wakes the TFT.
static bool screenBlank=false;
static bool autoScreenSleep=false; // V8: NEVER turn off automatically; power button only
static uint32_t lastUserTouchMs=0;
static constexpr uint32_t SCREEN_IDLE_MS=120000;

static uint32_t lastTouchPoll=0,touchDownAt=0;
static int16_t touchStartX=0,touchStartY=0,touchLastX=0,touchLastY=0;
static int16_t touchScrollAnchorY=0;
static bool touchScrolled=false;
static uint32_t pairOpenUntil=0,portalOpenUntil=0;
// Stage 13 candidate: let ONE station wait for physical MAIN approval without
// repeated 200ms deauth. NAT is disabled throughout this admission window.
// This is temporary AP access, NOT an authenticated/authorized GUEST session.
static String pendingPairMac;
static uint32_t pendingPairUntil=0;
// A deleted station may reconnect immediately using its saved WPA password.
// Keep that station out of NAT until a new PHYSICAL role approval, even if
// its Wi-Fi reassociation races ahead of the periodic AP admission refresh.
static String deletedStationAwaitingApproval;
static bool pendingPairActive(){
  return !pendingPairMac.isEmpty() && pendingPairUntil!=0 &&
    (int32_t)(pendingPairUntil-millis())>0;
}
static void cancelPendingPair(){
  pendingPairMac="";
  pendingPairUntil=0;
}

static uint32_t portalChangeMs=0,lastStaRetry=0,lastViewRefresh=0;
static uint8_t staReconnectAttempts=0; // capped reconnection retry backoff
static bool wifiChangePending=false,apChangePending=false;
static String nextAPPassword;
static uint8_t selectedPeer=0;
static int userScroll=0,wifiScroll=0; // finger-scrolled list positions, not MORE pages
// Scroll one menu item at a time. Header, owner status and Back remain fixed.
static uint8_t peerDetailScroll=0;
static constexpr uint8_t MR5_DETAIL_ITEMS=4;
static constexpr uint8_t MR5_DETAIL_VISIBLE=2;
static int lastScanCount=0;
static bool uiDirty=true;
static bool portalForAPKey=false;
// Direct iPhone profile delivery, DEVELOPMENT ONLY: HTTP last hop over WPA2 AP.
static bool portalForVpn=false;
static bool portalForOwnerRelink=false; // physical approval for MAIN or extra owned device
static bool relinkExtraDevice=false; // controls UI copy/return path only; authorization stays in Registry
// Stage 6 QR page state: 0 ready, 1 insecure default AP key, 2 AP off,
// 3 WireGuard not initialized, 4 selected device is not MAIN.
static uint8_t ownerQrBlock=0;
static bool ownerProfileIssued=false;  // means served, NOT confirmed installed on phone
// A fresh 128-bit scan token replaces typed PINs for physical OWNER setup.
// Development prototype: the last hop is still HTTP on the local Wi-Fi AP.
static MiniRackQrToken::Approval qrApproval;
static String &mr7OwnerUrl=qrApproval.url;
static bool &mr7QrReady=qrApproval.ready;
static uint8_t vpnPinFailures=0; // reserved for legacy non-OWNER setup paths
static char ownerSetupMessage[32] = "";
static uint32_t ownerSetupMessageUntil=0;
static void ownerStatus(const char *msg){
  snprintf(ownerSetupMessage,sizeof(ownerSetupMessage),"%s",msg);
  ownerSetupMessageUntil=millis()+15000;
  uiDirty=true;
}

// V6: network state changes repaint just the header + live card, NOT the whole TFT.
// Arduino_GFX SPI panels show a visible flash if fillScreen() runs every few seconds.
static bool liveInfoDirty=true;
static uint32_t lastLivePaint=0;
static uint32_t lastReadoutPaint=0;
static uint32_t lastPaintFingerprint=0xFFFFFFFFu;
static bool wakeBacklightPending=false;
static bool apStartFailed=false;

// Mini Rack internet forwarding. NAT alone is NOT a firewall.
// GUEST packets are screened on the AP ingress before NAPT is enabled.
static MiniRackNat::Controller natController;
static bool &natActive=natController.active;
static uint32_t &natLastAttempt=natController.lastAttempt;
static bool natShareEnabled=true; // separately controlled internet sharing, saved in NVS
static bool natStationPolicyOk=false; // only admitted stations; guests require AP packet filter
// Broadcast is an explicit, persistent setting. Pairing remains a separate,
// temporary permission window; switching pairing off NEVER restarts the AP.
static bool apBroadcastEnabled=true;
// User preference, defaults ON to preserve the previously working automatic VPN.
// This flag controls the tunnel only; it never stops the uplink or MiniRack AP.
static bool vpnEnabled=true;
static WireGuard vpnTunnel;
static bool vpnNtpStarted=false;
static bool vpnAttempted=false;
static uint32_t vpnLastAttemptMs=0;
static uint32_t vpnLastPollMs=0;
static String vpnBoundNetwork;
static uint8_t vpnLastUiState=255;
static constexpr uint32_t VPN_RETRY_MS=30000;
static bool setBroadcastEnabled(bool enabled);  // implemented after NAT stop
static void miniNatStop();
static void mrSecurityObserve(MiniRackSecurity::Event event,uint32_t sourceTag);
static void mrSecurityTick();
static uint32_t mrSecurityIPTag(const IPAddress &ip);

static constexpr uint32_t NAT_RETRY_MS=6000;
static const IPAddress AP_IP(192,168,4,1);
static const IPAddress AP_MASK(255,255,255,0);
static const IPAddress AP_LEASE_START(192,168,4,10);
static const IPAddress AP_DNS(1,1,1,1); // Preserve normal DNS; no wildcard DNS hijack.
// Android/iOS can use RFC 8910 DHCP Option 114 to discover an onboarding page.
// The OS may choose NOT to open a captive window. Never claim forced installation.
static char CAPTIVE_API_URL[]="http://192.168.4.1/captive-api";
static const char *CAPTIVE_PAGE_URL="http://192.168.4.1/onboard";


enum class View:uint8_t {HOME, USERS, MY_DEVICES, GUESTS, PAIR_CHOICE, PEER_DETAILS, CONFIRM_REMOVE, CONFIRM_UNSET_PRIMARY, CONFIRM_SET_PRIMARY, INTERNET, WIFI_LIST, WIFI_SETUP, OWNER_VPN_QR,
                         SECURE,SETTINGS,DEVICE_INFO,CONFIRM_RESTART,POWER,CONFIRM_AP_OFF,STATUS,TRANSPORTS};
static View view=View::HOME;
static View returnView=View::HOME;
static View userReturnView=View::USERS; // back from device details / confirm removal
static View pairingReturnView=View::HOME; // restore the owner's page after first-join prompt

static bool windowOpen(uint32_t until) {
  return until!=0 && (int32_t)(until-millis())>0;
}
static void go(View dest) {
  if(dest==View::PEER_DETAILS && view!=View::PEER_DETAILS)peerDetailScroll=0;
  view=dest;uiDirty=true;
}

static void eng(int x,int y,const char *s,uint16_t c=WHITE,uint8_t sz=1) {
  gfx->setTextColor(c);gfx->setTextSize(sz);gfx->setCursor(x,y);gfx->print(s);
}
static void bitmapText(int cx,int y,const uint8_t *bits,int w,int h,uint16_t c) {
  int sx=cx-w/2,stride=(w+7)/8;
  for(int yy=0;yy<h;yy++) {
    int run=-1;
    for(int xx=0;xx<=w;xx++) {
      bool on=false;
      if(xx<w) on=(((pgm_read_byte(bits+yy*stride+xx/8)>>(7-xx%8))&1)!=0);
      if(on && run<0) run=xx;
      if(!on && run>=0) {gfx->drawFastHLine(sx+run,y+yy,xx-run,c);run=-1;}
    }
  }
}
static void word(int cx,int y,Word w,uint16_t c=WHITE) {
  const WordGlyph &g=WORDS[(int)w];bitmapText(cx,y,g.data,g.w,g.h,c);
}
static void arabicOld(int cx,int y,ArLabel id,uint16_t c=WHITE) {
  const ArBitmap &g=AR_BITMAPS[(int)id];bitmapText(cx,y,g.data,g.width,g.height,c);
}
static void labelWord(int cx,int y,Word w,const char *en,uint16_t c=WHITE,uint8_t size=1) {
  if(arabicLanguage) word(cx,y,w,c);
  else eng(cx-(int)strlen(en)*3*size,y,en,c,size);
}
static void surface(int x,int y,int w,int h,uint16_t fill=PANEL,int radius=10,uint16_t edge=BORDER) {
  gfx->fillRoundRect(x,y,w,h,radius,fill);
  gfx->drawRoundRect(x,y,w,h,radius,edge);
}
static void textButton(int x,int y,int w,int h,Word ar,const char *en,
                       bool danger=false,bool bright=false) {
  const uint16_t fill=bright?WHITE:(danger?0x1082:PANEL);
  const uint16_t edge=bright?WHITE:(danger?MUTED:BORDER);
  surface(x,y,w,h,fill,10,edge);
  int yy=y+(h-(arabicLanguage?WORDS[(int)ar].h:8))/2;
  labelWord(x+w/2,yy,ar,en,bright?BLACK:WHITE);
}


// MINI RACK V9: compact touch-safe Arabic UI. Generated glyphs live in flash.
#include "ui_assets_stage8.h"
#include "ui_labels_stage16.h"

static void mr8Arabic(MR8Label id,int cx,int cy,uint16_t color=WHITE){
  const MR8Glyph &g=MR8_GLYPHS[(uint8_t)id];
  bitmapText(cx,cy-g.h/2,g.data,g.w,g.h,color);
}
static void mr8Caption(MR8Label label,int cx,int cy,const char *english,uint16_t color=WHITE){
  if(arabicLanguage)mr8Arabic(label,cx,cy,color);
  else eng(cx-3*(int)strlen(english),cy-4,english,color,1);
}
static void mr8Switch(int x,int y,bool on){
  // Native iPhone-style 43x25 switch; state is read from real subsystem flags.
  const uint16_t fill=on?0x366A:0x6B4D;
  gfx->fillRoundRect(x,y,43,25,12,fill);
  gfx->fillCircle(on?x+30:x+13,y+12,9,WHITE);
}
static void mr8Arrow(int cx,int cy){
  gfx->drawLine(cx-3,cy-4,cx+2,cy,MUTED);
  gfx->drawLine(cx+2,cy,cx-3,cy+4,MUTED);
}
static void mr8Title(MR8Label title,const char *en){
  mr8Caption(title,120,62,en,WHITE);
}

static void powerDot() {
  // Compact iPhone-inspired earpiece + camera pill (not an immediate power off).
  // A tap opens two SEPARATE actions: display sleep and confirmed deep sleep.
  gfx->fillRoundRect(173,7,58,24,12,PANEL_2);
  gfx->drawRoundRect(173,7,58,24,12,WHITE);
  gfx->fillRoundRect(183,17,15,3,1,WHITE); // earpiece
  gfx->drawCircle(217,19,5,WHITE);         // camera
  gfx->fillCircle(217,19,2,MUTED);
}
static void blankUi() {
  digitalWrite(TFT_BL,LOW);
  uiDirty=false;
}
static void sleepDisplay() {
  if(screenBlank)return;
  screenBlank=true;
  // Turn off backlight BEFORE blanking the framebuffer to avoid visible flash.
  digitalWrite(TFT_BL,LOW);
  gfx->fillScreen(BLACK);
  uiDirty=false;
  liveInfoDirty=false;
  Serial.println("MINIRACK DISPLAY OFF: Wi-Fi and NAT continue");
}
static void wakeDisplay() {
  if(!screenBlank)return;
  screenBlank=false;
  lastUserTouchMs=millis();
  // Draw while backlight is OFF, then switch it on only after rendering.
  wakeBacklightPending=true;
  uiDirty=true;
  liveInfoDirty=true;
  Serial.println("MINIRACK DISPLAY WAKE");
}

static void lineWifiIcon(int cx,int cy,uint16_t c) {
  gfx->drawLine(cx-11,cy-5,cx,cy-10,c);gfx->drawLine(cx,cy-10,cx+11,cy-5,c);
  gfx->drawLine(cx-7,cy+1,cx,cy-2,c);gfx->drawLine(cx,cy-2,cx+7,cy+1,c);
  gfx->fillCircle(cx,cy+7,2,c);
}

static void statusWarning(int x,int y) {
  gfx->drawCircle(x,y,7,WHITE);
  gfx->drawFastVLine(x,y-4,6,WHITE);
  gfx->fillCircle(x,y+4,1,WHITE);
}
static bool uplinkHasIp(){return WiFi.status()==WL_CONNECTED && WiFi.STA.hasIP();}
static bool broadcastLive(){return apBroadcastEnabled && WiFi.AP.localIP()[0]!=0;}
static bool subnetCollision(){
  if(!uplinkHasIp())return false;
  IPAddress ip=WiFi.localIP();
  return ip[0]==192 && ip[1]==168 && ip[2]==4;
}

static bool weakUplink(){
  static bool weak=false;
  if(!uplinkHasIp()){weak=false;return false;}
  const int rssi=WiFi.RSSI();
  if(rssi<=-80)weak=true;
  else if(rssi>=-72)weak=false;
  return weak;
}
// Fault classification uses observable link/routing status; VPN remains unverified.
enum class NetworkHealth:uint8_t {READY,NO_SOURCE,CONNECTING,UPLINK_LOST,AP_PAUSED,AP_FAILED,NO_NAT,CONFLICT,WEAK};
static NetworkHealth networkHealth(){
  if(apStartFailed)return NetworkHealth::AP_FAILED;
  if(!apBroadcastEnabled)return NetworkHealth::AP_PAUSED;
  if(savedSSID.isEmpty())return NetworkHealth::NO_SOURCE;
  if(!uplinkHasIp())return millis()<12000?NetworkHealth::CONNECTING:NetworkHealth::UPLINK_LOST;
  if(subnetCollision())return NetworkHealth::CONFLICT;
  if(!natActive)return NetworkHealth::NO_NAT;
  if(weakUplink())return NetworkHealth::WEAK;
  return NetworkHealth::READY;
}
static const char *healthTitle(NetworkHealth h){
  switch(h){
  case NetworkHealth::READY:return "ROUTING ACTIVE";
  case NetworkHealth::NO_SOURCE:return "SET UP UPLINK";
  case NetworkHealth::CONNECTING:return "CONNECTING TO WI-FI";
  case NetworkHealth::UPLINK_LOST:return "UPLINK DISCONNECTED";
  case NetworkHealth::AP_PAUSED:return "BROADCAST PAUSED";
  case NetworkHealth::AP_FAILED:return "BROADCAST FAILED";
  case NetworkHealth::NO_NAT:return "NAT NOT READY";
  case NetworkHealth::CONFLICT:return "SUBNET CONFLICT";
  case NetworkHealth::WEAK:return "WEAK WI-FI SIGNAL";
  }return "CHECK NETWORK";
}
static const char *healthAdvice(NetworkHealth h){
  switch(h){
  case NetworkHealth::READY:return "Wi-Fi + NAT available";
  case NetworkHealth::NO_SOURCE:return "Choose a source Wi-Fi";
  case NetworkHealth::CONNECTING:return "Waiting for source Wi-Fi";
  case NetworkHealth::UPLINK_LOST:return "Check hotspot or router";
  case NetworkHealth::AP_PAUSED:return "Start AP in Internet menu";
  case NetworkHealth::AP_FAILED:return "Restart AP / check logs";
  case NetworkHealth::NO_NAT:return "Check uplink and NAT";
  case NetworkHealth::CONFLICT:return "Uplink uses 192.168.4.x";
  case NetworkHealth::WEAK:return "Move closer to hotspot";
  }return "Open network details";
}

static void drawHealthTitle(int cx,int y,NetworkHealth h){
  if(arabicLanguage){
    const WordGlyph &g=V6_AR_TITLE_TEXT[(int)h];
    bitmapText(cx,y,g.data,g.w,g.h,WHITE);
  }else eng(19,y,healthTitle(h),WHITE,1);
}
static void drawHealthAdvice(int cx,int y,NetworkHealth h){
  if(arabicLanguage){
    const WordGlyph &g=V6_AR_ADVICE_TEXT[(int)h];
    bitmapText(cx,y,g.data,g.w,g.h,MUTED);
  }else eng(19,y,healthAdvice(h),MUTED,1);
}
static void v6OtherArabic(int cx,int y,int which,uint16_t color=WHITE){
  const WordGlyph &g=V6_AR_OTHER_TEXT[which];
  bitmapText(cx,y,g.data,g.w,g.h,color);
}

// RGB565 grayscale blended against the solid card background. Text is drawn
// as short scanline runs so SPI traffic stays low; no large sprites are kept.
static uint16_t v7BlendWhite(uint16_t bg,uint8_t intensity){
  const int r=((bg>>11)&31),g=((bg>>5)&63),b=(bg&31);
  const int rr=r+((31-r)*intensity+1)/3;
  const int gg=g+((63-g)*intensity+1)/3;
  const int bb=b+((31-b)*intensity+1)/3;
  return (uint16_t)((rr<<11)|(gg<<5)|bb);
}
static void v7SoftText(int cx,int y,const V7SoftGlyph &t,uint16_t background=PANEL_2){
  const int left=cx-(int)t.w/2, stride=(t.w+3)/4;
  const uint16_t color[4]={background,v7BlendWhite(background,1),
                            v7BlendWhite(background,2),WHITE};
  for(int yy=0;yy<(int)t.h;yy++){
    int start=0;uint8_t previous=0;
    for(int xx=0;xx<=t.w;xx++){
      uint8_t now=0;
      if(xx<t.w){
        const uint8_t packed=pgm_read_byte(t.data+yy*stride+xx/4);
        now=(packed>>(6-2*(xx%4)))&3;
      }
      if(now!=previous){
        if(previous)gfx->drawFastHLine(left+start,y+yy,xx-start,color[previous]);
        start=xx;previous=now;
      }
    }
  }
}
static void v7PowerPill(){
  // Small power capsule exactly 39x27 px, on the LEFT as in the reference.
  gfx->fillRoundRect(10,8,39,27,13,PANEL_2);
  // Deliberately no filled white button: dark iOS-style pill.
  gfx->drawRoundRect(10,8,39,27,13,BORDER);
  gfx->drawCircle(29,22,8,WHITE);
  gfx->fillRect(24,12,10,8,PANEL_2); // gap at top of power symbol
  gfx->drawFastVLine(29,10,11,WHITE);
}
static void v7RouteIcon(int cx,int cy,uint16_t c){
  // Opposing arrowheads = NAT/router forwarding, not VPN.
  gfx->drawFastHLine(cx-8,cy-5,16,c);
  gfx->drawLine(cx+4,cy-9,cx+8,cy-5,c);
  gfx->drawLine(cx+4,cy-1,cx+8,cy-5,c);
  gfx->drawFastHLine(cx-8,cy+6,16,c);
  gfx->drawLine(cx-4,cy+2,cx-8,cy+6,c);
  gfx->drawLine(cx-4,cy+10,cx-8,cy+6,c);
}
static void v7ApIcon(int cx,int cy,uint16_t c){
  gfx->fillCircle(cx,cy,2,c);
  gfx->drawCircle(cx,cy,6,c);
  gfx->drawLine(cx-10,cy-6,cx-12,cy-3,c);
  gfx->drawLine(cx+10,cy-6,cx+12,cy-3,c);
}
static void v7WarningDot(int x,int y){
  gfx->fillCircle(x,y,5,WHITE);
  gfx->drawFastVLine(x,y-3,4,BG);
  gfx->fillCircle(x,y+3,1,BG);
}
static void v7CheckCircle(int x,int y,NetworkHealth h){
  uint16_t c=(h==NetworkHealth::READY)?0x07E0:0xFD20;
  gfx->drawCircle(x,y,8,c);
  if(h==NetworkHealth::READY){
    gfx->drawLine(x-4,y,x-1,y+3,c);
    gfx->drawLine(x-1,y+3,x+5,y-4,c);
  }else{
    gfx->drawFastVLine(x,y-5,7,c);
    gfx->fillCircle(x,y+5,1,c);
  }
}
static void v7UsersIcon(int cx,int cy){
  // Two-person line icon drawn as true resolution vectors.
  gfx->drawCircle(cx-4,cy-5,5,WHITE);
  gfx->drawCircle(cx+9,cy-3,4,WHITE);
  gfx->drawRoundRect(cx-13,cy+3,18,11,5,WHITE);
  gfx->drawLine(cx+9,cy+3,cx+14,cy+5,WHITE);
  gfx->drawLine(cx+14,cy+5,cx+15,cy+13,WHITE);
}
static void v7ShieldIcon(int cx,int cy){
  gfx->drawLine(cx-10,cy-13,cx,cy-17,WHITE);
  gfx->drawLine(cx,cy-17,cx+10,cy-13,WHITE);
  gfx->drawLine(cx-10,cy-13,cx-9,cy+5,WHITE);
  gfx->drawLine(cx+10,cy-13,cx+9,cy+5,WHITE);
  gfx->drawLine(cx-9,cy+5,cx,cy+14,WHITE);
  gfx->drawLine(cx+9,cy+5,cx,cy+14,WHITE);
  gfx->drawLine(cx-5,cy-1,cx-1,cy+3,WHITE);
  gfx->drawLine(cx-1,cy+3,cx+5,cy-5,WHITE);
}
static void v7SettingsIcon(int cx,int cy){
  gfx->drawCircle(cx,cy,11,WHITE);
  gfx->drawCircle(cx,cy,4,WHITE);
  static const int8_t dx1[8]={12,9,0,-9,-12,-9,0,9};
  static const int8_t dy1[8]={0,9,12,9,0,-9,-12,-9};
  static const int8_t dx2[8]={16,12,0,-12,-16,-12,0,12};
  static const int8_t dy2[8]={0,12,16,12,0,-12,-16,-12};
  for(int t=0;t<8;t++)gfx->drawLine(cx+dx1[t],cy+dy1[t],cx+dx2[t],cy+dy2[t],WHITE);
}
// V8: use compact, legible line-art icons instead of oversized V7 glyphs.
// Only the DRAWING is smaller: cards and touch hitboxes remain 106x62 px.
// V8.1: Arabic label rendered as a compact RTL 1-bit glyph: "إغلاق الجهاز".
// Does not depend on system fonts or Arabic shaping at runtime.
static const uint8_t V81_AR_CLOSE_DEVICE[] PROGMEM = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0xCC,0x00,0x00,0x00,0x04,0x00,0x0C,0x00,0x00,0x30,0x00,0x00,0x00,0xCC,0x00,0x00,0x00,0x04,0x02,0x0C,0x00,0x00,0x30,0x00,0x00,0x00,0xCC,0x00,0x02,0x40,0x04,0x06,0x0C,0x00,0x04,0x30,0x00,0x00,0x00,0xCC,0x00,0x03,0x42,0x04,0x00,0x0C,0x00,0x04,0x10,0x00,0x00,0x00,0xCC,0x00,0x00,0x03,0x84,0x00,0x0C,0x00,0x00,0x10,0x0C,0x00,0x00,0xC4,0x00,0x00,0x01,0xC6,0x0F,0x84,0x00,0x00,0x10,0x1E,0x00,0x00,0xC4,0x00,0x01,0xC0,0xC6,0x1F,0x04,0x00,0x02,0x10,0x36,0x3E,0x00,0xC4,0x00,0x03,0xE0,0x66,0x18,0x04,0x00,0x06,0x10,0x66,0x3F,0x80,0xC4,0x00,0x06,0x60,0x36,0x10,0x04,0x00,0x03,0x18,0x66,0x00,0xF0,0xC4,0x00,0x06,0x30,0x1E,0x10,0x04,0x00,0x03,0x18,0x66,0x00,0xF0,0xC4,0x03,0x06,0x30,0x0E,0x18,0x04,0x00,0x03,0x18,0x4C,0x03,0xE0,0xC4,0x03,0x07,0xF0,0x1E,0x0E,0xC4,0x00,0x03,0x1F,0xFF,0xFF,0x3F,0xC4,0x02,0x03,0xF3,0xF7,0xFF,0xC4,0x00,0x03,0x0F,0xE7,0xF8,0x1F,0x86,0x02,0x00,0x23,0xE3,0xFC,0x06,0x00,0x02,0x00,0x63,0x00,0x00,0x00,0x03,0x00,0x60,0x00,0x00,0x00,0x00,0x06,0x00,0x61,0x00,0x00,0x00,0x03,0x80,0xC0,0x00,0x00,0x00,0x00,0x1C,0x00,0x3F,0x02,0x00,0x00,0x01,0xFF,0x80,0x00,0x00,0x06,0x00,0x38,0x00,0x1E,0x06,0x00,0x00,0x00,0xFE,0x00,0x00,0x00,0x08,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static constexpr int V81_CLOSE_W=97, V81_CLOSE_H=23;

static void v8CompactNavIcon(int which,int cx,int cy){
  switch(which){
    case 0: // Internet: 20x15 Wi-Fi mark
      gfx->drawLine(cx-9,cy-5,cx,cy-9,WHITE);
      gfx->drawLine(cx,cy-9,cx+9,cy-5,WHITE);
      gfx->drawLine(cx-6,cy+0,cx,cy-3,WHITE);
      gfx->drawLine(cx,cy-3,cx+6,cy+0,WHITE);
      gfx->fillCircle(cx,cy+5,2,WHITE);
      break;
    case 1: // Users: compact pair of people
      gfx->drawCircle(cx-4,cy-5,4,WHITE);
      gfx->drawCircle(cx+7,cy-3,3,WHITE);
      gfx->drawRoundRect(cx-12,cy+2,15,10,4,WHITE);
      gfx->drawRoundRect(cx+3,cy+3,10,8,4,WHITE);
      break;
    case 2: // Settings: clearly recognizable compact 8-tooth gear
      gfx->fillCircle(cx,cy,9,WHITE);
      gfx->fillRect(cx-2,cy-13,5,6,WHITE); // upper tooth
      gfx->fillRect(cx-2,cy+8,5,6,WHITE);  // lower tooth
      gfx->fillRect(cx-13,cy-2,6,5,WHITE); // left tooth
      gfx->fillRect(cx+8,cy-2,6,5,WHITE);  // right tooth
      gfx->fillRect(cx-10,cy-10,5,5,WHITE);
      gfx->fillRect(cx+6,cy-10,5,5,WHITE);
      gfx->fillRect(cx-10,cy+6,5,5,WHITE);
      gfx->fillRect(cx+6,cy+6,5,5,WHITE);
      gfx->fillCircle(cx,cy,4,PANEL_2);   // central gear hole
      break;
    default: // Secure: compact outlined shield
      gfx->drawLine(cx-8,cy-10,cx,cy-13,WHITE);
      gfx->drawLine(cx,cy-13,cx+8,cy-10,WHITE);
      gfx->drawLine(cx-8,cy-10,cx-7,cy+4,WHITE);
      gfx->drawLine(cx+8,cy-10,cx+7,cy+4,WHITE);
      gfx->drawLine(cx-7,cy+4,cx,cy+11,WHITE);
      gfx->drawLine(cx+7,cy+4,cx,cy+11,WHITE);
      gfx->drawLine(cx-4,cy-1,cx-1,cy+2,WHITE);
      gfx->drawLine(cx-1,cy+2,cx+4,cy-4,WHITE);
      break;
  }
}
static void v7NavCard(int x,int y,int which){
  // V8 compact icons: preserve existing grid, language labels and hitboxes.
  surface(x,y,106,62,PANEL_2,13,BORDER);
  const int cx=x+53, cy=y+20;
  v8CompactNavIcon(which,cx,cy);
  if(arabicLanguage)v7SoftText(cx,y+41,V7_BUTTON[which],PANEL_2);
  else{
    static const char* en[]={"INTERNET","USERS","SETTINGS","SECURE"};
    eng(cx-((int)strlen(en[which])*3),y+46,en[which],WHITE,1);
  }
}


static void miniStatusBar(){
  v7PowerPill();
  // Service indicators appear only when the service is truly running.
  if(natActive && broadcastLive() && uplinkHasIp())v7RouteIcon(65,21,WHITE);
  else if(broadcastLive() && uplinkHasIp() && natLastAttempt &&
          (uint32_t)(millis()-natLastAttempt)>3500)v7WarningDot(65,21);
  if(broadcastLive())v7ApIcon(96,21,WHITE);
  else if(apStartFailed)v7WarningDot(96,21);
  if(uplinkHasIp()){
    lineWifiIcon(127,19,WHITE);
    if(weakUplink())v7WarningDot(140,13);
  }else if(savedSSID.length() && millis()>12000)v7WarningDot(127,21);
  // No VPN symbol until a verified tunnel exists.
}
static void header(){
  gfx->fillScreen(BG); // Only on real page navigation.
  miniStatusBar();
  v7SoftText(190,16,V7_LOGO[0],BG); // MINIRACK name only at the top right
  gfx->drawFastHLine(10,46,220,BORDER);
}
static void refreshHeaderOnly(){
  // Fast little status strip, never erase or flash the entire TFT.
  gfx->fillRect(51,5,98,35,BG);
  miniStatusBar();
}
static void backButton() {textButton(10,286,220,29,Word::BACK,"Back");}
static void statusPill(int x,int y,const char *s,bool on) {
  surface(x,y,90,22,on?PANEL_2:PANEL,11,on?WHITE:BORDER);
  gfx->fillCircle(x+12,y+11,3,on?WHITE:MUTED);
  eng(x+21,y+7,s,on?WHITE:MUTED,1);
}
static void icon(uint8_t type,int x,int y) {
  // Crisp monochrome vector icons.
  if(type==0) {
    gfx->drawCircle(x,y-5,7,WHITE);
    gfx->drawRoundRect(x-14,y+4,28,15,7,WHITE);
    gfx->fillCircle(x+11,y-10,3,MUTED);
  } else if(type==1) lineWifiIcon(x,y,WHITE);
  else if(type==2) {
    gfx->drawLine(x-12,y-10,x,y-15,WHITE);gfx->drawLine(x,y-15,x+12,y-10,WHITE);
    gfx->drawLine(x-12,y-10,x-9,y+8,WHITE);gfx->drawLine(x+12,y-10,x+9,y+8,WHITE);
    gfx->drawLine(x-9,y+8,x,y+16,WHITE);gfx->drawLine(x+9,y+8,x,y+16,WHITE);
    // Shield is an icon, not a guarantee that VPN is connected.
    gfx->drawLine(x-5,y,x-1,y+5,WHITE);gfx->drawLine(x-1,y+5,x+6,y-4,WHITE);
  } else {
    gfx->drawCircle(x,y,11,WHITE);gfx->drawCircle(x,y,4,WHITE);
    for(int j=0;j<4;j++){
      gfx->drawLine(x+(j==0?0:j==1?0:j==2?-15:15), y+(j==0?-15:j==1?15:0),
                    x+(j==0?0:j==1?0:j==2?-12:12), y+(j==0?-12:j==1?12:0),WHITE);
    }
  }
}
static void homeCard(int x,int y,Word w,const char *label,int ic) {
  surface(x,y,106,63,PANEL_2,13,BORDER);
  icon(ic,x+53,y+18);
  if(arabicLanguage) word(x+53,y+41,w,WHITE);
  else eng(x+8,y+46,label,WHITE,1);
}
static void drawBootBrand() {
  // Real product-name splash, no network SSID or unused language selector.
  gfx->fillScreen(BLACK);
  gfx->drawRoundRect(69,67,102,94,20,BORDER);
  gfx->drawCircle(120,101,20,WHITE);
  lineWifiIcon(120,99,WHITE);
  gfx->setTextColor(WHITE);gfx->setTextSize(2);
  gfx->setCursor(60,178);gfx->print("MINI RACK");
  eng(71,206,"TRAVEL ROUTER",MUTED);
  gfx->drawFastHLine(57,232,126,BORDER);
  eng(92,245,"STARTING",MUTED);
}
// Legacy single-file call sites deliberately kept as thin UI adapters.
// The registry module owns NVS-backed association state; it does NOT grant
// cryptographic identities or network firewall privileges.
static String macToStr(const uint8_t *mac) { return MiniRackPeers::formatMac(mac); }
static bool parseMac(const String &s,uint8_t *mac) { return MiniRackPeers::parseMac(s,mac); }
static String peerKey(uint8_t i) { return MiniRackPeers::peerKey(i); }
static String accessKey(uint8_t i) { return MiniRackPeers::accessKey(i); }
static String nameKey(uint8_t i) { return MiniRackPeers::nameKey(i); }
static String defaultPeerName(uint8_t i) { return MiniRackPeers::defaultName(i); }
static String getPeerName(uint8_t i) { return peerRegistry.name(i); }
// Device names are assigned automatically. No owner-facing rename control.
// Actual client hostname is used only when the DHCP server reports it.
static String getPeer(uint8_t i) { return i<MAX_PEERS?peerMacs[i]:String(""); }
static bool isPrimary(uint8_t i) { return peerRegistry.isPrimary(i); }
static bool isMyDevice(uint8_t i) { return peerRegistry.isOwnerAuthorized(i); }
static uint8_t pairedCount() {
  // SAVED is strictly the persistent OWNER/MY DEVICES count, never temporary
  // GUEST or waiting association records.
  uint8_t count=0;
  for(uint8_t i=0;i<MAX_PEERS;i++)
    if(!peerMacs[i].isEmpty() && !peerRegistry.isTransient(i))++count;
  return count;
}
static void loadPeerState() {
  peerRegistry.load(prefsPeers);
  // One-time migration: previous firmware did not packet-filter GUESTs.
  // Revoke any legacy guest authorizations rather than inheriting unsafe
  // permissions. Approvals made after this version survive subsequent boots.
  if(!prefsNet.getBool("guestfwv1",false)) {
    for (uint8_t i=0;i<MAX_PEERS;++i) {
      if(!peerMacs[i].isEmpty() && !isMyDevice(i) && peerAllowed[i]) {
        if(!peerRegistry.setAllowed(i,false))peerAllowed[i]=false;
      }
    }
    if(!prefsNet.putBool("guestfwv1",true))
      Serial.println("MINIRACK: guest permission migration not persisted");
  }
}
static void mrSyncGuestFirewall() {
  MiniRackGuestFirewall::KnownStation stations[MAX_PEERS]={};
  // Wi-Fi association MAC is not authentication, but binding each approved
  // station's currently leased IPv4 reduces source-spoofing opportunities.
  wifi_sta_list_t wifiList={};
  wifi_sta_mac_ip_list_t leases={};
  const bool haveLeases=esp_wifi_ap_get_sta_list(&wifiList)==ESP_OK &&
      esp_wifi_ap_get_sta_list_with_ip(&wifiList,&leases)==ESP_OK;
  uint8_t count=0;
  for(uint8_t i=0;i<MAX_PEERS;i++) {
    if(peerMacs[i].isEmpty())continue;
    uint8_t mac[6];
    if(!MiniRackPeers::parseMac(peerMacs[i],mac))continue;
    memcpy(stations[count].mac,mac,6);
    stations[count].role=isMyDevice(i)
      ? MiniRackGuestPolicy::Role::OWNER
      : (peerAllowed[i] ? MiniRackGuestPolicy::Role::GUEST
                        : MiniRackGuestPolicy::Role::UNKNOWN);
    if(haveLeases)for(int k=0;k<leases.num;k++) {
      if(memcmp(stations[count].mac,leases.sta[k].mac,6)!=0)continue;
      IPAddress leased((uint32_t)leases.sta[k].ip.addr);
      for(int q=0;q<4;q++)stations[count].leasedIP[q]=leased[q];
      break;
    }
    ++count;
  }
  MiniRackGuestFirewall::updateKnown(stations,count);
}
static int findPair(const uint8_t *mac) { return peerRegistry.find(mac); }
static bool setPeerAllowed(uint8_t i,bool allowed) {
  // A physical approval can grant guest Internet ONLY if packet admission
  // is active. On installation failure, all guest packets stay blocked.
  if(allowed && !isMyDevice(i) && !MiniRackGuestFirewall::ready()) {
    Serial.println("MINIRACK GUEST DENIED: AP packet firewall not ready");
    ownerStatus("GUEST FILTER NOT READY");
    return false;
  }
  if (!peerRegistry.setGuestSession(i,allowed)) return false;
  if (allowed && deletedStationAwaitingApproval.equalsIgnoreCase(getPeer(i)))
    deletedStationAwaitingApproval="";
  mrSyncGuestFirewall();
  if(!allowed)miniNatStop();
  uiDirty=true;
  return true;
}
// Explicit touchscreen-approved MAIN selection or transfer; does not depend
// on the temporary network pairing window after the device is already saved.
// This physical confirmation does NOT revoke any prior IKEv2 credentials on Pi.
static bool isPeerOnline(uint8_t i);
static bool selectMainOnScreen(uint8_t i) {
  if(i>=MAX_PEERS || peerMacs[i].isEmpty())return false;
  if(isPrimary(i))return true;
  // A transfer requires the replacement to actually be connected at approval.
  // Initial enrollment may choose a saved, temporarily offline phone.
  if(!primaryMac.isEmpty() && !isPeerOnline(i)){
    ownerStatus("CONNECT NEW MAIN FIRST");
    return false;
  }
  if(!peerRegistry.transferPrimary(i)){
    ownerStatus("MAIN CHANGE NOT SAVED");
    return false;
  }
  if(deletedStationAwaitingApproval.equalsIgnoreCase(getPeer(i)))
    deletedStationAwaitingApproval="";
  mrSyncGuestFirewall();
  miniNatStop(); // Force admission against the newly approved role.
  cancelPendingPair();
  pairOpenUntil=0;
  ownerProfileIssued=false;
  prefsNet.putBool("ownerprof",false);
  ownerStatus("MAIN SAVED - VPN SETUP");
  uiDirty=true;
  return true;
}
static bool clearPrimary() {
  if (!peerRegistry.clearPrimary()) return false;
  mrSyncGuestFirewall();
  ownerProfileIssued=false;
  prefsNet.putBool("ownerprof",false);
  uiDirty=true;
  return true;
}
static bool addPair(const uint8_t *mac) {
  if (findPair(mac)>=0) return true;
  const int slot=peerRegistry.addPending(mac);
  if (slot<0) return false;
  selectedPeer=(uint8_t)slot;
  mrSyncGuestFirewall();
  pairOpenUntil=0; // automatic screen approval; no manual pairing action
  // Pending station remains DHCP-only; existing MAIN/GUEST internet continues.
  // The lwIP ingress hook denies routing for this unapproved session.
  pendingPairMac=macToStr(mac);
  pendingPairUntil=millis()+120000;
  // Arrival prompts on the physical display immediately, regardless of menu.
  pairingReturnView=(view==View::PAIR_CHOICE)?pairingReturnView:view;
  userReturnView=View::USERS;
  go(View::PAIR_CHOICE);
  Serial.printf("MINIRACK NEW DEVICE PENDING: %s\n",peerMacs[slot].c_str());
  return true;
}
// Approved guest -> saved owned device. Always re-evaluate the AP firewall.
// Caller handles navigation only after a confirmed successful NVS write.
static bool promoteToMyDevices(uint8_t slot){
  if(slot>=MAX_PEERS || peerMacs[slot].isEmpty() || !isPeerOnline(slot)){
    ownerStatus("CONNECT DEVICE FIRST");return false;
  }
  if(primaryMac.isEmpty())return selectMainOnScreen(slot);
  if(!peerRegistry.setOwnerDevice(slot,true)){
    ownerStatus("SAVE FAILED");return false;
  }
  if(deletedStationAwaitingApproval.equalsIgnoreCase(getPeer(slot)))
    deletedStationAwaitingApproval="";
  mrSyncGuestFirewall();
  miniNatStop();
  cancelPendingPair();
  ownerStatus("SAVED IN MY DEVICES");
  return true;
}
static void deauthByMac(const uint8_t*mac){
  uint16_t aid=0;
  if(esp_wifi_ap_get_sta_aid(mac,&aid)==ESP_OK)esp_wifi_deauth_sta(aid);
}
static wifi_sta_list_t getClients(){wifi_sta_list_t list={};esp_wifi_ap_get_sta_list(&list);return list;}
// Prove the browser belongs to the *currently associated* OWNER station.
// Checking a saved MAC alone is not a reliable authorization proof.
static bool isOwnerBrowser(const IPAddress &remote){
  if(!apBroadcastEnabled || primaryMac.isEmpty()) return false;
  if(remote[0]!=AP_IP[0] || remote[1]!=AP_IP[1] || remote[2]!=AP_IP[2])
    return false;
  wifi_sta_list_t wireless={};
  wifi_sta_mac_ip_list_t addressList={};
  if(esp_wifi_ap_get_sta_list(&wireless)!=ESP_OK) return false;
  if(esp_wifi_ap_get_sta_list_with_ip(&wireless,&addressList)!=ESP_OK) return false;
  for(int i=0;i<addressList.num;i++){
    IPAddress address((uint32_t)addressList.sta[i].ip.addr);
    if(address==remote && primaryMac.equalsIgnoreCase(macToStr(addressList.sta[i].mac)))
      return true;
  }
  return false;
}
// Map THIS browser's AP IP to the Wi-Fi station MAC. This is only a
// station mapping: OWNER privilege requires a physical approval + PIN too.
static bool mrClientMacForIP(const IPAddress &remote,String &mac){
  mac="";
  if(!apBroadcastEnabled || remote[0]!=192 || remote[1]!=168 || remote[2]!=4)return false;
  wifi_sta_list_t wl={};
  wifi_sta_mac_ip_list_t ips={};
  if(esp_wifi_ap_get_sta_list(&wl)!=ESP_OK ||
     esp_wifi_ap_get_sta_list_with_ip(&wl,&ips)!=ESP_OK)return false;
  for(int i=0;i<ips.num;i++){
    IPAddress candidate((uint32_t)ips.sta[i].ip.addr);
    if(candidate==remote){mac=macToStr(ips.sta[i].mac);return true;}
  }
  return false;
}
static bool isPeerOnline(uint8_t i){
  if(i>=MAX_PEERS || peerMacs[i].isEmpty())return false;
  wifi_sta_list_t list=getClients();
  for(int k=0;k<list.num;k++)
    if(peerMacs[i].equalsIgnoreCase(macToStr(list.sta[k].mac)))return true;
  return false;
}
static void enforcePairing(){
  static uint32_t lastCheck=0;
  if((uint32_t)(millis()-lastCheck)<300)return;
  lastCheck=millis();
  const wifi_sta_list_t list=getClients();
  // Forget every temporary GUEST/PENDING entry as soon as the Wi-Fi
  // association ends. MAIN and MY DEVICES remain saved.
  bool removed=false;
  for(uint8_t slot=0;slot<MAX_PEERS;slot++){
    if(!peerRegistry.isTransient(slot) || peerMacs[slot].isEmpty())continue;
    bool present=false;
    for(int k=0;k<list.num;k++){
      if(peerMacs[slot].equalsIgnoreCase(macToStr(list.sta[k].mac))){present=true;break;}
    }
    if(present)continue;
    if(pendingPairMac.equalsIgnoreCase(peerMacs[slot]))cancelPendingPair();
    if(view==View::PAIR_CHOICE && selectedPeer==slot)go(pairingReturnView);
    if(view==View::PEER_DETAILS && selectedPeer==slot)go(View::USERS);
    if(peerRegistry.expireDisconnected(slot))removed=true;
  }
  if(removed){mrSyncGuestFirewall();uiDirty=true;}
  for(int i=0;i<list.num;i++){
    const uint8_t *mac=list.sta[i].mac;
    const int slot=findPair(mac);
    // A station rejected on its previous association is not blacklisted.
    // Each new association must go through the physical approval screen.
    if(slot>=0){
      // Existing OWNED, approved GUEST, or pending station. Packet filter
      // limits pending traffic to DHCP and on-device pairing page.
      continue;
    }
    if(pendingPairActive()){
      // One unknown station at a time. Do not auto-approve or store others.
      deauthByMac(mac);continue;
    }
    if(portalForOwnerRelink && windowOpen(portalOpenUntil))continue;
    // Only the physical owner gets to choose MY DEVICE or GUEST. The
    // unapproved device never receives forwarding rights automatically.
    if(addPair(mac))continue;
    uint32_t tag=2166136261U;
    for(int b=0;b<6;++b)tag=(tag ^ mac[b])*16777619U;
    mrSecurityObserve(MiniRackSecurity::Event::UnregisteredStation,tag);
    deauthByMac(mac);
  }
}

// The home information card is a LIVE control: tap it to inspect actionable faults.

static void drawHomeStatusCard(){
  surface(10,78,220,72,PANEL_2,12,BORDER);
  const bool wan=uplinkHasIp();
  const bool ap=broadcastLive();
  const bool routed=wan && ap && natActive;
  gfx->fillCircle(23,95,4,routed?0x366A:MUTED);
  mr8Caption(MR8Label::NET_STATUS,123,96,"NETWORK STATUS",WHITE);
  char line[44];
  snprintf(line,sizeof(line),"WAN %s   AP %s   NAT %s",wan?"ON":"OFF",ap?"ON":"OFF",natActive?"ON":"OFF");
  eng(18,114,line,wan?WHITE:MUTED,1);
  snprintf(line,sizeof(line),"ONLINE %u  |  SAVED %u",(unsigned)getClients().num,(unsigned)pairedCount());
  eng(18,134,line,MUTED,1);
}

static void drawHome(){
  header();
  mr8Title(MR8Label::HOME,"HOME");
  drawHomeStatusCard();
  // Four main destinations, 106x60 px touch targets.
  static const MR8Label navLabels[]={MR8Label::NETWORK,MR8Label::SECURE,MR8Label::USERS,MR8Label::SETTINGS};
  static const char*navEn[]={"NETWORK","SECURE","USERS","SETTINGS"};
  static const uint8_t navIcons[]={0,3,1,2};
  for(int i=0;i<4;i++){
    const int x=(i%2)?124:10;
    const int y=(i/2)?229:159;
    surface(x,y,106,60,PANEL_2,12,BORDER);
    v8CompactNavIcon(navIcons[i],x+53,y+21);
    if(i==1)eng(x+53-9,y+42,"VPN",WHITE,1);
    else mr8Caption(navLabels[i],x+53,y+46,navEn[i],WHITE);
  }
  // Notifications are on the device itself; we cannot assume iPhone installed a profile.
  if(!primaryMac.isEmpty() && !ownerProfileIssued)
    mr8Caption(MR8Label::FIRST_PAIR,120,303,"OWNER NEEDS VPN",MUTED);
}

// Category lists are independent pages. Nothing in this view grants network rights.
static bool listedInGroup(View group, uint8_t i){
  if(i>=MAX_PEERS || peerMacs[i].isEmpty())return false;
  if(group==View::MY_DEVICES)return isMyDevice(i);
  // "Guest" means a LIVE, approved, temporary session only.
  // Pending and legacy stale entries do not belong in this list.
  if(group==View::GUESTS)
    return peerRegistry.isTransient(i) && peerAllowed[i] && !isMyDevice(i);
  return false;
}
static int groupDeviceCount(View group){
  int count=0;
  for(uint8_t i=0;i<MAX_PEERS;i++)if(listedInGroup(group,i))++count;
  return count;
}
static int groupSlotAt(View group,int ordinal){
  if(ordinal<0)return -1;
  for(uint8_t i=0;i<MAX_PEERS;i++)if(listedInGroup(group,i)){
    if(ordinal--==0)return i;
  }
  return -1;
}
static int groupOnlineCount(View group){
  int count=0;
  for(uint8_t i=0;i<MAX_PEERS;i++)
    if(listedInGroup(group,i) && isPeerOnline(i))++count;
  return count;
}
static int myDeviceCount(){return groupDeviceCount(View::MY_DEVICES);}
static int clampListScroll(int value,int count,int visible){
  return max(0,min(value,max(0,count-visible)));
}
static uint8_t detailActionCount(){
  return (isPrimary(selectedPeer) || (!isMyDevice(selectedPeer) && !peerMacs[selectedPeer].isEmpty()))?2:MR5_DETAIL_ITEMS;
}
static void mr16ArabicLabel(int cx,int y,const uint8_t *bits,int w,int h){
  bitmapText(cx,y,bits,w,h,WHITE);
}
static void drawUsers(){
  header();mr8Title(MR8Label::USERS,"USERS");
  wifi_sta_list_t stations=getClients();
  surface(10,78,220,36,PANEL_2,10,BORDER);
  char summary[48];snprintf(summary,sizeof(summary),"MINE %d   GUEST %d   ONLINE %d",
      groupDeviceCount(View::MY_DEVICES),groupDeviceCount(View::GUESTS),stations.num);
  eng(17,94,summary,WHITE,1);
  // New stations are approved only from the physical role-choice screen.
  surface(10,120,220,45,PANEL_2,9,BORDER);
  if(arabicLanguage)mr16ArabicLabel(111,127,MR16_MY,MR16_MY_W,MR16_MY_H);
  else eng(52,138,"MY DEVICES",WHITE,1);
  char count[12];snprintf(count,sizeof(count),"%d",myDeviceCount());
  eng(184,138,count,MUTED,1);mr8Arrow(214,143);
  surface(10,173,220,45,PANEL_2,9,BORDER);
  if(arabicLanguage)mr16ArabicLabel(111,180,MR16_GUEST,MR16_GUEST_W,MR16_GUEST_H);
  else eng(72,191,"GUESTS",WHITE,1);
  snprintf(count,sizeof(count),"%d",groupDeviceCount(View::GUESTS));
  eng(184,191,count,MUTED,1);mr8Arrow(214,196);
  backButton();
}
// Only the NEW connection receives a role-choice screen, automatically.
// Guests already approved instead open management: promote to MY DEVICES or delete.
static void drawPairChoice(){
  header();
  if(arabicLanguage)bitmapText(120,51,MRUX_NEW_DEVICE_TITLE,MRUX_NEW_DEVICE_TITLE_W,MRUX_NEW_DEVICE_TITLE_H,WHITE);
  else eng(66,55,"NEW CONNECTION",WHITE,1);
  surface(10,85,220,76,PANEL_2,10,BORDER);
  String label=getPeerName(selectedPeer);
  if(label.length()>18)label=label.substring(0,18);
  eng(19,101,label.c_str(),WHITE,1);
  if(arabicLanguage)bitmapText(120,125,MRUX_CHOOSE_ROLE,MRUX_CHOOSE_ROLE_W,MRUX_CHOOSE_ROLE_H,WHITE);
  else eng(54,130,"CHOOSE DEVICE TYPE",WHITE,1);
  surface(10,178,220,46,PANEL_2,10,BORDER);
  if(arabicLanguage)bitmapText(120,186,MR16_MY,MR16_MY_W,MR16_MY_H,WHITE);
  else eng(88,195,"MY DEVICES",WHITE,1);
  surface(10,232,220,46,PANEL_2,10,BORDER);
  if(arabicLanguage)bitmapText(120,238,MRUX_ROLE_GUEST,MRUX_ROLE_GUEST_W,MRUX_ROLE_GUEST_H,WHITE);
  else eng(101,249,"GUEST",WHITE,1);
  // Third CHOICE replaces Back: reject this station and revoke access.
  surface(10,286,220,29,PANEL,9,BORDER);
  if(arabicLanguage)bitmapText(120,288,MRUX_REJECT,MRUX_REJECT_W,MRUX_REJECT_H,WHITE);
  else eng(102,298,"REJECT",WHITE,1);
}
static void drawDeviceGroupArea(){
  const View group=view;
  const int count=groupDeviceCount(group);
  userScroll=clampListScroll(userScroll,count,PEERS_PER_PAGE);
  gfx->fillRect(0,119,240,163,BG);
  for(int row=0;row<PEERS_PER_PAGE && userScroll+row<count;row++){
    const int slot=groupSlotAt(group,userScroll+row);
    if(slot<0)break;
    const uint8_t i=(uint8_t)slot;
    const int y=123+row*36;
    surface(10,y,220,32,PANEL_2,8,BORDER);
    String label=getPeerName(i);
    if(label.length()>14)label=label.substring(0,14);
    eng(18,y+11,label.c_str(),WHITE,1);
    const char *role=isPrimary(i)?"MAIN":isMyDevice(i)?"MINE":
                     (peerAllowed[i]?"GUEST":"WAIT");
    eng(150,y+11,role,isMyDevice(i)?WHITE:MUTED,1);
    if(isPeerOnline(i))gfx->fillCircle(199,y+16,3,WHITE);
    mr8Arrow(216,y+16);
  }
  if(count==0)eng(59,173,"NO DEVICES ONLINE",MUTED,1);
  char line[40];snprintf(line,sizeof(line),"SWIPE UP / DOWN   %d-%d / %d",
       count?userScroll+1:0,min(userScroll+PEERS_PER_PAGE,count),count);
  eng(14,275,line,MUTED,1);
}
static void drawDeviceGroup(){
  header();
  if(view==View::MY_DEVICES){
    if(arabicLanguage)mr16ArabicLabel(120,47,MR16_MY,MR16_MY_W,MR16_MY_H);
    else eng(87,59,"MY DEVICES",WHITE,1);
  }else{
    if(arabicLanguage)mr16ArabicLabel(120,53,MR16_GUEST,MR16_GUEST_W,MR16_GUEST_H);
    else eng(94,59,"GUESTS",WHITE,1);
  }
  surface(10,80,220,32,PANEL_2,9,BORDER);
  char status[44];snprintf(status,sizeof(status),"DEVICES %d   ONLINE %d",
        groupDeviceCount(view),groupOnlineCount(view));
  eng(18,92,status,WHITE,1);
  drawDeviceGroupArea();
  backButton();
}

// Stage 5: ordered device actions with finger swipe / arrow navigation.
// Two full-height buttons are always visible; never draw cropped touch targets.
static void drawPeerDetails(){
  header();
  if(arabicLanguage)bitmapText(120,53,ROLE_AR_TITLE,ROLE_AR_TITLE_W,ROLE_AR_TITLE_H,WHITE);
  else eng(70,56,"DEVICE DETAILS",WHITE,1);
  surface(10,77,220,80,PANEL_2,12,BORDER);
  String friendly=getPeerName(selectedPeer);
  if(friendly.length()>14)friendly=friendly.substring(0,14);
  eng(17,85,friendly.c_str(),WHITE,2);
  eng(17,110,getPeer(selectedPeer).c_str(),MUTED,1);
  const bool owner=isPrimary(selectedPeer);
  const bool mine=peerRegistry.isOwnerDevice(selectedPeer);
  const bool online=isPeerOnline(selectedPeer);
  const bool awaitingRole=!owner && !mine && !peerAllowed[selectedPeer];
  eng(17,126,owner?"MAIN":mine?"MY DEVICE":
    (peerAllowed[selectedPeer]?"GUEST":"WAITING OWNER"),WHITE,1);
  eng(126,126,online?"ONLINE":"OFFLINE",online?WHITE:MUTED,1);
  if((int32_t)(ownerSetupMessageUntil-millis())>0)
    eng(17,143,ownerSetupMessage,WHITE,1);
  else if(owner){
    if(!online)eng(17,143,"MAIN OFFLINE",MUTED,1);
    else if(!vpnEnabled || !vpnTunnel.is_initialized())eng(17,143,"VPN TUNNEL NOT READY",MUTED,1);
    else eng(17,143,"VPN SETUP: VPN PAGE",MUTED,1);
  }else if(mine){
    eng(17,143,"LOCAL AP ACCESS - MAC BASED",MUTED,1);
  }else if(awaitingRole){
    eng(17,143,online?"SELECT DEVICE TYPE":"DEVICE DISCONNECTED",MUTED,1);
  }
  // Approved guest: PROMOTE TO MY DEVICES / DELETE. Pending stations are
  // classified in PAIR_CHOICE on association, never in this details page.
  if(mine || owner){
    if(arabicLanguage)bitmapText(116,161,MR5_SWIPE_HINT,MR5_SWIPE_HINT_W,MR5_SWIPE_HINT_H,MUTED);
    else eng(51,161,"SWIPE UP / DOWN",MUTED,1);
  }
  const uint8_t detailItems=detailActionCount();
  peerDetailScroll=min(peerDetailScroll,(uint8_t)(detailItems-MR5_DETAIL_VISIBLE));
  for(uint8_t row=0;row<MR5_DETAIL_VISIBLE;row++){
    const uint8_t action=(uint8_t)(peerDetailScroll+row);
    const int y=183+row*49;
    const bool destructive=(owner?action>=1:(mine?action==1||action==3:action==1 && peerAllowed[selectedPeer]));
    surface(10,y,220,43,destructive?PANEL:PANEL_2,9,destructive?MUTED:BORDER);
    // New role labels use English until matching Arabic glyph assets are generated.
    // Legacy bitmap labels are kept only for unchanged actions.
    const char* title="";
    const uint8_t *bits=nullptr;int w=0,h=0;
    if(owner){
      title=action==0?"REMOVE MAIN ROLE":"DELETE DEVICE";
      if(arabicLanguage){
        if(action==0){bits=MR5_UNSET_PRIMARY_BUTTON;w=MR5_UNSET_PRIMARY_BUTTON_W;h=MR5_UNSET_PRIMARY_BUTTON_H;}
        else{bits=MR5_DELETE_DEVICE_BUTTON;w=MR5_DELETE_DEVICE_BUTTON_W;h=MR5_DELETE_DEVICE_BUTTON_H;}
      }
    }else if(mine){
      title=action==0?"SET AS MAIN":action==1?"REMOVE MY DEVICE":
            action==2?"RE-LINK DEVICE":"DELETE DEVICE";
    }else{
      title=action==0?"ADD TO MY DEVICES":"DELETE";
      if(arabicLanguage){
        if(action==0){bits=MRUX_MINE_ADD;w=MRUX_MINE_ADD_W;h=MRUX_MINE_ADD_H;}
        else{bits=MR5_DELETE_DEVICE_BUTTON;w=MR5_DELETE_DEVICE_BUTTON_W;h=MR5_DELETE_DEVICE_BUTTON_H;}
      }
    }
    if(arabicLanguage && !owner){
      if(action==0){
        if(mine){bits=MRUX_MAIN;w=MRUX_MAIN_W;h=MRUX_MAIN_H;}
        // Guest promotion above already has its own "إضافة لأجهزتي" bitmap.
      }
      else if(mine && action==1){bits=MRUX_MINE_REMOVE;w=MRUX_MINE_REMOVE_W;h=MRUX_MINE_REMOVE_H;}
      else if(mine && action==2){bits=MRUX_RELINK;w=MRUX_RELINK_W;h=MRUX_RELINK_H;}
    }
    if(bits)bitmapText(120,y+(43-h)/2,bits,w,h,WHITE);
    else eng(19,y+17,title,action==1&&!owner&&!mine?MUTED:WHITE,1);
  }
  if(mine || owner){
    char location[18];
    snprintf(location,sizeof(location),"%u-%u / %u",
         (unsigned)(peerDetailScroll+1),(unsigned)(peerDetailScroll+2),(unsigned)detailItems);
    eng(14,276,peerDetailScroll>0?"^ UP":"  UP",MUTED,1);
    eng(95,276,location,MUTED,1);
    eng(188,276,peerDetailScroll<detailItems-MR5_DETAIL_VISIBLE?"DOWN v":"DOWN",MUTED,1);
  }
  backButton();
}
// Destructive role changes require a second physical confirmation.
static void drawConfirmSetPrimary(){
  header();
  if(arabicLanguage){
    if(primaryMac.isEmpty())bitmapText(120,54,MRUX_CONFIRM_INITIAL,MRUX_CONFIRM_INITIAL_W,MRUX_CONFIRM_INITIAL_H,WHITE);
    else bitmapText(120,54,MRUX_CONFIRM_CHANGE,MRUX_CONFIRM_CHANGE_W,MRUX_CONFIRM_CHANGE_H,WHITE);
  }else eng(43,55,primaryMac.isEmpty()?"SET FIRST MAIN?":"CHANGE MAIN?",WHITE,1);
  surface(10,94,220,103,PANEL_2,12,BORDER);
  String label=getPeerName(selectedPeer);
  if(label.length()>19)label=label.substring(0,19);
  eng(18,111,label.c_str(),WHITE,1);
  if(arabicLanguage)bitmapText(120,131,MRUX_CONFIRM_HINT,MRUX_CONFIRM_HINT_W,MRUX_CONFIRM_HINT_H,MUTED);
  else eng(18,136,"Approve on this screen.",MUTED,1);
  if(!primaryMac.isEmpty()){
    if(arabicLanguage)bitmapText(120,163,MRUX_CONFIRM_VPN,MRUX_CONFIRM_VPN_W,MRUX_CONFIRM_VPN_H,MUTED);
    else{
      eng(18,157,"Old Wi-Fi role removed.",MUTED,1);
      eng(18,178,"Old phone VPN stays on Pi!",MUTED,1);
    }
  }else{
    eng(18,164,"No PIN or manual rename.",MUTED,1);
  }
  textButton(10,213,220,45,Word::CONFIRM,"CONFIRM MAIN",true);
  textButton(10,270,220,43,Word::CANCEL,"CANCEL");
}
static void drawConfirmUnsetPrimary(){
  header();
  eng(42,55,"REMOVE MAIN ROLE?",WHITE,1);
  surface(10,94,220,94,PANEL_2,12,BORDER);
  eng(18,112,"This phone will no longer",WHITE,1);
  eng(18,135,"be the Mini Rack OWNER.",WHITE,1);
  eng(18,161,"VPN delivery will stop.",MUTED,1);
  textButton(10,213,220,45,Word::CONFIRM,"REMOVE MAIN ROLE",true);
  textButton(10,270,220,43,Word::CANCEL,"CANCEL");
}
static void drawConfirmRemove(){
 header();labelWord(120,56,Word::CONFIRM,"CONFIRM REMOVE",DANGER);
 surface(10,94,220,94,PANEL_2,12,BORDER);
 eng(18,110,getPeer(selectedPeer).c_str(),WHITE,1);
 eng(18,139,"Remove this saved device",MUTED,1);
 eng(18,155,"and revoke its pairing?",MUTED,1);
 textButton(10,213,220,45,Word::REMOVE,"REMOVE",true);
 textButton(10,270,220,43,Word::CANCEL,"Cancel");
}

static void drawInternetReadout(){
  // Live uplink readout: do not clear switch/buttons during refresh.
  gfx->fillRoundRect(10,144,220,63,11,PANEL_2);
  gfx->drawRoundRect(10,144,220,63,11,BORDER);
  mr8Caption(MR8Label::INTERNET_SOURCE,120,157,"INTERNET SOURCE",WHITE);
  if(uplinkHasIp()){
    String ss=WiFi.SSID();if(ss.length()>21)ss=ss.substring(0,21);
    eng(20,181,ss.c_str(),WHITE,1);
    char dbm[19];snprintf(dbm,sizeof(dbm),"%d dBm",(int)WiFi.RSSI());
    eng(20,194,dbm,MUTED,1);
  }else eng(21,183,"NO UPLINK - TAP TO SELECT",MUTED,1);
  mr8Arrow(211,177);
}

static void drawInternet(){
  header();mr8Title(MR8Label::NETWORK,"NETWORK");
  surface(10,82,220,54,PANEL_2,11,BORDER);
  mr8Caption(MR8Label::DEVICE_WIFI,86,101,"DEVICE WI-FI",WHITE);
  eng(20,119,apBroadcastEnabled?"MiniRack-Secure":"HOTSPOT OFF",MUTED,1);
  mr8Switch(172,96,apBroadcastEnabled);
  drawInternetReadout();
  surface(10,216,220,56,PANEL_2,11,BORDER);
  mr8Caption(MR8Label::SHARE_NET,91,235,"SHARE INTERNET",WHITE);
  const char *natLabel=!natShareEnabled?"NAT DISABLED":
      (MiniRackEgressPolicy::kRequireHomeEgress && !MiniRackEgressPolicy::kHomeExperiment)?"HOME ONLY: NAT BLOCKED":
      (MiniRackEgressPolicy::kRequireHomeEgress && !natStationPolicyOk)?"HOME: ADMISSION LOCKED":
      (MiniRackEgressPolicy::kRequireHomeEgress && natActive)?"HOME ROUTE: TEST REQUIRED":
      MiniRackEgressPolicy::kRequireHomeEgress?"HOME LINK: NOT READY":
      !natStationPolicyOk?"NAT: ADMISSION LOCKED":
      natActive?(vpnEnabled?"NAPT ACTIVE: ROUTE TBD":"DIRECT WAN ACTIVE"):
      uplinkHasIp()?"NAT STARTING":"WAITING UPLINK";
  eng(19,254,natLabel,MUTED,1);
  mr8Switch(172,232,natShareEnabled);
  backButton();
}

static void drawConfirmBroadcastOff(){
 header();
 if(arabicLanguage)bitmapText(120,57,AP_AR_CONFIRM,AP_AR_CONFIRM_W,AP_AR_CONFIRM_H,DANGER);
 else eng(53,59,"STOP BROADCAST?",DANGER,1);
 surface(10,99,220,96,PANEL_2,12,BORDER);
 eng(18,115,"All Wi-Fi users disconnect.",WHITE,1);
 eng(18,143,"Saved users will NOT be deleted.",MUTED,1);
 eng(18,164,"Pairing is independent.",MUTED,1);
 // This stops only the MiniRack Wi-Fi broadcast; it never deletes users.
 surface(10,216,220,42,PANEL,10,MUTED);
 if(arabicLanguage)bitmapText(120,226,V5_AR_STOP_BROADCAST,
     V5_AR_STOP_BROADCAST_W,V5_AR_STOP_BROADCAST_H,WHITE);
 else eng(75,233,"STOP BROADCAST",WHITE);
 textButton(10,270,220,43,Word::CANCEL,"CANCEL");
}
static void drawWifiListArea(){
  gfx->fillRect(0,80,240,203,BG); // Keep title and Back fixed while dragging.
  const int count=max(0,lastScanCount);
  wifiScroll=clampListScroll(wifiScroll,count,4);
  for(int row=0;row<4 && wifiScroll+row<count;row++){
    const int index=wifiScroll+row;
    String ss=WiFi.SSID(index);if(ss.length()>24)ss=ss.substring(0,24);
    const int y=86+row*42;
    surface(10,y,220,36,PANEL_2,8,BORDER);
    eng(18,y+12,ss.c_str(),WHITE,1);
    const int bars=WiFi.RSSI(index)>-55?3:(WiFi.RSSI(index)>-75?2:1);
    for(int b=0;b<bars;b++)gfx->fillRect(205+b*5,y+26-(b+1)*4,3,(b+1)*4,ACCENT);
  }
  if(count==0)eng(29,144,"NO NETWORKS FOUND",DANGER,1);
  char label[40];
  snprintf(label,sizeof(label),"SWIPE UP / DOWN   %d-%d / %d",
           count?wifiScroll+1:0,min(wifiScroll+4,count),count);
  eng(15,265,label,MUTED,1);
}
static void drawWifiList(){
  header();labelWord(120,54,Word::SCAN,"CHOOSE NETWORK",ACCENT);
  drawWifiListArea();
  backButton();
}
// QR Version 5-L, mask 0, byte mode. Self-contained for PlatformIO builds.
// One symbol fits a fresh single-use 128-bit authorization URL (~63 bytes).
static constexpr int MR7_QR_SIZE=37;
static uint8_t mr7QrModules[MR7_QR_SIZE*MR7_QR_SIZE];
static uint8_t mr7QrFunctional[MR7_QR_SIZE*MR7_QR_SIZE];
static void mr7QrFn(int x,int y,bool black){
  if(x<0||x>=MR7_QR_SIZE||y<0||y>=MR7_QR_SIZE)return;
  const int i=y*MR7_QR_SIZE+x;
  mr7QrFunctional[i]=1;mr7QrModules[i]=black?1:0;
}
static uint8_t mr7QrGfMul(uint8_t x,uint8_t y){
  int z=0;
  for(int i=7;i>=0;i--){
    z=(z<<1)^((z&0x80)?0x11D:0);
    if((y>>i)&1)z^=x;
  }
  return (uint8_t)z;
}
static void mr7QrFinder(int cx,int cy){
  for(int dy=-4;dy<=4;dy++)for(int dx=-4;dx<=4;dx++){
    int d=max(abs(dx),abs(dy));
    mr7QrFn(cx+dx,cy+dy,d!=2 && d!=4);
  }
}
static bool mr7EncodeQr(const String &payload){
  const size_t len=payload.length();
  if(len==0 || len>106)return false;
  memset(mr7QrModules,0,sizeof(mr7QrModules));
  memset(mr7QrFunctional,0,sizeof(mr7QrFunctional));
  uint8_t codewords[134]={};
  int bitIndex=0;
  // Bit writer for the first 108 data codewords.
  auto putBits=[&](unsigned value,int n){
    for(int bit=n-1;bit>=0;bit--){
      if(value&(1U<<bit)) codewords[bitIndex>>3]|=(uint8_t)(1U<<(7-(bitIndex&7)));
      bitIndex++;
    }
  };
  putBits(4,4);putBits((unsigned)len,8);
  for(size_t i=0;i<len;i++)putBits((uint8_t)payload[i],8);
  int left=108*8-bitIndex;
  if(left<0)return false;
  putBits(0,min(4,left));
  while(bitIndex%8)putBits(0,1);
  int dataBytes=bitIndex/8;
  bool padEven=true;
  while(dataBytes<108){codewords[dataBytes++]=padEven?0xEC:0x11;padEven=!padEven;}
  // QR Reed-Solomon: version 5 L uses one block, 108 data + 26 parity.
  uint8_t divisor[26]={};divisor[25]=1;
  uint8_t root=1;
  for(int i=0;i<26;i++){
    for(int j=0;j<26;j++){
      divisor[j]=mr7QrGfMul(divisor[j],root);
      if(j+1<26)divisor[j]^=divisor[j+1];
    }
    root=mr7QrGfMul(root,2);
  }
  uint8_t ecc[26]={};
  for(int i=0;i<108;i++){
    uint8_t factor=codewords[i]^ecc[0];
    memmove(ecc,ecc+1,25);ecc[25]=0;
    for(int j=0;j<26;j++)ecc[j]^=mr7QrGfMul(divisor[j],factor);
  }
  memcpy(codewords+108,ecc,26);
  mr7QrFinder(3,3);
  mr7QrFinder(MR7_QR_SIZE-4,3);
  mr7QrFinder(3,MR7_QR_SIZE-4);
  for(int i=8;i<MR7_QR_SIZE-8;i++){
    mr7QrFn(i,6,(i&1)==0);mr7QrFn(6,i,(i&1)==0);
  }
  for(int dy=-2;dy<=2;dy++)for(int dx=-2;dx<=2;dx++)
    mr7QrFn(30+dx,30+dy,max(abs(dx),abs(dy))!=1);
  // Reserve QR format bits, then draw L + mask 0 (format=0x77C4).
  for(int i=0;i<9;i++){mr7QrFn(8,i,false);mr7QrFn(i,8,false);}
  for(int i=0;i<8;i++)mr7QrFn(MR7_QR_SIZE-1-i,8,false);
  for(int i=8;i<15;i++)mr7QrFn(8,MR7_QR_SIZE-15+i,false);
  const int fmt=0x77C4;
  for(int i=0;i<6;i++)mr7QrFn(8,i,((fmt>>i)&1)!=0);
  mr7QrFn(8,7,((fmt>>6)&1)!=0);
  mr7QrFn(8,8,((fmt>>7)&1)!=0);
  mr7QrFn(7,8,((fmt>>8)&1)!=0);
  for(int i=9;i<15;i++)mr7QrFn(14-i,8,((fmt>>i)&1)!=0);
  for(int i=0;i<8;i++)mr7QrFn(MR7_QR_SIZE-1-i,8,((fmt>>i)&1)!=0);
  for(int i=8;i<15;i++)mr7QrFn(8,MR7_QR_SIZE-15+i,((fmt>>i)&1)!=0);
  mr7QrFn(8,MR7_QR_SIZE-8,true);
  mr7QrFn(8,6,true);mr7QrFn(6,8,true);
  int dataBit=0;
  for(int right=MR7_QR_SIZE-1;right>=1;right-=2){
    if(right==6)right=5;
    bool upward=((right+1)&2)==0;
    for(int vert=0;vert<MR7_QR_SIZE;vert++){
      int y=upward?MR7_QR_SIZE-1-vert:vert;
      for(int j=0;j<2;j++){
        int x=right-j;
        int idx=y*MR7_QR_SIZE+x;
        if(mr7QrFunctional[idx])continue;
        bool black=(dataBit<134*8)?((codewords[dataBit>>3]>>(7-(dataBit&7)))&1):false;
        if(((x+y)&1)==0)black=!black; // fixed mask 0
        mr7QrModules[idx]=black?1:0;
        dataBit++;
      }
    }
  }
  return dataBit==1079; // v5 has exactly 7 remainder bits
}
static bool mr7NewToken(bool forRelink){
  qrApproval.create(forRelink);
  qrApproval.ready=mr7EncodeQr(qrApproval.url);
  if (!qrApproval.ready) qrApproval.clear();
  return qrApproval.ready;
}
static void mr7CloseToken(){qrApproval.clear();}

static uint32_t mrSecurityIPTag(const IPAddress &ip) {
  return (static_cast<uint32_t>(ip[0]) << 24) |
         (static_cast<uint32_t>(ip[1]) << 16) |
         (static_cast<uint32_t>(ip[2]) << 8) |
          static_cast<uint32_t>(ip[3]);
}

static void mrSecurityTick(){
  securityMonitor.tick(millis());
  const MiniRackSecurity::Snapshot status=securityMonitor.snapshot();
  MiniRackCrypto::setSecurityState(status.alert,status.score);
  if (securityLastAlert != status.alert) {
    securityLastAlert=status.alert;
    if(view==View::SECURE)uiDirty=true;
    Serial.printf("MINIRACK SECURITY %s risk=%u attempts=%lu\n",
       status.alert?"ALERT":"NORMAL", (unsigned)status.score,
       (unsigned long)status.observedEvents);
  }
}

static void mrSecurityObserve(MiniRackSecurity::Event event,uint32_t sourceTag) {
  const bool before=securityMonitor.alert();
  securityMonitor.observe(event,sourceTag,millis());
  if(!before && securityMonitor.alert()) {
    // Protective reaction: revoke physical QR release windows. No WIFI/NAT
    // shutdown and no automatic MAC bans on a statistical risk score.
    if(portalForVpn || portalForOwnerRelink){
      portalForVpn=false;
      portalForOwnerRelink=false;
      portalOpenUntil=0;
      mr7CloseToken();
      if(view==View::OWNER_VPN_QR)go(View::SECURE);
    }
  }
  mrSecurityTick();
}
static bool mr7ValidToken(const String &incoming){return qrApproval.matches(incoming);}
static void mr7PaintQr(int x,int y){
  const int scale=4;
  gfx->fillRoundRect(x-16,y-16,MR7_QR_SIZE*scale+32,
                     MR7_QR_SIZE*scale+32,6,WHITE);
  for(int row=0;row<MR7_QR_SIZE;row++)for(int col=0;col<MR7_QR_SIZE;col++){
    if(mr7QrModules[row*MR7_QR_SIZE+col])
      gfx->fillRect(x+col*scale,y+row*scale,scale,scale,BLACK);
  }
}

static void qrBitmap(int x,int y,bool ownerVpn=false){
 // Static QR contains ONLY the local portal URL. PIN and secret profile are
 // never embedded in the image. HTTP endpoint rechecks owner and approval.
 const uint8_t scale=4, stride=(QR_WIDTH+7)/8;
 const int margin=ownerVpn?16:5; // Four-module quiet zone for the OWNER QR.
 gfx->fillRoundRect(x-margin,y-margin,QR_WIDTH*scale+margin*2,QR_WIDTH*scale+margin*2,7,WHITE);
 for(int yy=0;yy<QR_WIDTH;yy++)for(int xx=0;xx<QR_WIDTH;xx++){
   uint8_t mask=pgm_read_byte((ownerVpn?MR6_OWNER_QR:QR_MODULES)+yy*stride+xx/8);
   if(mask&(0x80>>(xx%8)))gfx->fillRect(x+xx*scale,y+yy*scale,scale,scale,BLACK);
 }
}
// Stage 6: OWNER-only menu item opens this full-screen, scannable QR page.
// Never show a credential QR: a scan leads to an owner/PIN-guarded page.
static void drawOwnerVpnQr(){
  header();
  if(relinkExtraDevice)eng(32,57,"DEVICE RE-LINK QR",WHITE,1);
  else mr8Title(MR8Label::CONFIG_TUNNEL,"OWNER VPN");
  if(ownerQrBlock!=0){
    surface(10,89,220,108,PANEL_2,12,BORDER);
    if(ownerQrBlock==1){
      eng(22,115,"DEFAULT WI-FI KEY UNSAFE",DANGER,1);
      eng(25,143,"CHANGE AP PASSWORD",WHITE,1);
      surface(10,213,220,48,PANEL_2,10,WHITE);
      eng(53,233,"GO TO SETTINGS",WHITE,1);
    }else if(ownerQrBlock==2){
      eng(31,119,"MINI RACK WI-FI OFF",DANGER,1);
      eng(26,148,"TURN HOTSPOT ON",WHITE,1);
    }else if(ownerQrBlock==3){
      eng(29,116,"WIREGUARD NOT READY",DANGER,1);
      eng(28,146,"CONNECT VPN FIRST",WHITE,1);
      surface(10,213,220,48,PANEL_2,10,WHITE);
      eng(64,233,"SECURE LINK",WHITE,1);
    }else{
      eng(50,127,"MAIN ONLY",DANGER,1);
    }
    backButton();return;
  }
  if(!windowOpen(portalOpenUntil) || !mr7QrReady){
    surface(10,95,220,112,PANEL_2,12,BORDER);
    eng(50,127,"QR EXPIRED",DANGER,1);
    eng(21,155,"OPEN VPN SETUP AGAIN",WHITE,1);
    backButton();return;
  }
  // Physical touchscreen tap generates a fresh short-lived one-use URL.
  // The QR never contains the VPN password or the profile itself.
  mr7PaintQr(46,89);
  eng(55,265,portalForOwnerRelink?(relinkExtraDevice?"RE-LINK DEVICE":"RE-LINK PHONE"):
      "SCAN TO INSTALL",WHITE,1);
  backButton();
}
static void drawWifiSetup(){
 header();labelWord(120,54,Word::QR,(portalForVpn||portalForOwnerRelink)?"OWNER VPN":"PHONE LOGIN",ACCENT);
 String ss=(portalForAPKey || portalForVpn || portalForOwnerRelink)?String(AP_NAME):chosenSSID;
 if(ss.length()>28)ss=ss.substring(0,28);
 eng(12,80,ss.c_str(),WHITE,1);
 qrBitmap(62,99);
 // iOS/Android may open the setup panel on AP association; QR fallback.
 if(portalForVpn || portalForOwnerRelink){
   eng(18,225,"CHECK PHONE SETUP WINDOW",WHITE,1);
   eng(18,236,"IF ABSENT, SCAN QR",MUTED,1);
 }else eng(23,229,"MiniRack-Secure Wi-Fi first",MUTED,1);
 // Shows whether the phone's browser request actually reached this ESP32.
 char req[28];snprintf(req,sizeof(req),"HTTP received: %lu",(unsigned long)portalHttpRequests);
 eng(20,273,req,MUTED,1);
 backButton();
}

static void drawStatusDetailsCard(){
  surface(10,79,220,143,PANEL_2,12,BORDER);
  NetworkHealth h=networkHealth();
  drawHealthTitle(120,89,h);
  drawHealthAdvice(120,109,h);
  char line[46];
  snprintf(line,sizeof(line),"WAN:%s  AP:%s  NAT:%s",
      uplinkHasIp()?"ON":"OFF",broadcastLive()?"ON":"OFF",natActive?"ON":"OFF");
  eng(18,134,line,WHITE,1);
  if(uplinkHasIp()){
    snprintf(line,sizeof(line),"SIGNAL: %d dBm",(int)WiFi.RSSI());
    eng(18,154,line,MUTED,1);
    eng(18,174,WiFi.localIP().toString().c_str(),MUTED,1);
  }else eng(18,155,"No source IP address",MUTED,1);
  snprintf(line,sizeof(line),"ONLINE: %u   SAVED: %u",
        (unsigned)getClients().num,(unsigned)pairedCount());
  eng(18,196,line,MUTED,1);
}
static void drawStatusDetails(){
  header();
  if(arabicLanguage)v6OtherArabic(120,52,0);
  else eng(69,55,"NETWORK STATUS",WHITE,1);
  drawStatusDetailsCard();
  textButton(10,233,220,43,Word::INTERNET,"OPEN INTERNET",false,true);
  backButton();
}
// Called at most once per second and paints only small changed regions.
static uint32_t networkFingerprint(){
  const uint8_t weak=weakUplink();
  uint32_t f=(uint32_t)networkHealth() |
             ((uint32_t)(uplinkHasIp()?1:0)<<5) |
             ((uint32_t)(broadcastLive()?1:0)<<6) |
             ((uint32_t)(natActive?1:0)<<7) |
             ((uint32_t)(weak?1:0)<<8) |
             ((uint32_t)(getClients().num&0xF)<<9) |
             ((uint32_t)(pairedCount()&0x1F)<<13) |
             ((uint32_t)(natShareEnabled?1:0)<<18) |
             ((uint32_t)(vpnEnabled?1:0)<<19);
  // The above changes only on meaningful events, not every small RSSI change.
  return f;
}
static void paintLiveChanges(){
  if(screenBlank || uiDirty)return;
  uint32_t now=millis();
  if((uint32_t)(now-lastLivePaint)<900)return;
  lastLivePaint=now;
  uint32_t f=networkFingerprint();
  bool changed=liveInfoDirty || f!=lastPaintFingerprint;
  if(changed){
    lastPaintFingerprint=f;
    refreshHeaderOnly();
    if(view==View::HOME)drawHomeStatusCard();
    if(view==View::STATUS)drawStatusDetailsCard();
    if(view==View::INTERNET)drawInternetReadout();
    liveInfoDirty=false;
    lastReadoutPaint=now;
  }
  // Useful measured signal can drift while connected. Update only the 91px
  // Internet detail card every 12 seconds; never flash the whole screen.
  if(view==View::INTERNET && (uint32_t)(now-lastReadoutPaint)>=12000){
    drawInternetReadout();lastReadoutPaint=now;
  }
  if(view==View::SECURE && changed)uiDirty=true;
  if(view==View::STATUS && (uint32_t)(now-lastReadoutPaint)>=12000){
    drawStatusDetailsCard();lastReadoutPaint=now;
  }
  // Pairing timer counts down without clearing all the touch buttons.
  if(view==View::USERS && windowOpen(pairOpenUntil) &&
     (uint32_t)(now-lastReadoutPaint)>=10000){
    gfx->fillRect(14,105,205,16,PANEL_2);
    char countdown[32];
    snprintf(countdown,sizeof(countdown),"PAIR OPEN: %lus",
       (unsigned long)((pairOpenUntil-millis()+999)/1000));
    eng(17,107,countdown,WHITE,1);
    lastReadoutPaint=now;
  }
}

static const int V81_VPN_ON_AR_W = 111;
static const int V81_VPN_ON_AR_H = 21;
static const uint8_t V81_VPN_ON_AR[] PROGMEM = {
  0x00,0x00,0x00,0x00,0x0C,0x70,0x00,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x0C,0x70,0x00,0x06,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x06,0x00,0x0C,0x70,0x00,0x06,
  0x00,0x01,0x80,0x03,0x00,0x6C,0x00,0x00,0x06,0x00,0x0C,0x70,0x00,0x06,0x00,0x01,0x80,0x00,
  0x00,0x6C,0x00,0x6C,0x00,0x00,0x0C,0x70,0x00,0x06,0x00,0x00,0x00,0x0D,0x80,0x00,0x00,0x6C,
  0x00,0x07,0x0C,0x70,0x00,0x06,0x00,0x00,0x00,0x0D,0x80,0x00,0x00,0x00,0x0F,0x03,0x0E,0x70,
  0x00,0x06,0x00,0x03,0xC0,0x00,0x00,0x18,0x00,0x00,0x1F,0x80,0x0E,0x70,0x00,0x06,0x00,0x0F,
  0xE0,0x00,0x18,0x38,0x00,0x3C,0x1D,0xC0,0x0E,0x70,0x00,0x06,0x00,0x1E,0xF0,0x00,0x1C,0x18,
  0x00,0x7E,0x39,0xC3,0x0E,0x70,0x00,0x06,0x07,0x1C,0x70,0xC3,0x1C,0x18,0x00,0xEE,0x39,0xC3,
  0x0E,0x70,0x00,0x06,0x06,0x0E,0x61,0xC7,0x1C,0x1C,0x00,0xC6,0x1D,0xC7,0x0E,0x30,0x18,0x07,
  0x06,0x07,0xE1,0xC7,0x1C,0x1C,0x70,0xE7,0x1F,0x9F,0xBC,0x30,0x18,0x07,0x9F,0x8F,0xE3,0xEF,
  0xBE,0xB8,0x60,0xFF,0xFF,0xFF,0xFC,0x30,0x18,0x07,0xFF,0xFF,0xFF,0xFF,0xFF,0xF8,0x60,0x7F,
  0xFD,0xFC,0xF8,0x30,0x38,0x07,0xF9,0xFC,0x7F,0x7D,0xF3,0xF0,0x60,0x0E,0x00,0x00,0x00,0x00,
  0x18,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x0E,0x00,0x00,0x00,0x00,0x1E,0x1E,0x00,0x00,
  0x00,0x00,0x00,0x00,0x78,0x3C,0x00,0x00,0x00,0x00,0x0F,0xFC,0x1B,0x00,0x00,0x00,0x00,0x00,
  0x3F,0xF8,0x00,0x00,0x00,0x00,0x07,0xF8,0x1B,0x80,0x00,0x00,0x00,0x00,0x1F,0xE0,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00
};

static const int V81_VPN_OFF_AR_W = 100;
static const int V81_VPN_OFF_AR_H = 23;
static const uint8_t V81_VPN_OFF_AR[] PROGMEM = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0C,
  0x70,0x00,0x00,0xE0,0xE0,0x00,0x01,0xC0,0x00,0x00,0x00,0x00,0x0C,0x70,0x00,0x00,0xE0,0xE0,
  0x00,0x01,0xC0,0x00,0x00,0x06,0x00,0x0C,0x70,0x00,0x00,0x00,0xE1,0xD8,0x01,0xC0,0x00,0x00,
  0x06,0x00,0x0C,0x70,0x00,0x00,0x00,0xE0,0xD8,0x01,0xC0,0x00,0x6C,0x00,0x00,0x0C,0x70,0x00,
  0x01,0xF0,0xE0,0x00,0x01,0xC0,0x00,0x6C,0x00,0x07,0x0C,0x70,0x00,0x01,0xF8,0xE0,0x00,0x01,
  0xC0,0x00,0x00,0x0F,0x03,0x0E,0x70,0x00,0x03,0xB8,0xE0,0xF0,0x31,0xC0,0x00,0x00,0x1F,0x80,
  0x0E,0x70,0x10,0x03,0x18,0xE1,0xF8,0x71,0xC0,0x00,0x3C,0x1D,0xC0,0x0E,0x70,0x18,0x03,0x18,
  0x61,0xDC,0x31,0xC0,0x00,0x7E,0x39,0xC3,0x0E,0x70,0x18,0x03,0xF8,0x63,0x9C,0x31,0xC0,0x00,
  0xEE,0x39,0xC3,0x0E,0x70,0x18,0x01,0xF8,0x63,0x9C,0x39,0xC0,0x00,0xC6,0x1D,0xC7,0x0E,0x30,
  0x1C,0x00,0x18,0x61,0xDC,0x38,0xC0,0x70,0xE7,0x1F,0x9F,0xBC,0x30,0x1F,0x00,0x78,0x75,0xF9,
  0x70,0xC0,0x60,0xFF,0xFF,0xFF,0xFC,0x30,0x0F,0xFF,0xF0,0x7F,0xFF,0xF0,0xC0,0x60,0x7F,0xFD,
  0xFC,0xF8,0x30,0x03,0xFF,0xE0,0x3F,0xDF,0xE0,0xC0,0x60,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x60,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x78,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xB0,0xC0,0x3F,0xF8,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x01,0xB9,0x80,0x1F,0xE0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x01,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xE0,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80
};

// Reflect whether the tunnel has been initialized, not a verified handshake.
// The library does not expose the peer's latest-handshake state here.
static bool vpnUplinkReady() {
  return WiFi.status()==WL_CONNECTED && WiFi.localIP()!=IPAddress(0,0,0,0);
}
static uint8_t vpnUiState() {
  if(!vpnEnabled)return 0;                       // Manual OFF
  if(!vpnUplinkReady())return 1;                // Waiting for Wi-Fi/Internet
  if(vpnTunnel.is_initialized())return 4;       // Interface initialized (not handshake proof)
  if(time(nullptr)<=1700000000)return 2;       // Clock not synchronized
  return vpnAttempted?3:2;                      // Starting or retrying
}
static void setVpnEnabled(bool enabled) {
  if(vpnEnabled==enabled)return;
  vpnEnabled=enabled;
  if(!prefsNet.putBool("vpnEnabled",enabled))
    Serial.println("MINIRACK VPN: unable to persist preference");
  if(!vpnEnabled) {
    if(MiniRackEgressPolicy::kRequireHomeEgress)miniNatStop();
    if(vpnTunnel.is_initialized())vpnTunnel.end(); // Actually tear down WG
    vpnAttempted=false;
    vpnLastAttemptMs=0;
    Serial.println("MINIRACK VPN: OFF (manual)");
  } else {
    // Start on next vpnService() tick after Wi-Fi/NTP is ready.
    vpnAttempted=false;
    vpnLastAttemptMs=0;
    Serial.println("MINIRACK VPN: ON requested");
  }
  vpnLastUiState=255;
  uiDirty=true;
}
static void vpnService() {
  // Keep the network stack lightweight: no network scans or NVS reads here.
  if((uint32_t)(millis()-vpnLastPollMs)<500)return;
  vpnLastPollMs=millis();
  const bool connected=vpnUplinkReady();
  // SSID may be identical at different hotels. BSSID + address distinguish roam.
  const String networkId=connected ?
      (WiFi.BSSIDstr()+"|"+WiFi.localIP().toString()+"|"+WiFi.gatewayIP().toString())
      : String("");
  if(networkId!=vpnBoundNetwork) {
    // Tear down old tunnel whenever the underlying network changes.
    if(MiniRackEgressPolicy::kRequireHomeEgress)miniNatStop();
    if(vpnTunnel.is_initialized())vpnTunnel.end();
    vpnBoundNetwork=networkId;
    vpnNtpStarted=false;
    vpnAttempted=false;
    vpnLastAttemptMs=0;
    Serial.println(connected?"MINIRACK VPN: uplink changed; reinitializing":
                             "MINIRACK VPN: waiting for uplink");
  }
  if(!vpnEnabled) {
    if(MiniRackEgressPolicy::kRequireHomeEgress)miniNatStop();
    if(vpnTunnel.is_initialized())vpnTunnel.end();
  } else if(connected) {
    if(!vpnNtpStarted) {
      configTime(0,0,"pool.ntp.org","time.google.com");
      vpnNtpStarted=true;
    }
    if(!vpnTunnel.is_initialized() && time(nullptr)>1700000000 &&
       (!vpnAttempted || (uint32_t)(millis()-vpnLastAttemptMs)>=VPN_RETRY_MS)) {
      vpnAttempted=true;
      vpnLastAttemptMs=millis();
      IPAddress vpnIP;
      if(vpnIP.fromString(WG_LOCAL_IP)) {
       static bool mdnsReady = false;

if (!mdnsReady) {
    mdnsReady = MDNS.begin("minirack-esp32");
}

String endpointHost;
// Optional: define WG_SERVER_HOST in your PRIVATE include/wg_secrets.h.
// Example: #define WG_SERVER_HOST "your-host.example".
// Merely defining a hostname does NOT make carrier/router NAT or IPv6 work;
// external reachability must be verified separately.
#ifdef WG_SERVER_HOST
  endpointHost = String(WG_SERVER_HOST);
  endpointHost.trim();
#endif
#ifdef MINIRACK_HOME_TUNNEL_EXPERIMENT
  if (WiFi.SSID() == "MiniRack-Pi-Link") {
    IPAddress piGateway = WiFi.gatewayIP();
    if (piGateway != IPAddress(0,0,0,0))
      endpointHost = piGateway.toString();
  }
#endif
if(endpointHost.isEmpty()) {
  // Legacy home-LAN discovery only. mDNS does not work from hotels abroad.
  if(mdnsReady) {
    IPAddress piIP = MDNS.queryHost("salem-pi", 2000);
    if(piIP != IPAddress(0, 0, 0, 0)) endpointHost = piIP.toString();
  }
}
if(!endpointHost.isEmpty()) {
    Serial.printf("MINIRACK WG ENDPOINT: %s\n", endpointHost.c_str());
    // Pi (10.10.0.1) must remain reachable via wg0 even when AP NAT
    // selects Wi-Fi STA as the default route. The legacy overload used
    // a /32 netmask, leaving 10.10.0.1 outside the WG on-link network.
    const bool ok = vpnTunnel.begin(vpnIP,
        IPAddress(255, 255, 255, 0), IPAddress(0, 0, 0, 0),
        WG_PRIVATE_KEY, endpointHost.c_str(),
        WG_SERVER_PUBLIC_KEY, WG_SERVER_PORT);
    Serial.printf("MINIRACK WG INIT: %s\n",ok ? "OK" : "FAILED");
} else {
    Serial.println("MINIRACK WG: NO ENDPOINT; local mDNS unavailable");
}
      } else {
        Serial.println("MINIRACK WG INIT: INVALID LOCAL IP");
      }
    }
  }
  const uint8_t state=vpnUiState();
  if(state!=vpnLastUiState) {
    vpnLastUiState=state;
    if(view==View::SECURE)uiDirty=true;
  }
}

static void drawSecure(){
  header();
  eng(102,54,"VPN",WHITE,2);
  // Security mode is based on observed failed authorizations, NOT a guess.
  eng(15,150,securityMonitor.alert()?"SECURITY: ALERT - QR PAUSED":"SECURITY: NORMAL",
      securityMonitor.alert()?WHITE:MUTED,1);
  // Persistent WireGuard ON/OFF, separate from the phone's native IKEv2.
  surface(10,82,220,60,PANEL_2,12,BORDER);
  mr8Caption(MR8Label::VPN_TUNNEL,94,101,"WIREGUARD",WHITE);
  const uint8_t st=vpnUiState();
  const char *status=st==0?"OFF":st==1?"NO UPLINK":st==2?"WAITING TIME":st==3?"CONNECTING":"WG INIT (UNVERIFIED)";
  eng(18,123,status,st==4?WHITE:MUTED,1);
  mr8Switch(173,99,vpnEnabled);
  // One and only phone configuration entry, restricted by MAIN identity.
  surface(10,158,220,75,PANEL_2,12,WHITE);
  mr8Caption(MR8Label::CONFIG_TUNNEL,120,180,"CONFIGURE TUNNEL",WHITE);
  mr8Caption(MR8Label::SETUP_READY,120,208,"SETUP / RESTORE OWNER",MUTED);
  if(primaryMac.isEmpty()){
    mr8Caption(MR8Label::NO_OWNER,120,251,"NO OWNER REGISTERED",MUTED);
  }else if((int32_t)(ownerSetupMessageUntil-millis())>0){
    eng(20,250,ownerSetupMessage,MUTED,1);
  }else if(!ownerProfileIssued){
    mr8Caption(MR8Label::FIRST_PAIR,120,251,"OWNER NEEDS PROFILE",MUTED);
  }else{
    eng(32,247,"PROFILE SENT - NOT INSTALL PROOF",MUTED,1);
  }
  eng(17,269,"GUEST: PUBLIC INTERNET ONLY",MUTED,1);
  backButton();
}

static void drawCloseDeviceLabel(int cy,uint16_t color=WHITE){
  if(arabicLanguage)bitmapText(120,cy,V81_AR_CLOSE_DEVICE,V81_CLOSE_W,V81_CLOSE_H,color);
  else eng(120-(int)strlen("SHUT DOWN DEVICE")*3,cy+6,"SHUT DOWN DEVICE",color,1);
}
static void drawSettings(){
 header();labelWord(120,55,Word::SETTINGS,"SETTINGS",ACCENT);
 labelWord(120,85,Word::LANG,"LANGUAGE",MUTED);
 surface(55,110,130,38,PANEL_2,10,WHITE);
 arabicOld(97,121,AR_AR_LETTER,arabicLanguage?ACCENT:MUTED);
 eng(119,118,"| E",arabicLanguage?MUTED:ACCENT,2);
 textButton(10,155,220,39,Word::DEVICE,"DEVICE INFO");
 textButton(10,199,220,39,Word::AP_KEY,"CHANGE AP KEY");
 // Independent shutdown menu: never nested in DEVICE INFO.
 surface(10,243,220,37,PANEL,9,BORDER);
 drawCloseDeviceLabel(250);
 backButton();
}
static void drawDevice(){
 header();labelWord(120,55,Word::DEVICE,"DEVICE INFO",ACCENT);
 surface(10,92,220,153,PANEL_2,12,BORDER);
 char line[46];
 snprintf(line,sizeof(line),"Heap: %u KB",(unsigned)ESP.getFreeHeap()/1024);eng(20,109,line,WHITE);
 snprintf(line,sizeof(line),"CPU: %u MHz",(unsigned)ESP.getCpuFreqMHz());eng(20,131,line,WHITE);
 eng(20,153,"Crypto telemetry: REAL",ACCENT);
 eng(20,175,MiniRackCrypto::hasAcknowledgement()?"Pi UART: ACK received":"Pi UART: no ACK yet",MUTED);
 // This page contains diagnostics only: no shutdown link.
 surface(10,199,220,60,PANEL,9,BORDER);
 eng(20,213,"4G/5G + SATELLITE",WHITE,1);
 eng(20,235,"TRANSPORT PROFILES",MUTED,1);
 backButton();
}
static void drawTransportProfiles(){
  header();
  if(arabicLanguage)
    bitmapText(120,46,MR_EXPO_TITLE,MR_EXPO_TITLE_W,MR_EXPO_TITLE_H,WHITE);
  else eng(40,57,"LINK PRIORITY",WHITE,2);

  const auto &cfg = MiniRackTransport::settings();

  // 4G/5G: a green switch means the saved PROFILE is enabled, not connected.
  surface(10,82,220,57,PANEL_2,11,BORDER);
  if(arabicLanguage)
    bitmapText(90,90,MR_EXPO_CELL,MR_EXPO_CELL_W,MR_EXPO_CELL_H,WHITE);
  else eng(18,94,"4G/5G FALLBACK",WHITE,1);
  eng(18,116,MiniRackTransport::ratName(cfg.rat),MUTED,1);
  if(arabicLanguage) {
    if(cfg.policy.cellularProfile)
      bitmapText(110,112,MR_EXPO_CELL_OFFLINE,MR_EXPO_CELL_OFFLINE_W,MR_EXPO_CELL_OFFLINE_H,MUTED);
    else
      bitmapText(110,112,MR_EXPO_CELL_DISABLED,MR_EXPO_CELL_DISABLED_W,MR_EXPO_CELL_DISABLED_H,MUTED);
  } else eng(78,116,cfg.policy.cellularProfile?"NO MODEM":"PROFILE OFF",MUTED,1);
  eng(18,130,cfg.apn.isEmpty()?"APN: NOT SET":"APN: SET",MUTED,1);
  mr8Switch(176,100,cfg.policy.cellularProfile);

  // Satellite: no terminal hardware, regardless of configuration switch.
  surface(10,146,220,53,PANEL_2,11,BORDER);
  if(arabicLanguage)
    bitmapText(92,151,MR_EXPO_SAT,MR_EXPO_SAT_W,MR_EXPO_SAT_H,WHITE);
  else eng(18,158,"SATELLITE BACKUP",WHITE,1);
  if(arabicLanguage) {
    if(cfg.policy.satelliteProfile)
      bitmapText(88,177,MR_EXPO_SAT_OFFLINE,MR_EXPO_SAT_OFFLINE_W,MR_EXPO_SAT_OFFLINE_H,MUTED);
    else
      bitmapText(88,177,MR_EXPO_SAT_DISABLED,MR_EXPO_SAT_DISABLED_W,MR_EXPO_SAT_DISABLED_H,MUTED);
  } else eng(18,180,cfg.policy.satelliteProfile?"NO TERMINAL":"PROFILE OFF",MUTED,1);
  mr8Switch(176,163,cfg.policy.satelliteProfile);

  // Auto-failover is a policy request only; no radio driver or route switch.
  surface(10,206,220,53,PANEL_2,11,BORDER);
  if(arabicLanguage)
    bitmapText(93,210,MR_EXPO_AUTO,MR_EXPO_AUTO_W,MR_EXPO_AUTO_H,WHITE);
  else eng(18,219,"AUTO FAILOVER POLICY",WHITE,1);
  if(arabicLanguage) {
    if(cfg.policy.failoverRequested)
      bitmapText(88,237,MR_EXPO_POLICY_ONLY,MR_EXPO_POLICY_ONLY_W,MR_EXPO_POLICY_ONLY_H,MUTED);
    else
      bitmapText(88,237,MR_EXPO_POLICY_DISABLED,MR_EXPO_POLICY_DISABLED_W,MR_EXPO_POLICY_DISABLED_H,MUTED);
  } else eng(18,241,cfg.policy.failoverRequested?"POLICY ONLY; NO MODEM":"POLICY DISABLED",MUTED,1);
  mr8Switch(176,224,cfg.policy.failoverRequested);

  if(arabicLanguage)
    bitmapText(120,265,MR_EXPO_PRIORITY,MR_EXPO_PRIORITY_W,MR_EXPO_PRIORITY_H,MUTED);
  else eng(13,268,"HOME > 4G/5G > SAT",MUTED,1);
  backButton();
}
static void drawPower(){
 header();drawCloseDeviceLabel(52,ACCENT);
 surface(10,76,220,71,PANEL_2,12,BORDER);
 eng(17,91,"SCREEN OFF: touch to wake",WHITE);
 eng(17,108,"Wi-Fi and NAT stay active",MUTED);
 eng(17,126,"Deep sleep needs RESET",MUTED);
 surface(10,158,220,43,PANEL,9,BORDER);
 if(arabicLanguage) bitmapText(120,167,V5_AR_SCREEN_SLEEP,V5_AR_SCREEN_SLEEP_W,V5_AR_SCREEN_SLEEP_H,WHITE);
 else eng(81,174,"SCREEN OFF",WHITE);
 surface(10,210,220,42,PANEL,9,BORDER);
 if(arabicLanguage) bitmapText(120,220,V5_AR_DEEP_SLEEP,V5_AR_DEEP_SLEEP_W,V5_AR_DEEP_SLEEP_H,WHITE);
 else eng(76,226,"DEEP SLEEP",WHITE);
 textButton(10,263,220,40,Word::CANCEL,"CANCEL");
}
static void drawDeepSleepConfirm(){
 header();drawCloseDeviceLabel(52,WHITE);
 surface(10,78,220,111,PANEL_2,12,BORDER);
 eng(20,94,"DEEP SLEEP STOPS NETWORK",WHITE);
 eng(20,116,"Touch will NOT wake ESP32",WHITE);
 eng(20,139,"Press RESET or reconnect",MUTED);
 eng(20,156,"power to start again",MUTED);
 textButton(10,212,220,46,Word::SHUTDOWN,"CONFIRM SLEEP",true);
 textButton(10,265,220,42,Word::CANCEL,"CANCEL");
}
static void drawUI(){
 if(screenBlank){blankUi();return;}
 switch(view){
 case View::HOME:drawHome();break;
 case View::USERS:drawUsers();break;
 case View::PAIR_CHOICE:drawPairChoice();break;
 case View::MY_DEVICES:case View::GUESTS:drawDeviceGroup();break;
 case View::PEER_DETAILS:drawPeerDetails();break;
 case View::CONFIRM_REMOVE:drawConfirmRemove();break;
 case View::CONFIRM_UNSET_PRIMARY:drawConfirmUnsetPrimary();break;
 case View::CONFIRM_SET_PRIMARY:drawConfirmSetPrimary();break;
 case View::INTERNET:drawInternet();break;
 case View::CONFIRM_AP_OFF:drawConfirmBroadcastOff();break;
 case View::WIFI_LIST:drawWifiList();break;
 case View::WIFI_SETUP:drawWifiSetup();break;
 case View::OWNER_VPN_QR:drawOwnerVpnQr();break;
 case View::SECURE:drawSecure();break;
 case View::SETTINGS:drawSettings();break;
 case View::DEVICE_INFO:drawDevice();break;
 case View::TRANSPORTS:drawTransportProfiles();break;
 case View::CONFIRM_RESTART:drawDeepSleepConfirm();break;
 case View::POWER:drawPower();break;
 case View::STATUS:drawStatusDetails();break;
 }
 uiDirty=false;
 lastPaintFingerprint=networkFingerprint();
 liveInfoDirty=false;
 lastLivePaint=millis();
 lastReadoutPaint=millis();
}
static bool touchRead(int &x,int &y) {
  if(!touchscreenReady) return false;
  Wire.beginTransmission(TOUCH_ADDR);
  Wire.write((uint8_t)0x02);
  if(Wire.endTransmission(false)!=0) return false;
  if(Wire.requestFrom((uint8_t)TOUCH_ADDR,(uint8_t)5)!=5) return false;
  uint8_t touches=Wire.read()&0x0f;
  uint8_t xh=Wire.read(), xl=Wire.read(), yh=Wire.read(), yl=Wire.read();
  if(touches==0 || touches>2) return false;
  x=((xh&0x0F)<<8)|xl;
  y=((yh&0x0F)<<8)|yl;
  return x>=0 && x<240 && y>=0 && y<320;
}
static void touchStart() {
  pinMode(18,OUTPUT);
  digitalWrite(18,LOW); delay(12);
  digitalWrite(18,HIGH); delay(120);
  Wire.begin(16,15);
  Wire.setClock(100000);
  Wire.beginTransmission(TOUCH_ADDR);
  touchscreenReady=(Wire.endTransmission()==0);
  Serial.printf("FT6336G: %s\n",touchscreenReady?"READY":"NOT DETECTED");
}


static void openPortal(bool apKeyOnly=false){
 portalForOwnerRelink=false;
 portalForVpn=false;
 mr7CloseToken();
 portalForAPKey=apKeyOnly;
 portalOpenUntil=millis()+300000;
 go(View::WIFI_SETUP);
}
// A visible OWNER control opens one physically approved enrollment / recovery.
// If the owner MAC changed (iOS Private Wi-Fi Address etc.), ask the owner to
// RE-LINK explicitly rather than treating any associated client as OWNER.
static void openOwnerSetup(bool forExtraDevice=false){
  if(securityMonitor.sensitiveOperationsLocked()){
    ownerStatus("SECURITY ALERT: QR PAUSED");
    go(View::SECURE);return;
  }
  ownerQrBlock=0;
  cancelPendingPair();pairOpenUntil=0;
  portalForOwnerRelink=false;portalForVpn=false;portalForAPKey=false;
  relinkExtraDevice=forExtraDevice;
  portalOpenUntil=0;mr7CloseToken();
  if(!(isPrimary(selectedPeer) || (forExtraDevice && peerRegistry.isOwnerDevice(selectedPeer))))ownerQrBlock=4;
  else if(apPassword=="MiniRack2026!")ownerQrBlock=1; // known shared demo password
  else if(!apBroadcastEnabled)ownerQrBlock=2;
  else if(forExtraDevice || !isPeerOnline(selectedPeer)){
    portalForOwnerRelink=true;
    miniNatStop(); // before allowing any unidentified station onto the AP
  }
  else if(!vpnEnabled || !vpnTunnel.is_initialized())ownerQrBlock=3;
  else portalForVpn=true;
  if(ownerQrBlock==0){
    if(mr7NewToken(portalForOwnerRelink)){
      portalOpenUntil=millis()+120000;
      Serial.println(portalForOwnerRelink?"AUTHORIZED DEVICE RE-LINK QR READY (120s)":
                                       "OWNER VPN QR READY (120s)");
    }else{
      portalForVpn=false;portalForOwnerRelink=false;
      ownerQrBlock=4;
      Serial.println("OWNER QR ENCODING FAILED");
    }
  }
  go(View::OWNER_VPN_QR);
}

static void chooseLanguage(int x) {
 if(x>=72 && x<116) arabicLanguage=true;
 else if(x>=116 && x<170)arabicLanguage=false;
 prefsNet.putBool("ar",arabicLanguage);uiDirty=true;
}
static void onTap(int x,int y){
 if(view==View::CONFIRM_AP_OFF){
   if(y>=215 && y<=260){setBroadcastEnabled(false);go(View::INTERNET);}
   else if(y>=265)go(View::INTERNET);
   return;
 }
 if(view==View::CONFIRM_RESTART) {
   if(y>=212 && y<=260){
     // Deep sleep stops Wi-Fi and all tasks.  Wakes only via RESET or power
     // re-connection on this board (no capacitive touch wake is configured).
     Serial.println("MINI RACK DEEP SLEEP: use RESET or power cycle to wake");
     gfx->fillScreen(BLACK);
     digitalWrite(TFT_BL,LOW);
     delay(70);
     esp_deep_sleep_start();
   }
   if(y>=263)go(View::POWER);
   return;
 }
 if(view==View::POWER) {
   if(y>=158 && y<=205){sleepDisplay();return;}
   if(y>=209 && y<=255){go(View::CONFIRM_RESTART);return;}
   if(y>=263)go(returnView);
   return;
 }
 if(view==View::HOME){
   if(y>=78 && y<151){go(View::STATUS);return;}
   if(y>=159 && y<220){if(x<120)go(View::INTERNET);else go(View::SECURE);return;}
   if(y>=229 && y<290){if(x<120){userScroll=0;go(View::USERS);}else go(View::SETTINGS);return;}
   return;
 }
 if(view==View::STATUS){
   if(y>=230 && y<281)go(View::INTERNET);
   else if(y>=285)go(View::HOME);
   return;
 }
 if(view==View::CONFIRM_SET_PRIMARY){
   if(y>=212 && y<262){
     selectMainOnScreen(selectedPeer);
     go(View::PEER_DETAILS);
   }else if(y>=263)go(View::PEER_DETAILS);
   return;
 }
 if(view==View::CONFIRM_UNSET_PRIMARY){
   if(y>=212 && y<262){clearPrimary();go(View::PEER_DETAILS);}
   else if(y>=263){go(View::PEER_DETAILS);}
   return;
 }
 if(view==View::CONFIRM_REMOVE){
   if(y>=212 && y<262){
     String m=getPeer(selectedPeer);
     uint8_t mac[6];
     if(isPrimary(selectedPeer))clearPrimary();
     // Removing a station revokes its live firewall role before disconnect.
     if(peerRegistry.remove(selectedPeer)){
       // Revoke before the deauth: the phone can rejoin automatically with
       // the unchanged shared Wi-Fi password. Wi-Fi access is NOT approval.
       deletedStationAwaitingApproval=m;
       mrSyncGuestFirewall();
       natStationPolicyOk=false;
       miniNatStop();
       if(parseMac(m,mac))deauthByMac(mac); // once, no deauth loop
       Serial.printf("MINIRACK ACCESS REVOKED: %s - APPROVAL REQUIRED\n",m.c_str());
     }
     pairOpenUntil=0;
     cancelPendingPair();
     userScroll=0;
     go(userReturnView==View::GUESTS||userReturnView==View::MY_DEVICES?userReturnView:View::USERS);
   }else if(y>=265)go(View::PEER_DETAILS);
   return;
 }
 if(view==View::OWNER_VPN_QR){
   if(y>=281){
     // Physically leaving cancels the one-time approval session.
     const View target=relinkExtraDevice?View::PEER_DETAILS:View::SECURE;
     portalForVpn=false;portalForOwnerRelink=false;relinkExtraDevice=false;
     portalOpenUntil=0;mr7CloseToken();
     go(target);return;
   }
   if(ownerQrBlock==1 && y>=206 && y<=267){go(View::SETTINGS);return;}
   if(ownerQrBlock==3 && y>=206 && y<=267){go(View::SECURE);return;}
   return;
 }
 if(view==View::PAIR_CHOICE){
   if(y<178 || (y>=225 && y<232) || (y>=278 && y<283))return;
   if(selectedPeer>=MAX_PEERS || peerMacs[selectedPeer].isEmpty() ||
      !peerRegistry.isTransient(selectedPeer) || !isPeerOnline(selectedPeer)){
     ownerStatus("DEVICE DISCONNECTED");go(pairingReturnView);return;
   }
   if(y>=283){
     const String denied=getPeer(selectedPeer);
     uint8_t mac[6];
     // Refuse the CURRENT Wi-Fi session only. The phone may keep the shared
     // password, but it receives no approval and no forwarded Internet.
     // On its next Wi-Fi association it appears as NEW DEVICE again.
     peerRegistry.remove(selectedPeer);
     mrSyncGuestFirewall();
     cancelPendingPair();
     go(pairingReturnView);
     if(parseMac(denied,mac))deauthByMac(mac); // once, never a loop
     Serial.printf("MINIRACK SESSION REFUSED (RETRY ALLOWED): %s\n",denied.c_str());
     return;
   }
   if(y<225){
     if(promoteToMyDevices(selectedPeer)){
       userScroll=0;userReturnView=View::MY_DEVICES;
       go(View::MY_DEVICES); // It must ACTUALLY move into the owned list.
     }
   }else if(y>=232){
     if(setPeerAllowed(selectedPeer,true)){
       cancelPendingPair();userScroll=0;userReturnView=View::GUESTS;
       go(View::GUESTS);
     }
   }
   return;
 }
 if(view==View::PEER_DETAILS){
   if(y>=286){go(userReturnView);return;}
   if(y>=276 && y<286){
     if(x<80 && peerDetailScroll>0)peerDetailScroll--;
     else if(x>168 && peerDetailScroll<detailActionCount()-MR5_DETAIL_VISIBLE)peerDetailScroll++;
     uiDirty=true;return;
   }
   if(y>=183 && y<275){
     const int visualRow=(y-183)/49;
     if(visualRow>=MR5_DETAIL_VISIBLE || (y-183)%49>=43)return;
     const uint8_t action=peerDetailScroll+(uint8_t)visualRow;
     const bool owner=isPrimary(selectedPeer);
     const bool mine=peerRegistry.isOwnerDevice(selectedPeer);
     if(owner){
       if(action==0){go(View::CONFIRM_UNSET_PRIMARY);return;}
       if(action==1){go(View::CONFIRM_REMOVE);return;}
     }else if(mine){
       if(action==0){go(View::CONFIRM_SET_PRIMARY);return;}
       if(action==1){
         if(peerRegistry.setOwnerDevice(selectedPeer,false)){
           uint8_t mac[6];
           if(parseMac(getPeer(selectedPeer),mac))deauthByMac(mac);
           mrSyncGuestFirewall();
           miniNatStop();
           ownerStatus("MY DEVICE ACCESS REMOVED");
         }
         uiDirty=true;return;
       }
       if(action==2){openOwnerSetup(true);return;}
       if(action==3){go(View::CONFIRM_REMOVE);return;}
     }else{
       // Guest management is only: (1) ADD TO MY DEVICES, (2) DELETE.
       if(action==0){
         if(promoteToMyDevices(selectedPeer)){
           userScroll=0;userReturnView=View::MY_DEVICES;
           go(View::MY_DEVICES);
         }
         return;
       }
       if(action==1){go(View::CONFIRM_REMOVE);return;}
     }
   }
   return;
 }
 if(y>=283){go(view==View::TRANSPORTS?View::DEVICE_INFO:view==View::DEVICE_INFO?View::SETTINGS:
    (view==View::MY_DEVICES||view==View::GUESTS)?View::USERS:View::HOME);return;}
 if(view==View::USERS){
   if(y>=120 && y<165){userScroll=0;go(View::MY_DEVICES);return;}
   if(y>=173 && y<218){userScroll=0;go(View::GUESTS);return;}
   return;
 }
 if(view==View::MY_DEVICES || view==View::GUESTS){
   if(y>=123 && y<267){
     const int row=(y-123)/36;
     if((y-123)%36>=32)return;
     const int slot=groupSlotAt(view,userScroll+row);
     if(slot>=0){
       selectedPeer=(uint8_t)slot;
       userReturnView=view;
       go(View::PEER_DETAILS);
     }
   }
   return;
 }
 if(view==View::INTERNET){
   if(y>=82 && y<137){
     if(apBroadcastEnabled)go(View::CONFIRM_AP_OFF);
     else if(!setBroadcastEnabled(true))Serial.println("MINIRACK AP: enable failed");
   }else if(y>=144 && y<210){
     go(View::WIFI_LIST);drawUI();
     lastScanCount=WiFi.scanNetworks(false,false);
     if(lastScanCount<0)lastScanCount=0;
     wifiScroll=0;uiDirty=true;
   }else if(y>=216 && y<273){
     natShareEnabled=!natShareEnabled;
     if(!prefsNet.putBool("natshare",natShareEnabled))Serial.println("NAT preference not saved");
     if(!natShareEnabled)miniNatStop();
     else natLastAttempt=0;
     uiDirty=true;
   }
   return;
 }
 if(view==View::WIFI_LIST){
   if(y>=86 && y<254){
     const int idx=wifiScroll+(y-86)/42;
     if(idx>=0 && idx<lastScanCount && (y-86)%42<37){
       chosenSSID=WiFi.SSID(idx);openPortal(false);
     }
   }
   return;
 }
 if(view==View::SECURE){
   if(y>=82 && y<143){setVpnEnabled(!vpnEnabled);return;}
   if(y>=158 && y<235){
     // Locate the persistent MAIN device; do not trust a browser to self-assign.
     for(uint8_t i=0;i<MAX_PEERS;i++)if(isPrimary(i)){
       selectedPeer=i;openOwnerSetup();return;
     }
     ownerStatus("PAIR MAIN FIRST");uiDirty=true;
     return;
   }
   return;
 }
  if(view==View::DEVICE_INFO){
   if(y>=199 && y<260){go(View::TRANSPORTS);return;}
 }
 if(view==View::TRANSPORTS){
   if(y>=82 && y<140){
     if(x>=159)MiniRackTransport::toggleCellular(prefsNet);
     else MiniRackTransport::nextRat(prefsNet);
     uiDirty=true;return;
   }
   if(y>=146 && y<200){MiniRackTransport::toggleSatellite(prefsNet);uiDirty=true;return;}
   if(y>=206 && y<260){MiniRackTransport::toggleFailover(prefsNet);uiDirty=true;return;}
   return;
 }if(view==View::SETTINGS){
   if(y>=110 && y<=150){chooseLanguage(x);return;}
   if(y>=154 && y<=196){go(View::DEVICE_INFO);return;}
   if(y>=198 && y<=240){chosenSSID="";openPortal(true);return;}
   if(y>=242 && y<=281){returnView=View::SETTINGS;go(View::POWER);return;}
 }
 // DEVICE INFO is informational. Navigation back is handled above at y>=283.
}

static void onPowerTap(bool longPress){
  if(screenBlank){wakeDisplay();return;}
  if(!longPress){
    // Display-only lock: touches cannot navigate while LCD is off.
    // This is NOT a credential-protected security lock.
    sleepDisplay();
    return;
  }
  // Long press opens the existing power menu; destructive deep sleep still
  // requires explicit confirmation and will stop all networking.
  if(view==View::POWER || view==View::CONFIRM_RESTART){go(returnView);return;}
  returnView=view;
  go(View::POWER);
}
static void touchService(){
 if((uint32_t)(millis()-lastTouchPoll)<35)return;
 lastTouchPoll=millis();
 int x=0,y=0;bool down=touchRead(x,y);
 if(down && !wasPressed){
   touchDownAt=millis();touchStartX=x;touchStartY=y;
   touchLastX=x;touchLastY=y;
   touchScrollAnchorY=y;touchScrolled=false;
 }
 if(down){
   touchLastX=x;touchLastY=y;
   // Update scrolling WHILE the finger moves, at one-row increments.
   // List indices (not LCD touch calibration) change, so Stage 8 touch
   // coordinates and full-size hit areas remain unchanged.
   const bool groupList=view==View::MY_DEVICES || view==View::GUESTS;
   const int rowPx=view==View::WIFI_LIST?42:groupList?36:0;
   const bool inList=(view==View::WIFI_LIST && touchStartY>=80 && touchStartY<283) ||
      (groupList && touchStartY>=120 && touchStartY<268);
   if(!screenBlank && inList && rowPx && abs(touchScrollAnchorY-y)>=rowPx){
     const int delta=(touchScrollAnchorY-y)/rowPx;
     if(view==View::WIFI_LIST)
       wifiScroll=clampListScroll(wifiScroll+delta,lastScanCount,4);
     else userScroll=clampListScroll(userScroll+delta,groupDeviceCount(view),PEERS_PER_PAGE);
     touchScrollAnchorY-=delta*rowPx;
     touchScrolled=true;
     if(view==View::WIFI_LIST)drawWifiListArea();
     else drawDeviceGroupArea();
   }
 }
 if(!down && wasPressed){
   uint32_t held=(uint32_t)(millis()-touchDownAt);
   lastUserTouchMs=millis();
   if(screenBlank)wakeDisplay();
   else {
     bool pwr=touchStartX>=8 && touchStartX<=51 && touchStartY<=40;
     int travel=touchStartY-touchLastY;
     const bool swipe=abs(travel)>=24;
     if(touchScrolled){
       // The list already tracked the finger. Do not activate a touched row.
     }else if(swipe && view==View::WIFI_LIST && touchStartY>=80 && touchStartY<283){
       // Short flick below one row still advances one item on release.
       wifiScroll=clampListScroll(wifiScroll+(travel>0?1:-1),lastScanCount,4);
       uiDirty=true;
     }else if(swipe && (view==View::MY_DEVICES||view==View::GUESTS) && touchStartY>=120 && touchStartY<268){
       userScroll=clampListScroll(userScroll+(travel>0?1:-1),groupDeviceCount(view),PEERS_PER_PAGE);
       uiDirty=true;
     }else if(swipe && view==View::PEER_DETAILS && touchStartY>=159 && touchStartY<284){
       // Swipes never accidentally trigger destructive device actions.
       if(travel>0 && peerDetailScroll<detailActionCount()-MR5_DETAIL_VISIBLE)++peerDetailScroll;
       else if(travel<0 && peerDetailScroll>0)--peerDetailScroll;
       uiDirty=true;
     }else if(pwr)onPowerTap(held>=PWR_HOLD_MS);
     else if(held<1800)onTap(touchStartX,touchStartY);
   }
 }
 wasPressed=down;
}
static String escapeHtml(const String& s) {
  String result;
  for(size_t i=0;i<s.length();i++) {
    char c=s[i];
    if(c=='&') result+="&amp;";
    else if(c=='<') result+="&lt;";
    else if(c=='>') result+="&gt;";
    else if(c=='\"') result+="&quot;";
    else if(c=='\'') result+="&#39;";
    else result+=c;
  }
  return result;
}

static String htmlLayout(const String &body) {
  String s=F("<!doctype html><html lang='ar' dir='rtl'><head><meta charset='utf-8'>"
      "<meta name='viewport' content='width=device-width, initial-scale=1'>"
      "<meta name='referrer' content='no-referrer'>"
      "<style>body{font:17px system-ui;background:#050505;color:#f4f4f4;"
      "max-width:520px;margin:20px auto;padding:12px}h1{color:#fff}"
      "article{border:1px solid #595959;background:#1b1b1b;border-radius:18px;padding:16px}"
      "input,button{display:block;width:100%;box-sizing:border-box;border-radius:12px;"
      "padding:12px;margin:14px 0;font:inherit}button{background:#fff;color:#000;border:0}"
      "input{color:#121212;background:white;border:1px solid #ddd}p{line-height:1.65}</style>"
      "</head><body><h1>MINI RACK</h1>");
  s+=body;
  s+="</body></html>";
  return s;
}

static bool requirePortalAuth() {
  // MiniRack WIFI SETUP NO PIN - physical screen and OWNER only.
  // Never permit Wi-Fi/AP changes by a GUEST after MAIN enrollment.
  if (!primaryMac.isEmpty() && !isOwnerBrowser(portal.client().remoteIP())) {
    mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                      mrSecurityIPTag(portal.client().remoteIP()));
    portal.send(403,"text/plain; charset=utf-8","OWNER Wi-Fi connection required");
    return false;
  }
  // The selected network/AP key must be approved from the actual touchscreen.
  if(view != View::WIFI_SETUP || portalForVpn || portalForOwnerRelink ||
     !windowOpen(portalOpenUntil)) {
    portal.send(403,"text/html; charset=utf-8",
      htmlLayout("<p>افتح إعداد الاتصال من شاشة ESP32 أولًا.</p>"));
    return false;
  }
  return true;
}


static void noteHttpRequest(const char *route){
  ++portalHttpRequests;
  Serial.printf("MiniRack HTTP: %s from %s\n",route,portal.client().remoteIP().toString().c_str());
  if(view==View::WIFI_SETUP)uiDirty=true;
}

static void sendPortalHome(){
 noteHttpRequest("/");
 // A GUEST may see captive-portal probes but never the owner's configuration.
 // First-time setup still works when MAIN has not yet been assigned.
 if(!primaryMac.isEmpty() && !isOwnerBrowser(portal.client().remoteIP())){
   portal.sendHeader("Cache-Control","no-store");
   portal.send(403,"text/plain; charset=utf-8","OWNER Wi-Fi connection required");
   return;
 }
 if(!windowOpen(portalOpenUntil)){
   portal.send(403,"text/html; charset=utf-8",htmlLayout("<p>افتح إعداد الاتصال من شاشة MINI RACK أولًا.</p>"));return;
 }
 String page="<article>";
 if(portalForVpn){
   if(!isOwnerBrowser(portal.client().remoteIP())){
     mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                       mrSecurityIPTag(portal.client().remoteIP()));
     portal.send(403,"text/html; charset=utf-8",htmlLayout("<p>OWNER Wi-Fi only.</p>"));return;
   }
   page+="<h2>Mini Rack VPN - OWNER</h2>";
   page+="<p>تكوين النفق جاهز بعد موافقتك من شاشة Mini Rack.</p>";
   page+="<a style='display:block;background:white;color:black;padding:16px;"
         "border-radius:12px;text-align:center;text-decoration:none' href='"+mr7OwnerUrl+"'>استلام التكوين</a>";
   page+="<p>بعد التنزيل، وافق على التثبيت من إعدادات iPhone.</p>";
   page+="</article>";
   portal.sendHeader("Cache-Control","no-store");
   portal.sendHeader("X-Content-Type-Options","nosniff");
   portal.send(200,"text/html; charset=utf-8",htmlLayout(page));return;
 }
 if(!portalForAPKey){
   if(chosenSSID.isEmpty()){
     portal.send(409,"text/html; charset=utf-8",htmlLayout("<p>اختر الشبكة من شاشة الجهاز أولًا.</p>"));return;
   }
   page+="<h2>تسجيل الاتصال بالشبكة المحددة</h2>";
   page+="<p>الشبكة التي اخترتها على شاشة Mini Rack:</p>";
   page+="<p style='padding:12px;background:#152a3c;border-radius:8px'><b>"+escapeHtml(chosenSSID)+"</b></p>";
   page+="<p>إذا كانت الشبكة محمية بكلمة مرور، أدخلها هنا. للشبكات المفتوحة اترك الحقل فارغًا.</p>";
   page+="<form method='post' action='/wifi/connect'>";
   page+="<label>كلمة مرور Wi-Fi</label><input type='password' name='password' maxlength='63' autocomplete='off'>";
   page+="<button type='submit'>اتصال بالشبكة المحددة</button></form>";
   page+="<p style='opacity:.75'>هذه الصفحة لبيانات Wi-Fi فقط. شبكات الفندق التي تطلب صفحة دخول خارجية تحتاج دعمًا إضافيًا.</p>";
 }else{
   page+="<h2>تغيير كلمة مرور شبكة MiniRack-Secure</h2>";
   page+="<p>هذه العملية ستفصل الأجهزة المتصلة. ستحتاج إلى الاتصال من جديد بالكلمة الجديدة.</p>";
   page+="<form method='post' action='/ap/change'>";
   page+="<input type='password' name='pass' minlength='12' maxlength='63' placeholder='كلمة المرور الجديدة' required>";
   page+="<button type='submit'>تغيير كلمة مرور شبكة الجهاز</button></form>";
 }
 page+="</article>";
 portal.sendHeader("Cache-Control","no-store");
 portal.sendHeader("X-Content-Type-Options","nosniff");
 portal.send(200,"text/html; charset=utf-8",htmlLayout(page));
}
// =====================================================================
// REAL IPv4 NAPT: Wi-Fi uplink -> MiniRack-Secure clients.
// Does not hide identity / does not block access to home LAN.
// =====================================================================
// NAT implementation moved to minirack_nat.cpp. AP management below stays
// local to this file because it also owns UI and captive-portal state.
static void miniNatStop() {
  const bool wasActive=natActive;
  natController.stop();
  if (wasActive!=natActive) liveInfoDirty=true;
}

static bool mrAdvertiseCaptivePortal(){
  esp_netif_t *netif=esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if(!netif)return false;
  // ESP-IDF needs the DHCP server temporarily stopped for Option 114.
  // The URI has static storage because DHCP retains its pointer.
  esp_err_t stop=esp_netif_dhcps_stop(netif);
  if(stop!=ESP_OK)return false;
  esp_err_t set=esp_netif_dhcps_option(netif,ESP_NETIF_OP_SET,
      ESP_NETIF_CAPTIVEPORTAL_URI,CAPTIVE_API_URL,strlen(CAPTIVE_API_URL));
  esp_err_t start=esp_netif_dhcps_start(netif);
  Serial.printf("MINIRACK CAPTIVE DHCP: option=%d restart=%d\n",(int)set,(int)start);
  return set==ESP_OK && start==ESP_OK;
}
static bool startMiniRackAP(){
  // Keep the uplink STA alive; no DNS hijack and no loss of guest internet.
  if(!WiFi.AP.begin())return false;
  if(!WiFi.AP.config(AP_IP,AP_IP,AP_MASK,AP_LEASE_START,AP_DNS))return false;
  if(!WiFi.AP.create(AP_NAME,apPassword.c_str(),1,0,MAX_ONLINE))return false;
  // Optional discoverability: AP stays usable even if this fails.
  if(!mrAdvertiseCaptivePortal())Serial.println("MINIRACK: captive DHCP unsupported; portal remains available");
  return true;
}
static bool setBroadcastEnabled(bool enabled){
  if(enabled==apBroadcastEnabled)return true;
  if(enabled){
    if(!startMiniRackAP()){
      apStartFailed=true;
      Serial.println("MINIRACK: AP start failed");
      WiFi.AP.end();
      return false;
    }
    apBroadcastEnabled=true;
    apStartFailed=false;
    natLastAttempt=0; // NAT is restored on the next loop if STA has internet.
    Serial.println("MINIRACK BROADCAST ON (pairing state unchanged)");
  }else{
    // This action is explicitly confirmed on the ESP touchscreen.
    miniNatStop();
    if(!WiFi.AP.end()){
      Serial.println("MINIRACK: AP stop failed");
      return false;
    }
    MiniRackGuestFirewall::resetAfterApStop();
    apBroadcastEnabled=false;
    apStartFailed=false;
    pairOpenUntil=0;
    cancelPendingPair();
    Serial.println("MINIRACK BROADCAST OFF (saved peers unchanged)");
  }
  if(!prefsNet.putBool("apEnabled",apBroadcastEnabled))
    Serial.println("MINIRACK: warning, failed to save broadcast setting");
  uiDirty=true;
  return true;
}

// Every connected station must be approved (MAIN/MY DEVICES/GUEST), and
// the packet firewall must be live when any GUEST is present. Unlike the
// previous revision, global NAT is no longer incorrectly used as guest ACL.
static bool mrNatStationsAdmitted(){
  // Never forward ANY station without an active per-station packet filter.
  // In particular, otherwise an unapproved device might ride a shared NAPT
  // session started for another approved station.
  if(!MiniRackGuestFirewall::ready())return false;
  // A touchscreen-approved, temporary GUEST may use internet even when MAIN
  // is not yet assigned or is offline. The per-station AP ingress firewall
  // MUST be active for GUEST traffic, and unknown stations remain denied.
  // Requiring primaryMac here previously kept NAT OFF for approved guests.
  wifi_sta_list_t connected={};
  if(esp_wifi_ap_get_sta_list(&connected)!=ESP_OK)return false;
  if(connected.num<0 || connected.num>MAX_ONLINE)return false;
  MiniRackRoutePolicy::Role roles[MAX_ONLINE]={};
  for(int i=0;i<connected.num;i++){
    const int slot=findPair(connected.sta[i].mac);
    if(deletedStationAwaitingApproval.equalsIgnoreCase(
         macToStr(connected.sta[i].mac)) &&
       (slot<0 || (!isMyDevice((uint8_t)slot) && !peerAllowed[slot])))
      return false; // fail closed during the deleted phone's Wi-Fi rejoin
    roles[i]=(slot>=0 && isMyDevice((uint8_t)slot))
      ? MiniRackRoutePolicy::Role::OWNER
      : (slot>=0 && peerAllowed[slot])
        ? MiniRackRoutePolicy::Role::GUEST
        : MiniRackRoutePolicy::Role::UNAPPROVED;
  }
  return MiniRackRoutePolicy::allowNat(roles,(size_t)connected.num,true,
                                         MiniRackGuestFirewall::ready());
}

static void miniNatService() {
  if(apBroadcastEnabled)MiniRackGuestFirewall::beginInstall();
  // Avoid repeated Wi-Fi driver enumeration on every UI / NAT loop; direct
  // role changes call mrSyncGuestFirewall() immediately, and unrecognised
  // frames remain DENIED at the packet hook regardless of this refresh.
  static uint32_t lastStationRefresh=0;
  static bool firstStationRefresh=true;
  const uint32_t now=millis();
  const bool refresh=firstStationRefresh || (uint32_t)(now-lastStationRefresh)>=250;
  if(refresh) {
    firstStationRefresh=false;
    lastStationRefresh=now;
    mrSyncGuestFirewall();
  }
  const bool wasActive=natActive;
  const bool previousPolicy=natStationPolicyOk;
  if(refresh || !MiniRackGuestFirewall::ready())
    natStationPolicyOk=mrNatStationsAdmitted();
  if(previousPolicy!=natStationPolicyOk){
    uiDirty=true;
    Serial.printf("MINIRACK NAT ADMISSION: %s (filter=%s drops=%lu)\n",
      natStationPolicyOk?"APPROVED":"BLOCKED",
      MiniRackGuestFirewall::ready()?"ON":"OFF",
      (unsigned long)MiniRackGuestFirewall::dropped());
  }
  const bool recoveringOwner=portalForOwnerRelink && windowOpen(portalOpenUntil);
  // A new/unapproved phone has to be approved on the MiniRack screen;
  // while the role-choice prompt is open, NAPT stays OFF. This also covers
  // an automatically reconnected deleted phone, without a deauth loop.
  const bool admissionOpen=pendingPairActive() || windowOpen(pairOpenUntil);
  const bool homeMode=MiniRackEgressPolicy::kRequireHomeEgress;
  const bool wgLinkUp=homeMode && vpnEnabled && vpnTunnel.is_initialized() &&
                      MiniRackHomeRoute::linkReady();
  const bool mayForward=homeMode
      ? MiniRackEgressPolicy::allowHomeNat(natShareEnabled,natStationPolicyOk,
          !admissionOpen,!recoveringOwner,vpnEnabled,wgLinkUp)
      : MiniRackEgressPolicy::allowDirectNat(natShareEnabled,natStationPolicyOk,
          !admissionOpen,!recoveringOwner);
  // Enrolled V2 devices require a fresh signed HOME-001 authorization.
  // Unprovisioned V1 builds preserve the original behavior.
  static uint32_t natDiagAt = 0;
  if (homeMode && millis() - natDiagAt >= 5000) {
    natDiagAt = millis();
    Serial.printf(
      "MR NAT GATE: share=%d ap=%d wan=%d ip=%d approved=%d pending=%d relink=%d vpn=%d tunnel=%d route=%d auth=%d active=%d\n",
      natShareEnabled, apBroadcastEnabled,
      WiFi.status()==WL_CONNECTED, WiFi.STA.hasIP(),
      natStationPolicyOk, admissionOpen, recoveringOwner,
      vpnEnabled, vpnTunnel.is_initialized(), wgLinkUp,
      MiniRackV2::internetPermit(), natActive);
  }
  natController.poll(mayForward && MiniRackV2::internetPermit(),
                     apBroadcastEnabled,AP_IP,NAT_RETRY_MS,homeMode);
  if (wasActive!=natActive) liveInfoDirty=true;
}

static void startUplink() {
  if(savedSSID.isEmpty()) return;
  staReconnectAttempts=0;
  WiFi.begin(savedSSID.c_str(),savedPassword.c_str());
  lastStaRetry=millis();
}


// Read-only authenticated bridge endpoint, accessible ONLY through the Pi's
// existing WireGuard tunnel. The Pi polls this after the owner is selected
// on the physical touchscreen. Never expose a credential/profile from ESP.
static bool mrBridgeHmacHex(const String &msg,String &out){
  const char *hex=MINIRACK_BRIDGE_KEY_HEX;
  if(strlen(hex)!=64)return false;
  uint8_t key[32];
  for(int i=0;i<32;i++){
    char a=hex[i*2],b=hex[i*2+1];
    auto nybble=[](char c)->int{
      if(c>='0'&&c<='9')return c-'0';
      if(c>='a'&&c<='f')return c-'a'+10;
      return -1;
    };
    int high=nybble(a),low=nybble(b);
    if(high<0||low<0)return false;
    key[i]=(uint8_t)((high<<4)|low);
  }
  uint8_t tag[32]={};
  const mbedtls_md_info_t* info=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(!info || mbedtls_md_hmac(info,key,sizeof(key),
      (const uint8_t*)msg.c_str(),msg.length(),tag)!=0){
    memset(key,0,sizeof(key));return false;
  }
  memset(key,0,sizeof(key));
  static const char digits[]="0123456789abcdef";
  out.reserve(64);out="";
  for(uint8_t b:tag){out+=(char)digits[b>>4];out+=(char)digits[b&15];}
  return true;
}
static bool mrBridgeSignatureEqual(const String &received,const String &expected){
  if(received.length()!=64 || expected.length()!=64)return false;
  uint8_t difference=0;
  for(size_t i=0;i<64;i++) difference|=(uint8_t)(received[i]^expected[i]);
  return difference==0;
}
static void mrRegisterOwnerEndpoint(){
  // Reject AP clients, LAN clients and all non-Pi VPN peers before HMAC work.
  portal.on("/mr-internal/owner-state",HTTP_GET,[](){
    if(portal.client().remoteIP()!=IPAddress(10,10,0,1)){
      mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                        mrSecurityIPTag(portal.client().remoteIP()));
      portal.send(403,"text/plain","Forbidden");return;
    }
    String nonce=portal.header("X-MR-Nonce");
    String received=portal.header("X-MR-Auth");
    if(nonce.length()!=32){
      mrSecurityObserve(MiniRackSecurity::Event::InvalidPiBridgeAuth,
                        mrSecurityIPTag(portal.client().remoteIP()));
      portal.send(400,"text/plain","Bad request");return;}
    for(size_t i=0;i<nonce.length();i++){
      const char c=nonce[i];
      if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))){
        mrSecurityObserve(MiniRackSecurity::Event::InvalidPiBridgeAuth,
                          mrSecurityIPTag(portal.client().remoteIP()));
        portal.send(400,"text/plain","Bad request");return;
      }
    }
    String expected;
    if(!mrBridgeHmacHex(String("MR-BRIDGE-V1|REQ|")+nonce,expected) ||
       !mrBridgeSignatureEqual(received,expected)){
      mrSecurityObserve(MiniRackSecurity::Event::InvalidPiBridgeAuth,
                        mrSecurityIPTag(portal.client().remoteIP()));
      portal.send(403,"text/plain","Forbidden");return;
    }
    const String payload=String("V1|")+(primaryMac.isEmpty() || ownerBridgeId.isEmpty()?
                          String("NONE"):ownerBridgeId);
    String signedResponse;
    if(!mrBridgeHmacHex(String("MR-BRIDGE-V1|RESP|")+nonce+"|"+payload,signedResponse)){
      portal.send(503,"text/plain","Bridge disabled");return;
    }
    portal.sendHeader("Cache-Control","no-store");
    portal.sendHeader("X-MR-Signature",signedResponse);
    portal.send(200,"text/plain; charset=us-ascii",payload);
  });
}

// Requests are signed end-to-end between ESP and Pi over the WireGuard tunnel.
// The downloaded mobileconfig is held only temporarily in ESP RAM, never on flash.
static bool mrFetchOwnerProfile(String &profile){
  // Temporary diagnostics: do not log credentials, MACs, nonces or profiles.
  if(!vpnEnabled || !vpnTunnel.is_initialized() || primaryMac.isEmpty() ||
     ownerBridgeId.isEmpty()){
    Serial.printf("MRPROFILE: precheck failed vpn=%d wg_init=%d owner=%d bridge_id=%d\n",
                  vpnEnabled?1:0, vpnTunnel.is_initialized()?1:0,
                  primaryMac.isEmpty()?0:1, ownerBridgeId.isEmpty()?0:1);
    return false;
  }
  char buf[33];
  for(int i=0;i<4;i++)snprintf(buf+i*8,9,"%08lx",(unsigned long)esp_random());
  const String nonce(buf);
  String reqSig;
  if(!mrBridgeHmacHex(String("MR-PROFILE-V1|REQ|")+ownerBridgeId+"|"+nonce,reqSig)){
    Serial.println("MRPROFILE: request signature creation failed");
    return false;
  }
  HTTPClient upstream;
  const char *headers[]={"X-MR-Signature"};
  upstream.collectHeaders(headers,1);
  upstream.setTimeout(7000);
  if(!upstream.begin("http://10.10.0.1:8765/v1/owner.mobileconfig")){
    Serial.println("MRPROFILE: HTTP client begin failed");
    return false;
  }
  upstream.addHeader("X-MR-Owner",ownerBridgeId);
  upstream.addHeader("X-MR-Nonce",nonce);
  upstream.addHeader("X-MR-Auth",reqSig);
  const int code=upstream.GET();
  const int len=upstream.getSize();
  Serial.printf("MRPROFILE: upstream_http=%d reported_length=%d\n",code,len);
  if(code!=200 || len<100 || len>16384){
    Serial.println("MRPROFILE: upstream rejected or invalid length");
    upstream.end();return false;
  }
  const String proof=upstream.header("X-MR-Signature");
  profile=upstream.getString();
  upstream.end();
  if((int)profile.length()!=len || profile.indexOf("<plist")<0){
    Serial.println("MRPROFILE: profile body malformed or length mismatch");
    profile="";return false;
  }
  uint8_t digest[32];
  const mbedtls_md_info_t *info=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(!info || mbedtls_md(info,(const uint8_t *)profile.c_str(),profile.length(),digest)!=0){
    Serial.println("MRPROFILE: digest calculation failed");
    profile="";return false;
  }
  char sha[65];static const char hexdigits[]="0123456789abcdef";
  for(size_t i=0;i<32;i++){sha[i*2]=hexdigits[digest[i]>>4];sha[i*2+1]=hexdigits[digest[i]&15];}
  sha[64]=0;
  String expected;
  if(!mrBridgeHmacHex(String("MR-PROFILE-V1|RESP|")+nonce+"|"+sha,expected) ||
     !mrBridgeSignatureEqual(proof,expected)){
    Serial.println("MRPROFILE: server response signature mismatch");
    profile="";return false;
  }
  Serial.println("MRPROFILE: profile fetched and verified");
  return true;
}
// RFC 8908 captive-portal API referenced from DHCP Option 114.
// Only advertise a captive login while the owner still needs provisioning or
// a physical owner re-link/profile approval window is active.
static bool mrNeedsOnboarding(const IPAddress &remote){
  if(portalForOwnerRelink && windowOpen(portalOpenUntil))return true;
  if(portalForVpn && windowOpen(portalOpenUntil))return isOwnerBrowser(remote);
  if(primaryMac.isEmpty())return true; // first OWNER enrollment on TFT
  return !ownerProfileIssued && isOwnerBrowser(remote);
}
static void mrSendOnboardingPage(){
  noteHttpRequest("/onboard");
  const IPAddress remote=portal.client().remoteIP();
  if(portalForOwnerRelink && windowOpen(portalOpenUntil)){
    String currentMac;
    if(!mrClientMacForIP(remote,currentMac)){
      portal.send(403,"text/html; charset=utf-8",htmlLayout("<p>Connect to MiniRack Wi-Fi first.</p>"));return;
    }
    String page=relinkExtraDevice?"<article><h2>إعادة ربط جهاز مملوك</h2>":
        "<article><h2>ربط هاتف المالك</h2>";
    page+=relinkExtraDevice?"<p>ربط عنوان MAC الجديد بالجهاز الموافق عليه من شاشة Mini Rack.</p>":
        "<p>تحديث عنوان MAIN بموافقة فعلية من شاشة Mini Rack مع حفظ حساب VPN.</p>";
    page+="<a style='display:block;background:white;color:black;padding:16px;"
          "border-radius:12px;text-align:center;text-decoration:none' href='"+mr7OwnerUrl+"'>ربط الهاتف</a></article>";
    portal.sendHeader("Cache-Control","no-store");
    portal.send(200,"text/html; charset=utf-8",htmlLayout(page));return;
  }
  if(portalForVpn && windowOpen(portalOpenUntil)){
    if(isOwnerBrowser(remote)){sendPortalHome();return;}
    portal.send(403,"text/html; charset=utf-8",htmlLayout("<p>This phone is not the registered OWNER. Use RE-LINK PHONE on Mini Rack.</p>"));return;
  }
  String page="<article><h2>إعداد Mini Rack</h2>";
  if(primaryMac.isEmpty()){
    page+="<p>أهلًا بك. افتح المستخدمون على شاشة الجهاز، وافق على الهاتف وعيّنه MAIN.</p>";
  }else if(!ownerProfileIssued && isOwnerBrowser(remote)){
    page+="<p>هاتف المالك معروف. من شاشة تفاصيل MAIN اضغط VPN CONFIG / RESTORE "
          "لإصدار موافقة تسليم تكوين VPN.</p>";
  }else{
    page+="<p>هذا الهاتف ليس في جلسة تسليم تكوين المالك. استعمل الجهاز بشكل طبيعي.</p>";
  }
  page+="<p>لا يمكن تثبيت VPN بصمت؛ سوف يطلب الهاتف موافقتك.</p></article>";
  portal.sendHeader("Cache-Control","no-store");
  portal.send(200,"text/html; charset=utf-8",htmlLayout(page));
}
static void webInit(){
  const char* mrBridgeHeaders[]={"X-MR-Nonce","X-MR-Auth"};
  portal.collectHeaders(mrBridgeHeaders,2);
  mrRegisterOwnerEndpoint();
  portal.on("/captive-api",HTTP_GET,[](){
    noteHttpRequest("/captive-api");
    const bool captive=mrNeedsOnboarding(portal.client().remoteIP());
    String data=String("{\"captive\":")+(captive?"true":"false");
    if(captive){data+=String(",\"user-portal-url\":\"")+CAPTIVE_PAGE_URL+"\"";}
    data+="}";
    portal.sendHeader("Cache-Control","no-store");
    portal.send(200,"application/captive+json",data);
  });
  portal.on("/onboard",HTTP_GET,mrSendOnboardingPage);
  portal.on("/vpn/setup",HTTP_GET,[](){
    noteHttpRequest("/vpn/setup");
    if(view==View::OWNER_VPN_QR && portalForVpn && windowOpen(portalOpenUntil) &&
       isOwnerBrowser(portal.client().remoteIP())){sendPortalHome();return;}
    mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                      mrSecurityIPTag(portal.client().remoteIP()));
    portal.sendHeader("Cache-Control","no-store");
    portal.send(403,"text/html; charset=utf-8",htmlLayout(
      "<article><p>يتطلب إعداد VPN موافقة MAIN من شاشة Mini Rack واتصال هاتف المالك بالشبكة.</p></article>"));
  });
  // Stage 7: one physical tap + a one-use 128-bit QR link. No PIN form.
  portal.on("/vpn/now",HTTP_GET,[](){
    noteHttpRequest("/vpn/now");
    if(securityMonitor.sensitiveOperationsLocked() ||
       !portalForVpn || portalForOwnerRelink || ownerQrBlock!=0 ||
       view!=View::OWNER_VPN_QR || !windowOpen(portalOpenUntil) ||
       !mr7ValidToken(portal.arg("t")) ||
       !isOwnerBrowser(portal.client().remoteIP()) ||
       apPassword=="MiniRack2026!" ||
       !vpnEnabled || !vpnTunnel.is_initialized()){
      mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                        mrSecurityIPTag(portal.client().remoteIP()));
      portal.sendHeader("Cache-Control","no-store");
      portal.send(403,"text/html; charset=utf-8",htmlLayout(
        "<article><p>QR منتهي أو الهاتف ليس MAIN المتصل. افتح تكوين نفق من الجهاز من جديد.</p></article>"));
      return;
    }
    String profile;
    if(!mrFetchOwnerProfile(profile)){
      portal.sendHeader("Cache-Control","no-store");
      portal.send(503,"text/html; charset=utf-8",htmlLayout(
        "<article><p>خادم VPN غير جاهز. اترك شاشة QR مفتوحة وحاول المسح مجددًا.</p></article>"));
      return;
    }
    // Token is consumed BEFORE transmitting any owner credentials.
    portalForVpn=false;portalOpenUntil=0;mr7CloseToken();
    ownerProfileIssued=true;
    prefsNet.putBool("ownerprof",true); // delivered, not proven installed
    go(View::SECURE);
    portal.sendHeader("Cache-Control","no-store, no-cache, must-revalidate");
    portal.sendHeader("Pragma","no-cache");
    portal.sendHeader("X-Content-Type-Options","nosniff");
    portal.sendHeader("Content-Disposition","attachment; filename=MiniRack-Owner.mobileconfig");
    portal.send(200,"application/x-apple-aspen-config",profile);
    profile="";
  });
  portal.on("/owner/relink-now",HTTP_GET,[](){
    noteHttpRequest("/owner/relink-now");
    // One physical QR can update exactly ONE previously approved device.
    // The browser must be connected to this AP, and the token is single-use.
    const bool ownedSelection=selectedPeer<MAX_PEERS &&
        (isPrimary(selectedPeer) ||
         (relinkExtraDevice && peerRegistry.isOwnerDevice(selectedPeer)));
    if(securityMonitor.sensitiveOperationsLocked() || !ownedSelection ||
       !portalForOwnerRelink || portalForVpn || ownerQrBlock!=0 ||
       view!=View::OWNER_VPN_QR || !windowOpen(portalOpenUntil) ||
       !mr7ValidToken(portal.arg("t")) || apPassword=="MiniRack2026!"){
      mrSecurityObserve(MiniRackSecurity::Event::RejectedProtectedProfile,
                        mrSecurityIPTag(portal.client().remoteIP()));
      portal.send(403,"text/plain","Fresh physical re-link QR required");return;
    }
    String newMacText;
    uint8_t newMac[6]={};
    if(!mrClientMacForIP(portal.client().remoteIP(),newMacText) ||
       !parseMac(newMacText,newMac)){
      portal.send(403,"text/plain","Connect the new MAC to Mini Rack Wi-Fi");return;
    }
    const uint8_t slot=selectedPeer;
    const String oldMac=peerMacs[slot];
    if(!peerRegistry.rebindAuthorizedDevice(slot,newMac)){
      portal.send(409,"text/plain","Address already approved or storage failed");return;
    }
    // Consume approval before returning any successful browser content.
    const bool wasExtra=relinkExtraDevice;
    portalForOwnerRelink=false;relinkExtraDevice=false;
    portalOpenUntil=0;mr7CloseToken();
    cancelPendingPair();pairOpenUntil=0;
    mrSyncGuestFirewall();
    if(!oldMac.equalsIgnoreCase(newMacText)){
      uint8_t oldBytes[6]={};
      if(parseMac(oldMac,oldBytes))deauthByMac(oldBytes);
    }
    miniNatStop();  // Re-evaluate all stations under the new allow list.
    ownerStatus(wasExtra?"MY DEVICE RE-LINKED":"OWNER LINK UPDATED");
    go(View::PEER_DETAILS);
    portal.sendHeader("Cache-Control","no-store");
    portal.send(200,"text/html; charset=utf-8",htmlLayout(
      wasExtra ? "<article><h2>تم تحديث جهازك</h2><p>تم حفظ العنوان الجديد مع الاحتفاظ بصلاحيات الجهاز واسمه.</p></article>" :
      "<article><h2>تم ربط الهاتف</h2><p>حساب VPN المنزلي محفوظ كما هو. يمكنك إعادة فتح تكوين النفق عند الحاجة.</p></article>"));
  });
  // Direct probe paths are helpful on devices which visit this host. They do
  // not intercept HTTPS or unrelated domains and do not affect normal DNS.
  portal.on("/hotspot-detect.html",HTTP_GET,[](){
    if(mrNeedsOnboarding(portal.client().remoteIP())){
      portal.sendHeader("Location",CAPTIVE_PAGE_URL);
      portal.send(302,"text/plain","");
    }else portal.send(200,"text/html","<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
  });
  portal.on("/generate_204",HTTP_GET,[](){
    if(mrNeedsOnboarding(portal.client().remoteIP())){
      portal.sendHeader("Location",CAPTIVE_PAGE_URL);
      portal.send(302,"text/plain","");
    }else portal.send(204,"text/plain","");
  });
  portal.on("/gen_204",HTTP_GET,[](){
    if(mrNeedsOnboarding(portal.client().remoteIP())){
      portal.sendHeader("Location",CAPTIVE_PAGE_URL);
      portal.send(302,"text/plain","");
    }else portal.send(204,"text/plain","");
  });
  portal.on("/owner/relink",HTTP_POST,[](){
    portal.send(410,"text/plain","Use fresh owner QR on Mini Rack");
  });
 // Simple text endpoint: tests local Wi-Fi + HTTP without PIN, HTML or QR reader.
 // Use http://192.168.4.1/ping in Safari while connected to MiniRack-Secure.
 portal.on("/ping",HTTP_GET,[](){
   noteHttpRequest("/ping");
   portal.sendHeader("Cache-Control","no-store, max-age=0");
   portal.send(200,"text/plain; charset=utf-8","MINI RACK WEB SERVER OK");
 });
 portal.on("/favicon.ico",HTTP_GET,[](){portal.send(204,"text/plain","");});
 portal.on("/vpn/download",HTTP_POST,[](){
   // Old PIN flow intentionally disabled. Direct one-time physical QR is the sole release path.
   portal.send(410,"text/plain","Open a fresh owner QR on Mini Rack");
 });
 portal.on("/",HTTP_GET,sendPortalHome);
 portal.on("/wifi/connect",HTTP_POST,[](){
   noteHttpRequest("/wifi/connect");
   if(!requirePortalAuth())return;
   if(portalForAPKey || chosenSSID.isEmpty()){
     portal.send(403,"text/plain","Select a Wi-Fi network on the ESP32 first");return;
   }
   const String ssid=chosenSSID; // Browser cannot override touchscreen choice.
   String pass=portal.arg("password");
   if(ssid.length()>32 || pass.length()>63 || (pass.length()>0 && pass.length()<8)){
     portal.send(400,"text/plain","Invalid password length");return;
   }
   savedSSID=ssid;savedPassword=pass;
    size_t a = prefsNet.putString("ssid",savedSSID);
    size_t b = prefsNet.putString("pass",savedPassword);
    if (a != savedSSID.length() ||
        b != savedPassword.length() ||
        prefsNet.getString("ssid","") != savedSSID ||
        prefsNet.getString("pass","") != savedPassword) {
      Serial.println("MINIRACK WIFI SAVE FAILED");
      portal.send(500,"text/plain","Wi-Fi save failed");
      return;
    }
    Serial.println("MINIRACK WIFI SAVED VERIFIED");
   wifiChangePending=true;portalChangeMs=millis();
   portalOpenUntil=0; // single-use physical setup; reopen from touchscreen.
   portal.send(200,"text/html; charset=utf-8",htmlLayout("<article><p>تم حفظ الاتصال بالشبكة المختارة. تابع الحالة من شاشة Mini Rack.</p></article>"));
   uiDirty=true;
 });
 portal.on("/ap/change",HTTP_POST,[](){
   noteHttpRequest("/ap/change");
   if(!requirePortalAuth())return;
   if(!portalForAPKey){portal.send(403,"text/plain","Open AP settings on device");return;}
   String pass=portal.arg("pass");
   if(pass.length()<12 || pass.length()>63){portal.send(400,"text/plain","Invalid password length");return;}
   nextAPPassword=pass;apChangePending=true;portalChangeMs=millis();portalOpenUntil=0;
   portal.send(200,"text/html; charset=utf-8",htmlLayout("<article><p>سيتم تحديث كلمة مرور الشبكة خلال ثوانٍ. أعد الاتصال بالكلمة الجديدة.</p></article>"));
 });
 portal.onNotFound([](){
   noteHttpRequest("unknown path");
   portal.send(404,"text/plain; charset=utf-8","Mini Rack: Not found. Open http://192.168.4.1/");
 });
 portal.begin();
}
static void webService() {
  portal.handleClient();
  if(wifiChangePending && (uint32_t)(millis()-portalChangeMs)>1000) {
    wifiChangePending=false;
    WiFi.disconnect(false,false);
    startUplink();
    go(View::INTERNET);
  }
  if(apChangePending && (uint32_t)(millis()-portalChangeMs)>1500) {
    apChangePending=false;
    apPassword=nextAPPassword;
    prefsNet.putString("apkey",apPassword);
    miniNatStop();
    // Updating AP credentials may recreate the underlying lwIP interface.
    // Invalidate prior hook readiness and re-arm before mixed guest NAT.
    MiniRackGuestFirewall::resetAfterApStop();
    if(apBroadcastEnabled) {
      if(!WiFi.AP.create(AP_NAME,apPassword.c_str(),1,0,MAX_ONLINE)) {
        Serial.println("MINIRACK: AP password change failed");
      } else {
        mrSyncGuestFirewall();
        MiniRackGuestFirewall::beginInstall();
      }
    }
    natLastAttempt=0;
    portalOpenUntil=0;
    go(View::INTERNET);
  }
  // The STA (internet source) is distinct from the AP (MiniRack clients).
  // Retry reconnect without deleting the local AP or any peer registration.
  if(WiFi.status()==WL_CONNECTED) {
    staReconnectAttempts=0;
  } else if(savedSSID.length() &&
            MiniRackReconnect::due(millis(),lastStaRetry,staReconnectAttempts)) {
    lastStaRetry=millis();
    if(staReconnectAttempts<MiniRackReconnect::kMaxAttempts) ++staReconnectAttempts;
    Serial.printf("MINIRACK STA RETRY %u; AP PRESERVED\n",(unsigned)staReconnectAttempts);
    Serial.printf("MR WIFI RETRY ssid=%s pass_len=%u\n",
        savedSSID.c_str(), (unsigned)savedPassword.length());
    WiFi.begin(savedSSID.c_str(),savedPassword.c_str());
  }
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200,SERIAL_8N1,44,43);  // preserves verified Pi UART pins
  prefsNet.begin("mininet",false);
  MiniRackTransport::load(prefsNet);
  prefsPeers.begin("minipeers",false);
  clearLegacyRejections();
  loadPeerState();
  mrSyncGuestFirewall();
  arabicLanguage=prefsNet.getBool("ar",true);
  savedSSID=prefsNet.getString("ssid","");
  savedPassword=prefsNet.getString("pass","");
  apPassword=prefsNet.getString("apkey","MiniRack2026!");
  apBroadcastEnabled=prefsNet.getBool("apEnabled",true);
  vpnEnabled=prefsNet.getBool("vpnEnabled",true); // Same default as original auto-start
  natShareEnabled=prefsNet.getBool("natshare",true);
  ownerProfileIssued=prefsNet.getBool("ownerprof",false);
  Serial.printf("MINIRACK VPN PREFERENCE: %s\n",vpnEnabled?"ON":"OFF");
  Serial.println(MiniRackEgressPolicy::kRequireHomeEgress?
      (MiniRackEgressPolicy::kHomeExperiment?
          "MINIRACK EGRESS: EXPERIMENTAL WG ROUTE; PI EXIT NOT VERIFIED":
          "MINIRACK EGRESS: HOME-ONLY GUARD ON; DIRECT NAT DISABLED"):
      "MINIRACK EGRESS: AP NAPT ENABLED; VPN ROUTING REQUIRES TEST");
  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
    Serial.printf("MINIRACK WIFI DISCONNECT REASON=%u\n",
      (unsigned)info.wifi_sta_disconnected.reason);
  }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
  WiFi.persistent(false);
  WiFi.mode(apBroadcastEnabled?WIFI_AP_STA:WIFI_STA);
  WiFi.setSleep(false); // Reduce AP+STA packet delay; AP stays independent of pairing.
  WiFi.setAutoReconnect(true);
  // The AP broadcast setting is retained across reboot. No clients can join
  // while it is disabled; the uplink Wi-Fi STA remains available.
  bool started=apBroadcastEnabled?startMiniRackAP():false;
  if(apBroadcastEnabled && !started){apStartFailed=true;apBroadcastEnabled=false;}
  Serial.printf("MiniRack AP: %s / pairing independent\n",
                started?"STARTED":(apBroadcastEnabled?"FAILED":"OFF"));
  Serial.printf("MINIRACK BOOT SAVED SSID: %s\n",
    savedSSID.isEmpty() ? "NONE" : savedSSID.c_str());
  if(savedSSID.length()) startUplink();
#if defined(CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME) && CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME
  esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &mrDhcpNameEvent, nullptr);
#endif
  webInit();
  Serial.print("AP URL: http://");Serial.println(WiFi.softAPIP());

  MiniRackCrypto::begin();
  pinMode(TFT_BL,OUTPUT);digitalWrite(TFT_BL,HIGH);
  pinMode(BATTERY_PIN,INPUT);
  gfx->begin();
  drawBootBrand();
  delay(650);  // brief identity splash; not a network-dependent loading screen
  touchStart();
  drawUI();
  lastUserTouchMs=millis();
  MiniRackCrypto::announceMode();
}

void loop() {
  // Explicitly expire pairing, including when the pairing screen is not open.
  if (pairOpenUntil != 0 && !windowOpen(pairOpenUntil)) {
    pairOpenUntil=0;
    uiDirty=true;
    Serial.println("PAIRING CLOSED: timeout");
  }
  if (pendingPairUntil!=0 && !pendingPairActive()) {
    const String stale=pendingPairMac;
    cancelPendingPair();
    uint8_t mac[6]={};
    if(parseMac(stale,mac)) {
      const int slot=findPair(mac);
      if(slot>=0 && peerRegistry.isTransient((uint8_t)slot) &&
         !peerAllowed[slot]){
        peerRegistry.remove((uint8_t)slot);
        mrSyncGuestFirewall();
        deauthByMac(mac);
        if(view==View::PAIR_CHOICE && selectedPeer==(uint8_t)slot)go(pairingReturnView);
        if(view==View::PEER_DETAILS && selectedPeer==(uint8_t)slot)go(View::USERS);
      }
    }
    uiDirty=true;
    Serial.println("MINIRACK PENDING APPROVAL EXPIRED: WIFI ACCESS REVOKED");
  }
  touchService();
  // True backlight sleep, no wireless teardown.  Re-enable on first touch.
  if(autoScreenSleep && !screenBlank &&
     (uint32_t)(millis()-lastUserTouchMs)>=SCREEN_IDLE_MS) sleepDisplay();
  // Check current stations before any web requests or NAT startup.
  // This cannot replace an actual per-station firewall in the Wi-Fi stack.
  enforcePairing();
  if(mrApplyDhcpNames())uiDirty=true;
  // IMPORTANT: handle uplink/route changes before NAT admission. This narrows
  // the period where NAPT could use a stale home-route state after roaming.
  // This is not a packet-level kill switch; keep guests locked until isolated.
  vpnService(); // User-controlled WireGuard with Wi-Fi roaming and retries.
  MiniRackV2::tick(vpnEnabled && vpnTunnel.is_initialized() && WiFi.status()==WL_CONNECTED);
  miniNatService();
  webService();
  // Only log link transitions; show signal strength to diagnose poor 2.4 GHz
  // conditions without repeated flash writes or captive portal changes.
  static bool lastUplinkConnected=false;
  bool uplinkConnected=WiFi.status()==WL_CONNECTED;
  if(uplinkConnected!=lastUplinkConnected){
    Serial.printf("MINIRACK UPLINK %s, RSSI %d dBm\n",
       uplinkConnected?"ONLINE":"OFFLINE",uplinkConnected?(int)WiFi.RSSI():0);
    lastUplinkConnected=uplinkConnected;
    liveInfoDirty=true;
  }
  // Update top status icons when wireless/NAT state changes (not on each loop).
  static uint8_t previousStatus=255;
  static uint32_t lastStatusCheck=0;
  if((uint32_t)(millis()-lastStatusCheck)>1000){
    lastStatusCheck=millis();
    uint8_t nowStatus=(WiFi.status()==WL_CONNECTED?1:0) |
        (apBroadcastEnabled?2:0) | (natActive?4:0) |
        (weakUplink()?8:0);
    if(nowStatus!=previousStatus){previousStatus=nowStatus;liveInfoDirty=true;}
  }
  if(mr7QrReady && !windowOpen(portalOpenUntil)){
    mr7CloseToken();portalForVpn=false;portalForOwnerRelink=false;
  }
  // Refresh QR view once when the short approval window actually expires.
  // No repeated screen clears or unnecessary network resets.
  static bool lastOwnerQrWindow=false;
  if(view==View::OWNER_VPN_QR){
    const bool active=(ownerQrBlock==0 && windowOpen(portalOpenUntil));
    if(lastOwnerQrWindow && !active)uiDirty=true;
    lastOwnerQrWindow=active;
  }else lastOwnerQrWindow=false;
  MiniRackCrypto::pollCommands();
  mrSecurityTick();
  // Keep the actual encrypted telemetry running without overriding the menu.
  static uint32_t lastTelemetry=0;
  if((uint32_t)(millis()-lastTelemetry)>5000 || lastTelemetry==0) {
    lastTelemetry=millis();
    MiniRackCrypto::runRealIteration();
  }
  if(uiDirty && !screenBlank)drawUI();
  // LCD was redrawn with backlight OFF; enable only after framebuffer is ready.
  if(wakeBacklightPending && !screenBlank){
    digitalWrite(TFT_BL,HIGH);
    wakeBacklightPending=false;
  }
  paintLiveChanges();
  delay(5);
}

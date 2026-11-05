#include "minirack_v2_client.h"
#include <Arduino.h>

// ONE integrated firmware: the normal V1 build also contains the V2 client.
// The client becomes active only when the owner's *private* enrollment header
// is present; without enrollment, V1 network and UI behaviour stay unchanged.
// An explicit build flag can still override this for regression tests.
#ifndef MINIRACK_V2_CLIENT_ENABLED
  #if __has_include("minirack_v2_private.h")
    #define MINIRACK_V2_CLIENT_ENABLED 1
  #else
    #define MINIRACK_V2_CLIENT_ENABLED 0
  #endif
#endif

#if MINIRACK_V2_CLIENT_ENABLED && !__has_include("minirack_v2_private.h")
  #error "V2 enabled without a private enrollment header. Provision device locally first."
#endif

#if MINIRACK_V2_CLIENT_ENABLED
#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_system.h>
#include <mbedtls/md.h>
#include <time.h>
#include "minirack_v2_private.h" // generated only for this owner's board; DO NOT SHARE

#ifndef MINIRACK_V2_PI_URL
#define MINIRACK_V2_PI_URL "http://10.10.0.1:8873/v2/device/authorize"
#endif

namespace {
static uint32_t lastAuthMs=0;
static bool attempted=false;
static String lastBssid;
static uint32_t retryIntervalMs=60000;
static bool lastVerified=false;
static bool tunnelReady=false;
static uint32_t lastVerifiedAtMs=0;
static constexpr uint32_t kVerifiedMaxAgeMs=90000; // 90s, refresh every 60s.
static String hexBytes(const uint8_t *data, size_t len) {
  static const char kHex[]="0123456789abcdef";
  String out;
  out.reserve(len*2);
  for(size_t i=0;i<len;++i){out+=kHex[data[i]>>4];out+=kHex[data[i]&15];}
  return out;
}
static bool hmacHex(const String& keyHex,const String& message,String &signature){
  if(keyHex.length()!=64)return false;
  uint8_t key[32];
  for(int i=0;i<32;i++){
    char a=keyHex[2*i],b=keyHex[2*i+1];
    auto nib=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    int hi=nib(a),lo=nib(b);
    if(hi<0||lo<0)return false;
    key[i]=(uint8_t)((hi<<4)|lo);
  }
  uint8_t digest[32];
  const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if(!md||mbedtls_md_hmac(md,key,sizeof(key),
     reinterpret_cast<const unsigned char*>(message.c_str()),message.length(),digest)!=0){
    memset(key,0,sizeof(key));return false;
  }
  signature=hexBytes(digest,sizeof(digest));
  memset(digest,0,sizeof(digest));
  memset(key,0,sizeof(key));
  return true;
}
static String jsonText(const String &json, const char *field){
  const String prefix=String("\"")+field+"\":\"";
  int pos=json.indexOf(prefix);
  if(pos<0)return String();
  int begin=pos+prefix.length();
  int end=json.indexOf('"',begin);
  return end<0?String():json.substring(begin,end);
}
static bool equalHex64(const String &a,const String &b){
  if(a.length()!=64||b.length()!=64)return false;
  uint8_t diff=0;
  for(int i=0;i<64;i++)diff|=(uint8_t)(a[i]^b[i]);
  return diff==0;
}
static bool safeId(const String& id){
  if(id.length()<3||id.length()>64)return false;
  for(size_t i=0;i<id.length();++i){char c=id[i];
    if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
      (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
  }
  return true;
}
static bool attemptAuth(){
  const String device=String(MINIRACK_V2_DEVICE_ID);
  const String key=String(MINIRACK_V2_DEVICE_KEY_HEX);
  const String gateway=String(MINIRACK_V2_GATEWAY_ID);
  if(!safeId(device)||!safeId(gateway)){
    Serial.println("V2 AUTH: private enrollment configuration invalid");return false;
  }
  uint8_t nonceRaw[16];
  esp_fill_random(nonceRaw,sizeof(nonceRaw));
  const String nonce=hexBytes(nonceRaw,sizeof(nonceRaw));
  const int64_t now=(int64_t)time(nullptr);
  if(now<1700000000){Serial.println("V2 AUTH: awaiting synchronized clock");return false;}
  // Matches Python canonical() sorted keys, compact format exactly.
  const String unsignedBody="{\"device_id\":\""+device+"\",\"gateway_id\":\""+
       gateway+"\",\"nonce\":\""+nonce+"\",\"ts\":"+String((unsigned long)now)+"}";
  String signature;
  if(!hmacHex(key,unsignedBody,signature)){
    Serial.println("V2 AUTH: cannot sign request");return false;
  }
  // Gateway relay supplies a distinct gateway HMAC; the device never holds gateway key.
  const String request="{\"payload\":{\"device_id\":\""+device+
       "\",\"device_sig\":\""+signature+"\",\"gateway_id\":\""+
       gateway+"\",\"nonce\":\""+nonce+"\",\"ts\":"+
       String((unsigned long)now)+"}}";
  HTTPClient http;
  http.setTimeout(1500);
  if(!http.begin(String(MINIRACK_V2_PI_URL))){
    Serial.println("V2 AUTH: relay URL failed");return false;
  }
  http.addHeader("Content-Type","application/json");
  int code=http.POST(request);
  String reply= code>0?http.getString():String();
  http.end();
  // Pi relay is a local service reached only over the established WG tunnel.
  // NAPT is admitted on a fresh signed proof; this is not per-station routing.
  if(code==200 && jsonText(reply,"decision")=="allow"){
    const String session=jsonText(reply,"session_id");
    const String proof=jsonText(reply,"device_response_proof");
    if(safeId(session)){
      const String proofBody="{\"decision\":\"allow\",\"device_id\":\""+device+
          "\",\"gateway_id\":\""+gateway+"\",\"nonce\":\""+nonce+
          "\",\"session_id\":\""+session+"\"}";
      String expected;
      if(hmacHex(key,proofBody,expected)&&equalHex64(proof,expected)){
        Serial.println("V2 AUTH: ALLOW (signed entitlement verified)");
        return true;
      }
    }
    Serial.println("V2 AUTH: REJECTED unsigned or mismatched server proof");
    return false;
  }
  Serial.printf("V2 AUTH: NOT AUTHORIZED (HTTP %d)\n",code);
  return false;
}
} // namespace
namespace MiniRackV2 {
void tick(bool wgReady){
  tunnelReady=wgReady;
  if(!wgReady){
    attempted=false;
    lastBssid=String();
    lastVerified=false;
    return;
  }
  const String bssid=WiFi.BSSIDstr();
  if(bssid!=lastBssid){
    lastBssid=bssid;
    attempted=false;
    lastVerified=false; // roaming: previous grant cannot carry to a new uplink
  }
  const uint32_t now=millis();
  if(attempted && (uint32_t)(now-lastAuthMs)<retryIntervalMs)return;
  // Only one bounded HTTP attempt per minute, avoids scanning, blocking UI loops.
  attempted=true;
  lastAuthMs=now;
  lastVerified=attemptAuth();
  if(lastVerified) lastVerifiedAtMs=millis();
  retryIntervalMs=60000; // Check revoked entitlement at most once per minute.
}
bool internetPermit(){
  return tunnelReady && lastVerified &&
         (uint32_t)(millis()-lastVerifiedAtMs) <= kVerifiedMaxAgeMs;
}
}
#else
namespace MiniRackV2 {
void tick(bool) {}
bool internetPermit() { return true; } // V1 unchanged without V2 enrollment
}
#endif

#include "minirack_qr_token.h"
#include <esp_system.h>

namespace MiniRackQrToken {
void Approval::create(bool forRelink) {
  clear();
  static const char kHex[]="0123456789abcdef";
  char buf[33];
  for (uint8_t i=0; i<16; i+=4) {
    const uint32_t r=esp_random();
    for (uint8_t j=0; j<4; ++j) {
      const uint8_t b=(uint8_t)(r>>(8*j));
      buf[(i+j)*2]=kHex[b>>4];
      buf[(i+j)*2+1]=kHex[b&15];
    }
  }
  buf[32]='\0';
  token=String(buf);
  url=String("http://192.168.4.1/")+
    (forRelink?"owner/relink-now?t=":"vpn/now?t=")+token;
}
void Approval::clear() {
  // Avoid leaving old token text in live String objects after the QR closes.
  token="";
  url="";
  ready=false;
}
bool Approval::matches(const String &candidate) const {
  if (!ready || token.length()!=32 || candidate.length()!=32) return false;
  uint8_t different=0;
  for (uint8_t i=0;i<32;++i) different|=(uint8_t)(token[i]^candidate[i]);
  return different==0;
}
} // namespace MiniRackQrToken

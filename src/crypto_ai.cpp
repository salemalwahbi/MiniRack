// Extracted without algorithm changes from Mini Rack Stage 8 (2026-10-21).
// The prototype test keys are retained only to preserve the original behavior.
// Do NOT deploy with prototype keys; replace via a secure provisioning process.
#include <Arduino.h>
#include <Crypto.h>
#include <ChaCha.h>
#include <Ascon128.h>
#include <mbedtls/md.h>
#include "Classifier.h"
#include "crypto_ai.h"
#include "minirack_security.h"
#include "minirack_adaptive_policy.h"

namespace MiniRackCrypto {
// ======================================================
// AI + CRYPTO
// ======================================================

Classifier aiEngine;

ChaCha chacha;
Ascon128 ascon;

// ======================================================
// KEYS
// ======================================================

uint8_t chachaKey[32] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10,
  0x11,0x12,0x13,0x14,
  0x15,0x16,0x17,0x18,
  0x19,0x1A,0x1B,0x1C,
  0x1D,0x1E,0x1F,0x20
};

uint8_t asconKey[16] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10
};

uint8_t chachaIV[8] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08
};

 uint8_t asconIV[16] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10
};

// ======================================================
// PAYLOAD
// ======================================================

#define MAX_PAYLOAD 1500

uint8_t dummyPayload[MAX_PAYLOAD];
uint8_t ciphertext[MAX_PAYLOAD];


// Real telemetry stays active in the background; the TFT is a touch-based device UI.

static const float REAL_BATTERY_PROFILE = 100.0f;
static const float REAL_PRIORITY_PROFILE = 0.0f;

// Prototype-only shared MAC key; provision real secret keys before deployment.
static const uint8_t chachaMacKey[32] = {
  0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
  0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
  0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
  0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

// Per-boot random prefix + monotonically increasing counter.
// This is a development nonce strategy, not a full production key lifecycle.
static uint8_t bootNoncePrefix[8];
static uint64_t nonceCounter = 0;
static uint32_t packetSequence = 0;
static uint32_t lastAcknowledged = 0;
static bool everAcknowledged = false;
static bool lastTxSent = false;
static unsigned long lastEncryptUs = 0;
static int lastRealAlgorithm = 1;
static bool elevatedThreat = false;
static uint8_t currentThreatScore = 0;
static MiniRackAdaptive::Policy adaptivePolicy;

void setSecurityState(bool elevated, uint8_t risk) {
  elevatedThreat = elevated;
  currentThreatScore = risk;
}




struct CommandBuffer { char line[64]; size_t used = 0; };
CommandBuffer usbCommands, piCommands;

void announceMode() {
  // Only real operations are exposed in this travel UI firmware.
  Serial.println("MODE:REAL");
  Serial1.println("MODE:REAL");
}

static void handleCommand(const char *text) {
  String cmd(text); cmd.trim(); cmd.toUpperCase();
  if (cmd == "MODE?" || cmd == "MODE:REAL" || cmd == "MODE:DEMO") {
    announceMode();  // do not start demo scenarios
  } else if (cmd.startsWith("ACK:")) {
    unsigned long seq = 0;
    char result[4] = {};
    if (sscanf(cmd.c_str(), "ACK:%lu:%3s", &seq, result) == 2 &&
        strcmp(result, "OK") == 0 && seq <= packetSequence) {
      lastAcknowledged = (uint32_t)seq;
      everAcknowledged = true;
    }
  }
}

static void pollStream(Stream &stream, CommandBuffer &buf) {
  while (stream.available()) {
    const char c = (char)stream.read();
    if (c == '\r') continue;
    if (c == '\n') {
      buf.line[buf.used] = 0;
      if (buf.used) handleCommand(buf.line);
      buf.used = 0;
    } else if (buf.used < sizeof(buf.line) - 1 && c >= 32 && c <= 126) {
      buf.line[buf.used++] = c;
    } else {
      buf.used = 0;
    }
  }
}

void pollCommands() {
  pollStream(Serial1, piCommands);
  pollStream(Serial, usbCommands);
}

void makeNonce(uint8_t *nonce, size_t size) {
  // 8-byte ChaCha nonce: 4-byte boot prefix + 4-byte counter
  // 16-byte Ascon nonce: 8-byte boot prefix + 8-byte counter
  const size_t prefix = (size == 8) ? 4 : 8;
  const size_t countBytes = size - prefix;
  memcpy(nonce, bootNoncePrefix, prefix);
  for (size_t i = 0; i < countBytes; ++i) {
    nonce[prefix + i] = (uint8_t)((nonceCounter >> (8 * i)) & 0xFF);
  }
  ++nonceCounter;
}

void printHexToPi(const uint8_t *bytes, size_t size) {
  for (size_t i = 0; i < size; ++i) Serial1.printf("%02X", bytes[i]);
}


void runRealIteration() {
  // This message is REAL system data, not a synthetic payload.
  uint32_t heap = ESP.getFreeHeap();
  uint32_t mhz = ESP.getCpuFreqMHz();
  uint32_t uptime = millis();
  if (packetSequence == UINT32_MAX) {
    Serial.println("REAL packet counter exhausted; reprovision key!");
    return;
  }
  const uint32_t sequence = ++packetSequence;

  char realPayload[160];
  int n = snprintf(realPayload, sizeof(realPayload),
                   "Seq:%lu,UptimeMs:%lu,FreeHeap:%u,CpuMHz:%u",
                   (unsigned long)sequence, (unsigned long)uptime,
                   (unsigned)heap, (unsigned)mhz);
  if (n <= 0 || n >= (int)sizeof(realPayload)) {
    Serial.println("REAL payload format error");
    return;
  }
  const size_t payloadSize = (size_t)n;
  float features[4] = {
    (float)payloadSize, REAL_BATTERY_PROFILE,
    (float)heap, REAL_PRIORITY_PROFILE
  };
  int decision = aiEngine.predict(features);
  // Unified adaptive decision: legacy Classifier + live measured full crypto cost.
  // Threat response remains independent (authorization checks / QR temporary lock).
  // Neither algorithm has an automatic security upgrade at ALERT, so don't
  // force a cipher merely because an intrusion event was observed.
  decision = adaptivePolicy.select(decision, payloadSize);
  if (decision != 0 && decision != 1) {
    Serial.println("AI decision invalid");
    return;
  }

  uint8_t nonce[16] = {};
  uint8_t ct[160] = {};
  uint8_t tag[32] = {};
  const size_t nonceLen = decision == 0 ? 8 : 16;
  const size_t tagLen = decision == 0 ? 32 : 16;
  makeNonce(nonce, nonceLen);

  unsigned long start = micros();
  if (decision == 1) {
    ascon.clear();
    ascon.setKey(asconKey, sizeof(asconKey));
    ascon.setIV(nonce, nonceLen);
    ascon.encrypt(ct, (const uint8_t*)realPayload, payloadSize);
    ascon.computeTag(tag, tagLen);
  } else {
    chacha.clear();
    chacha.setKey(chachaKey, sizeof(chachaKey));
    chacha.setIV(nonce, nonceLen);
    chacha.encrypt(ct, (const uint8_t*)realPayload, payloadSize);

    // HMAC covers an algorithm-specific domain, the nonce and ciphertext.
    uint8_t macInput[13 + 8 + 160] = {};
    static const char DOMAIN[] = "MR-CHACHA-V1";  // 12 ASCII bytes
    const size_t domainLen = sizeof(DOMAIN) - 1;
    memcpy(macInput, DOMAIN, domainLen);
    memcpy(macInput + domainLen, nonce, 8);
    memcpy(macInput + domainLen + 8, ct, payloadSize);
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || mbedtls_md_hmac(md, chachaMacKey, sizeof(chachaMacKey),
                              macInput, domainLen + 8 + payloadSize, tag) != 0) {
      Serial.println("HMAC failed: data not sent");
      return;
    }
  }
  unsigned long encryptionUs = micros() - start;
  lastEncryptUs = encryptionUs;
  lastRealAlgorithm = decision;
  adaptivePolicy.record(decision, payloadSize, encryptionUs);

  // REAL2:<algorithm>:<sequence>:<length>:<nonce>:<ciphertext>:<tag>
  Serial1.printf("REAL2:%d:%lu:%u:", decision, (unsigned long)sequence,
                 (unsigned)payloadSize);
  printHexToPi(nonce, nonceLen);
  Serial1.print(":");
  printHexToPi(ct, payloadSize);
  Serial1.print(":");
  printHexToPi(tag, tagLen);
  Serial1.println();
  lastTxSent = true;

  Serial.printf("REAL #%lu AI:%d Mode:%s Risk:%u Bytes:%u Encrypt:%lu us Heap:%u CPU:%u\n",
                (unsigned long)sequence, decision, elevatedThreat ? "ALERT" : "NORMAL",
                (unsigned)currentThreatScore, (unsigned)payloadSize,
                encryptionUs, (unsigned)heap, (unsigned)mhz);
  // Display remains on touchscreen navigation; telemetry continues in background.
}





void begin() {
  adaptivePolicy.reset();
  // Same per-boot prefix initialization formerly in Stage 8 setup().
  for(int i=0;i<8;i+=4) {
    uint32_t r=esp_random();
    for(int b=0;b<4;b++) bootNoncePrefix[i+b]=(uint8_t)(r>>(b*8));
  }
}

bool hasAcknowledgement() { return everAcknowledged; }

} // namespace MiniRackCrypto

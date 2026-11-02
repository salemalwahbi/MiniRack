#pragma once
#include <stdint.h>

// Stage 9 modularization: original Stage 8 adaptive telemetry interface.
// Public operations; cryptographic keys/state stay private to crypto_ai.cpp.
namespace MiniRackCrypto {
  void begin();                  // Per-boot nonce initialization
  void announceMode();          // Announce real telemetry mode over UART
  void pollCommands();          // Receive UART/USB acknowledgements
  void runRealIteration();      // Encrypt & transmit telemetry
  bool hasAcknowledgement();    // Status for device diagnostics
  void setSecurityState(bool elevated, uint8_t risk); // Security-aware AI arbitration
}

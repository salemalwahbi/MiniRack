#pragma once
// Never mistake a WireGuard interface for a validated per-station firewall.
// Default preserves Stage 17 DIRECT-WAN owner-only behaviour.
// HOME-ONLY without the experimental route remains strictly blocked.
#ifndef MINIRACK_HOME_EGRESS_REQUIRED
#define MINIRACK_HOME_EGRESS_REQUIRED 0
#endif
#ifndef MINIRACK_HOME_TUNNEL_EXPERIMENT
#define MINIRACK_HOME_TUNNEL_EXPERIMENT 0
#endif
#if (MINIRACK_HOME_EGRESS_REQUIRED != 0 && MINIRACK_HOME_EGRESS_REQUIRED != 1) || \
    (MINIRACK_HOME_TUNNEL_EXPERIMENT != 0 && MINIRACK_HOME_TUNNEL_EXPERIMENT != 1)
#error "Mini Rack egress flags must be 0 or 1"
#endif
namespace MiniRackEgressPolicy {
constexpr bool kRequireHomeEgress = MINIRACK_HOME_EGRESS_REQUIRED == 1;
constexpr bool kHomeExperiment = MINIRACK_HOME_TUNNEL_EXPERIMENT == 1;
inline bool allowDirectNat(bool sharing, bool ownersOnly,
                           bool admissionClosed, bool relinkClosed) {
  return !kRequireHomeEgress && sharing && ownersOnly &&
         admissionClosed && relinkClosed;
}
inline bool allowHomeNat(bool sharing, bool ownersOnly,
                         bool admissionClosed, bool relinkClosed,
                         bool tunnelEnabled, bool tunnelLinkReady) {
  return kRequireHomeEgress && kHomeExperiment && sharing && ownersOnly &&
         admissionClosed && relinkClosed && tunnelEnabled && tunnelLinkReady;
}
}

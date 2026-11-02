#pragma once
// PRIVATE: copy to wg_secrets.h and change the values for your own network.
#define WG_LOCAL_IP "10.10.0.3"
#define WG_SERVER_IP "192.0.2.1" // documentation-only IP, replace
#define WG_SERVER_PORT 51820
#include "wg_private_local.h"
#define WG_SERVER_PUBLIC_KEY "REPLACE_WITH_SERVER_PUBLIC_KEY"
// For a host name, optionally define WG_SERVER_HOST in YOUR local file.

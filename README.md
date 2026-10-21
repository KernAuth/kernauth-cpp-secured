# KernAuth C++ secured example

Payload-key flow: `initialize` → `validate` → `unwrap_payload`.

The server seals the application payload key with a session secret derived from HWID, a random salt, and the server UTC hour. Validate returns `payload_box` only — never a cleartext wrap key.

Copy `include/` from this repo (or sync from the KernAuth monorepo `packages/sdk-cpp/include`), link **libsodium**, **libcurl**, and **nlohmann/json**, then build `src/main.cpp`.

For a plain license check without a payload key, use [kernauth-cpp](https://github.com/KernAuth/kernauth-cpp) (or the headers in `packages/sdk-cpp`).

## Use

```cpp
#include "kernauth.hpp"

kernauth::App app(
    "https://api.kernauth.com",
    "pub_your_app",
    "your_public_key");

if (!app.initialize().ok) {
  return 1;
}

kernauth::ClientResult result = app.validate(license_key);
if (!result.active) {
  return 1;
}

kernauth::PayloadUnwrap unwrapped = app.unwrap_payload();
if (!unwrapped.ok) {
  return 1;
}
// unwrapped.payload_key is the dashboard Payload key string — wipe after use.
```

1. In Developers / Settings, set a **Payload key** on the application.
2. Paste the public app ID and public key into `src/main.cpp`.
3. Build and run. Type the license at the prompt (`KERN_LICENSE_KEY` skips it).

`shared/payload_crypto.hpp` shows how to turn that string into a file key (BLAKE2b) for sealing a DLL or resource. Your product wires seal at build time and open after unwrap.

A modified program can still skip the local check. The server can still revoke the license and end the session.

Documentation: https://kernauth.apidog.io

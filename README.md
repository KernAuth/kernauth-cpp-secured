# KernAuth C++ secured example

Payload-key flow: `initialize` → `validate` → `unwrap_payload`.

Open `KernAuth.sln` in Visual Studio 2022 (x64), paste your public app ID and public key into `src/main.cpp`, set a **Payload key** on the application in the dashboard, then build and run.

Vendored **libsodium**, **libcurl**, and **nlohmann/json** live under `include/`. Static x64 libs are in `lib/`. vcpkg is not used.

For a plain license check without a payload key, use [kernauth-cpp](https://github.com/KernAuth/kernauth-cpp).

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

`shared/payload_crypto.hpp` shows how to turn that string into a file key (BLAKE2b) for sealing a DLL or resource.

## Layout

| Path | What |
| --- | --- |
| `KernAuth.sln` | Visual Studio solution |
| `example/` | Console project (links vendored libs) |
| `include/` | KernAuth SDK + curl / sodium / nlohmann |
| `lib/` | Static x64 libs |
| `src/main.cpp` | Secured example |
| `shared/payload_crypto.hpp` | Seal / open helpers |

Type the license at the prompt (`KERN_LICENSE_KEY` skips it).

A modified program can still skip the local check. The server can still revoke the license and end the session.

Documentation: https://kernauth.apidog.io

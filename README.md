# KernAuth C++ secured example

Same shape as a product loader: **payload** DLL → **seal** → **loader** embeds and decrypts it after KernAuth auth.

```text
KernAuth.sln
loader/          auth + unwrap + load sealed DLL
payload/         sample DLL (payload_run / payload_stop)
tools/seal/      encrypts payload.dll with the dashboard Payload key
shared/          payload_crypto.hpp + seal_key.example
include/         KernAuth SDK + curl / sodium / nlohmann
lib/             x64 static libs
```

## Setup

1. Set a **Payload key** on your app in the KernAuth dashboard.
2. Copy `shared/seal_key.example` → `shared/seal_key.txt` and put that same key in the file (or set `KERN_PAYLOAD_KEY`).
3. Paste public app ID and public key into `loader/main.cpp`.
4. Open `KernAuth.sln` (x64), build. Pre-build runs `seal.exe` and embeds `loader/generated/payload.enc`.
5. Run `build/kernauth-secured.exe` and type a license (`KERN_LICENSE_KEY` skips the prompt).

Flow: `initialize` → `validate` → `unwrap_payload` → decrypt resource → `LoadLibrary` → `payload_run`.

vcpkg is not used. A modified program can still skip the local check.

Documentation: https://kernauth.apidog.io

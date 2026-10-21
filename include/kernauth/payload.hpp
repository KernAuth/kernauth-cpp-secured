#pragma once

// Unwrap KernAuth validate features: session secret + payload_box (AES-256-GCM).
// Matches apps/api/src/licenses/payload-wrap.ts (session wrap, no wrap_key).

#include "kernauth/nonce.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace kernauth {

struct PayloadUnwrap {
  bool ok = false;
  std::string payload_key;
  std::string message;
};

namespace detail {

inline bool decode_base64_any(std::string_view text, std::vector<unsigned char>& out) {
  if (text.empty()) {
    return false;
  }
  out.assign(text.size(), 0);
  std::size_t decoded = 0;
  if (sodium_base642bin(
          out.data(),
          out.size(),
          text.data(),
          text.size(),
          nullptr,
          &decoded,
          nullptr,
          sodium_base64_VARIANT_ORIGINAL) != 0) {
    return false;
  }
  out.resize(decoded);
  return decoded > 0;
}

/** Open AES-256-GCM: nonce(12) || ciphertext || tag(16). Uses libsodium (portable). */
inline bool aes256_gcm_open(
    const unsigned char* key,
    const unsigned char* nonce,
    std::size_t nonce_len,
    const unsigned char* cipher,
    std::size_t cipher_len,
    std::vector<unsigned char>& plain) {
  if (!key || !nonce || !cipher || nonce_len != crypto_aead_aes256gcm_NPUBBYTES ||
      cipher_len <= crypto_aead_aes256gcm_ABYTES) {
    return false;
  }
  if (crypto_aead_aes256gcm_is_available() == 0) {
    return false;
  }
  plain.assign(cipher_len - crypto_aead_aes256gcm_ABYTES, 0);
  unsigned long long mlen = 0;
  if (crypto_aead_aes256gcm_decrypt(
          plain.data(),
          &mlen,
          nullptr,
          cipher,
          cipher_len,
          nullptr,
          0,
          nonce,
          key) != 0) {
    plain.clear();
    return false;
  }
  plain.resize(static_cast<std::size_t>(mlen));
  return true;
}

}  // namespace detail

/**
 * Open payload_box with the 32-byte session secret from App.initialize().
 * wrap_key is no longer returned by validate.
 */
inline PayloadUnwrap unwrap_payload_key(
    std::string_view features_json,
    const std::array<unsigned char, 32>& session_key) {
  PayloadUnwrap out;
  try {
    detail::ensure_sodium();
    const auto json = nlohmann::json::parse(features_json);
    if (!json.contains("payload_box")) {
      out.message = "Missing payload box (set Payload key in KernAuth)";
      return out;
    }
    if (json.contains("wrap_key")) {
      out.message = "Unexpected wrap_key (update KernAuth API)";
      return out;
    }

    std::vector<unsigned char> box;
    if (!detail::decode_base64_any(json.at("payload_box").get<std::string>(), box) ||
        box.size() <= 12 + 16) {
      out.message = "Invalid payload_box";
      return out;
    }

    std::vector<unsigned char> plain;
    if (!detail::aes256_gcm_open(
            session_key.data(),
            box.data(),
            12,
            box.data() + 12,
            box.size() - 12,
            plain)) {
      out.message = "Payload unwrap failed";
      return out;
    }

    out.payload_key.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
    sodium_memzero(plain.data(), plain.size());
    out.ok = !out.payload_key.empty();
    if (!out.ok) {
      out.message = "Empty payload key";
    }
  } catch (const std::exception&) {
    out.message = "Malformed features";
  }
  return out;
}

}  // namespace kernauth

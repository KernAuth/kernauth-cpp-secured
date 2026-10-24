#pragma once
// Sealed payload file: 24-byte nonce || secretbox(ciphertext).
// File key = BLAKE2b-256(KernAuth application payload key string).

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace payload_crypto {

inline constexpr std::size_t nonce_size = crypto_secretbox_NONCEBYTES;
inline constexpr std::size_t mac_size = crypto_secretbox_MACBYTES;
inline constexpr std::size_t key_size = crypto_secretbox_KEYBYTES;

inline bool ready() {
  return sodium_init() >= 0;
}

/** Same derivation for a seal tool (build) and the loader (runtime after unwrap). */
inline bool derive_file_key(std::string_view payload_key, unsigned char out[key_size]) {
  if (!ready() || payload_key.empty() || !out) {
    return false;
  }
  return crypto_generichash(
             out,
             key_size,
             reinterpret_cast<const unsigned char*>(payload_key.data()),
             payload_key.size(),
             nullptr,
             0) == 0;
}

inline bool seal(
    const unsigned char* plain,
    std::size_t plain_len,
    const unsigned char key[key_size],
    std::vector<unsigned char>& out) {
  if (!plain || !key || plain_len == 0) {
    return false;
  }
  out.resize(nonce_size + plain_len + mac_size);
  randombytes_buf(out.data(), nonce_size);
  return crypto_secretbox_easy(
             out.data() + nonce_size,
             plain,
             plain_len,
             out.data(),
             key) == 0;
}

inline bool open(
    const unsigned char* sealed,
    std::size_t sealed_len,
    const unsigned char key[key_size],
    std::vector<unsigned char>& plain) {
  if (!sealed || !key || sealed_len <= nonce_size + mac_size) {
    return false;
  }
  const std::size_t cipher_len = sealed_len - nonce_size;
  plain.resize(cipher_len - mac_size);
  return crypto_secretbox_open_easy(
             plain.data(),
             sealed + nonce_size,
             cipher_len,
             sealed,
             key) == 0;
}

}  // namespace payload_crypto

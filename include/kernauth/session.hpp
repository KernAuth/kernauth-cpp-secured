#pragma once

// Client session secret: SHA-256 of HWID + time bucket + salt (+ app id).
// Matches apps/api/src/licenses/session-secret.ts

#include "kernauth/nonce.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

namespace kernauth {

/** UTC hour as YYYYMMDDHH (10 digits). */
inline std::string utc_time_bucket(std::chrono::system_clock::time_point time) {
  using namespace std::chrono;
  const auto whole_seconds = time_point_cast<seconds>(time);
  const auto day_point = floor<days>(whole_seconds);
  const year_month_day date{day_point};
  const auto time_of_day = whole_seconds - sys_days{date};
  const auto hour = duration_cast<hours>(time_of_day);
  char buffer[16];
  std::snprintf(
      buffer,
      sizeof(buffer),
      "%04d%02u%02u%02d",
      static_cast<int>(date.year()),
      static_cast<unsigned>(date.month()),
      static_cast<unsigned>(date.day()),
      static_cast<int>(hour.count()));
  return buffer;
}

inline std::string utc_time_bucket_now() {
  return utc_time_bucket(std::chrono::system_clock::now());
}

/**
 * 32-byte AES session key shared with the API.
 * Material: kernauth-session-v1|public_app_id|installation_id|device_fingerprint|time_bucket|session_salt
 */
inline std::array<unsigned char, 32> derive_session_key(
    std::string_view public_app_id,
    std::string_view installation_id,
    std::string_view device_fingerprint,
    std::string_view time_bucket,
    std::string_view session_salt) {
  detail::ensure_sodium();
  const std::string material = std::string("kernauth-session-v1|") + std::string(public_app_id) + "|" +
                               std::string(installation_id) + "|" + std::string(device_fingerprint) + "|" +
                               std::string(time_bucket) + "|" + std::string(session_salt);
  std::array<unsigned char, crypto_hash_sha256_BYTES> hash{};
  crypto_hash_sha256(
      hash.data(),
      reinterpret_cast<const unsigned char*>(material.data()),
      material.size());
  return hash;
}

}  // namespace kernauth

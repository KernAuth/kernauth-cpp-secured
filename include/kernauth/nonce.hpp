#pragma once

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kernauth {
namespace detail {

inline void ensure_sodium() {
  static const int ready = sodium_init();
  if (ready < 0) {
    throw std::runtime_error("libsodium failed to initialize");
  }
}

inline std::string to_hex(const unsigned char* bytes, std::size_t size) {
  std::string hex;
  hex.resize(size * 2);
  for (std::size_t index = 0; index < size; ++index) {
    std::snprintf(hex.data() + (index * 2), 3, "%02x", bytes[index]);
  }
  return hex;
}

inline bool read_int(std::string_view text, int& value) {
  if (text.empty()) {
    return false;
  }
  int parsed = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return false;
    }
    parsed = (parsed * 10) + (character - '0');
  }
  value = parsed;
  return true;
}

}  // namespace detail

/** 32 cryptographic random bytes, hex-encoded. Matches the client nonce pattern. */
inline std::string random_nonce() {
  detail::ensure_sodium();
  std::array<unsigned char, 32> bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  return detail::to_hex(bytes.data(), bytes.size());
}

/** SHA-256 hex of a versioned installation marker. This is not a hardware serial. */
inline std::string derive_device_fingerprint(int fingerprint_version, std::string_view installation_id) {
  detail::ensure_sodium();
  const std::string material =
      "kernauth-device-v" + std::to_string(fingerprint_version) + ":" + std::string(installation_id);
  std::array<unsigned char, crypto_hash_sha256_BYTES> hash{};
  crypto_hash_sha256(
      hash.data(),
      reinterpret_cast<const unsigned char*>(material.data()),
      material.size());
  return detail::to_hex(hash.data(), hash.size());
}

inline std::string format_iso_utc(std::chrono::system_clock::time_point time) {
  using namespace std::chrono;
  const auto truncated = time_point_cast<milliseconds>(time);
  const auto milliseconds_part = truncated.time_since_epoch() % seconds{1};
  const auto whole_seconds = time_point_cast<seconds>(truncated);
  const auto day_point = floor<days>(whole_seconds);
  const year_month_day date{day_point};
  const auto time_of_day = whole_seconds - sys_days{date};
  const auto hour = duration_cast<hours>(time_of_day);
  const auto minute = duration_cast<minutes>(time_of_day - hour);
  const auto second = duration_cast<seconds>(time_of_day - hour - minute);
  char buffer[32];
  std::snprintf(
      buffer,
      sizeof(buffer),
      "%04d-%02u-%02uT%02d:%02d:%02d.%03dZ",
      static_cast<int>(date.year()),
      static_cast<unsigned>(date.month()),
      static_cast<unsigned>(date.day()),
      static_cast<int>(hour.count()),
      static_cast<int>(minute.count()),
      static_cast<int>(second.count()),
      static_cast<int>(milliseconds_part.count()));
  return buffer;
}

inline std::string utc_now_iso() {
  return format_iso_utc(std::chrono::system_clock::now());
}

inline bool parse_iso_utc(std::string_view text, std::chrono::system_clock::time_point& time) {
  if (text.size() != 24 || text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
      text[16] != ':' || text[19] != '.' || text[23] != 'Z') {
    return false;
  }
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  int millis = 0;
  if (!detail::read_int(text.substr(0, 4), year) || !detail::read_int(text.substr(5, 2), month) ||
      !detail::read_int(text.substr(8, 2), day) || !detail::read_int(text.substr(11, 2), hour) ||
      !detail::read_int(text.substr(14, 2), minute) || !detail::read_int(text.substr(17, 2), second) ||
      !detail::read_int(text.substr(20, 3), millis)) {
    return false;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
    return false;
  }
  using namespace std::chrono;
  const year_month_day date{std::chrono::year{year}, std::chrono::month{static_cast<unsigned>(month)},
                             std::chrono::day{static_cast<unsigned>(day)}};
  if (!date.ok()) {
    return false;
  }
  time = sys_days{date} + hours{hour} + minutes{minute} + seconds{second} + milliseconds{millis};
  return true;
}

}  // namespace kernauth

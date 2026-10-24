#pragma once

#include "kernauth/client.hpp"
#include "kernauth/installation.hpp"
#include "kernauth/nonce.hpp"
#include "kernauth/payload.hpp"
#include "kernauth/session.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace kernauth {

constexpr std::uint64_t mix64(std::uint64_t value) {
  value += 0x9E3779B97F4A7C15ull;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

constexpr std::uint8_t stream_byte(std::uint64_t seed, std::size_t index) {
  const std::uint64_t mixed = mix64(seed + static_cast<std::uint64_t>(index) * 0xD1B54A32D192ED03ull);
  return static_cast<std::uint8_t>(mixed >> ((index & 7u) * 8u));
}

template <std::size_t Size, std::uint64_t Seed>
class ConcealedString {
 public:
  constexpr explicit ConcealedString(const char (&plain)[Size]) : bytes_{} {
    for (std::size_t index = 0; index < Size; ++index) {
      bytes_[index] = static_cast<char>(
          static_cast<unsigned char>(plain[index]) ^ stream_byte(Seed, index));
    }
  }

  std::string reveal() const {
    std::string out(Size == 0 ? 0 : Size - 1, '\0');
    for (std::size_t index = 0; index + 1 < Size; ++index) {
      out[index] = static_cast<char>(
          static_cast<unsigned char>(bytes_[index]) ^ stream_byte(Seed, index));
    }
    return out;
  }

  constexpr unsigned char stored(std::size_t index) const {
    return static_cast<unsigned char>(bytes_[index]);
  }

 private:
  char bytes_[Size];
};

constexpr std::uint64_t build_seed() {
  constexpr char stamp[] = __DATE__ " " __TIME__;
  std::uint64_t hash = 0x6B65726E61757468ull;
  for (const char character : stamp) {
    hash = mix64(hash ^ static_cast<unsigned char>(character));
  }
  return hash == 0 ? 0xA5A5A5A5A5A5A5A5ull : hash;
}

class App {
 public:
  App(
      std::string base_url,
      std::string public_app_id,
      std::string public_key_base64,
      std::string client_version = {})
      : owned_(std::make_unique<CurlTransport>()), transport_(owned_.get()) {
    options_.base_url = std::move(base_url);
    options_.public_app_id = std::move(public_app_id);
    options_.public_key_base64 = std::move(public_key_base64);
    if (!client_version.empty()) {
      options_.client_version = std::move(client_version);
    }
  }

  App(HttpTransport& transport, ClientOptions options)
      : transport_(&transport), options_(std::move(options)) {}

  App(const App&) = delete;
  App& operator=(const App&) = delete;
  App(App&&) noexcept = default;
  App& operator=(App&&) noexcept = default;

  ~App() {
    sodium_memzero(session_key_.data(), session_key_.size());
  }

  void set_installation(std::string installation_id, std::string label = "kernauth") {
    options_.installation_id = std::move(installation_id);
    options_.device_label = std::move(label);
    if (options_.device_fingerprint.empty()) {
      options_.device_fingerprint =
          derive_device_fingerprint(options_.fingerprint_version, options_.installation_id);
    }
  }

  void set_fingerprint(std::string fingerprint) {
    options_.device_fingerprint = std::move(fingerprint);
  }

  /**
   * Create a session salt from HWID material, ask the API for the UTC hour bucket,
   * and derive the AES session secret used to unwrap payload_box on validate.
   */
  ClientResult initialize() {
    if (const ClientResult* missing = ensure_installation()) {
      return *missing;
    }
    options_.session_salt = random_nonce();
    options_.time_bucket.clear();
    sodium_memzero(session_key_.data(), session_key_.size());
    session_ready_ = false;

    ClientResult result = initialize_session(*transport_, options_);
    if (!result.ok) {
      return finish(std::move(result));
    }

    session_key_ = derive_session_key(
        options_.public_app_id,
        options_.installation_id,
        options_.device_fingerprint,
        options_.time_bucket,
        options_.session_salt);
    session_ready_ = true;
    result.message = "Session ready";
    return finish(std::move(result));
  }

  ClientResult validate(std::string_view license_key) {
    if (const ClientResult* missing = ensure_installation()) {
      return *missing;
    }
    // Session fields are sent only after initialize(). Apps without a payload key
    // can validate without it; unwrap_payload() still requires a session.
    return finish(validate_license(*transport_, options_, license_key));
  }

  ClientResult heartbeat(std::string_view license_key) {
    if (const ClientResult* missing = ensure_installation()) {
      return *missing;
    }
    return finish(heartbeat_license(*transport_, options_, license_key));
  }

  /** Open payload_box from the last successful validate using the session secret. */
  PayloadUnwrap unwrap_payload() const {
    PayloadUnwrap out;
    if (!session_ready_) {
      out.message = "Call initialize first";
      return out;
    }
    if (!response.ok || response.entitlement.features.empty()) {
      out.message = "Validate first";
      return out;
    }
    return unwrap_payload_key(response.entitlement.features, session_key_);
  }

  bool session_ready() const {
    return session_ready_;
  }

  ClientResult response;

 private:
  const ClientResult* ensure_installation() {
    if (!options_.installation_id.empty()) {
      return nullptr;
    }
    const std::string installation = default_installation_id();
    if (installation.empty()) {
      ClientResult missing;
      missing.message = "Could not read the HWID";
      response = std::move(missing);
      return &response;
    }
    set_installation(installation, "desktop");
    return nullptr;
  }

  ClientResult finish(ClientResult result) {
    if (result.ok && result.message.empty()) {
      result.message = "License is active";
    }
    response = std::move(result);
    return response;
  }

  std::unique_ptr<CurlTransport> owned_;
  HttpTransport* transport_ = nullptr;
  ClientOptions options_;
  std::array<unsigned char, 32> session_key_{};
  bool session_ready_ = false;
};

}  // namespace kernauth

#define hide(literal)                                                                          \
  ([]() -> std::string {                                                                       \
    constexpr static auto concealed =                                                          \
        ::kernauth::ConcealedString<sizeof(literal), ::kernauth::build_seed()>(literal);      \
    return concealed.reveal();                                                                 \
  }())

#pragma once

#include "kernauth/canonical.hpp"
#include "kernauth/nonce.hpp"

#include <sodium.h>

#include <string>
#include <string_view>
#include <vector>

namespace kernauth {

enum class GrantFailure {
  None = 0,
  BadSignature,
  NonceMismatch,
  ApplicationMismatch,
  KeyMismatch,
  NotActive,
  Expired,
  Malformed,
};

struct GrantExpectation {
  std::string_view application_id;
  std::string_view key_id;
  std::string_view nonce;
  std::string_view now_iso;
};

struct GrantDecision {
  bool active = false;
  GrantFailure failure = GrantFailure::Malformed;
};

namespace detail {

inline bool decode_base64(std::string_view text, std::size_t expected, std::vector<unsigned char>& out) {
  out.assign(expected, 0);
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
  return decoded == expected;
}

inline bool expired_at(std::string_view expires_at, std::string_view now_iso) {
  std::chrono::system_clock::time_point expires;
  std::chrono::system_clock::time_point now;
  if (!parse_iso_utc(expires_at, expires) || !parse_iso_utc(now_iso, now)) {
    return true;
  }
  return expires <= now;
}

}  // namespace detail

/** Ed25519 verify over the exact canonical bytes. Uses libsodium. */
inline bool signature_valid(
    std::string_view public_key_base64,
    std::string_view message,
    std::string_view signature_base64) {
  try {
    detail::ensure_sodium();
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> signature;
    if (!detail::decode_base64(public_key_base64, crypto_sign_PUBLICKEYBYTES, public_key) ||
        !detail::decode_base64(signature_base64, crypto_sign_BYTES, signature)) {
      return false;
    }
    return crypto_sign_verify_detached(
               signature.data(),
               reinterpret_cast<const unsigned char*>(message.data()),
               message.size(),
               public_key.data()) == 0;
  } catch (const std::exception&) {
    return false;
  }
}

/**
 * An active grant requires a valid signature plus the application id, key id,
 * nonce, active status, and an expiry that is still after `now_iso`.
 */
inline GrantDecision decide_grant(
    const EntitlementFields& fields,
    std::string_view signature_base64,
    std::string_view public_key_base64,
    const GrantExpectation& expected) {
  GrantDecision decision;
  if (fields.protocol_version != kProtocolVersion || fields.entitlement_id.empty() ||
      fields.application_id.empty() || fields.license_id.empty() || fields.device_id.empty() ||
      fields.nonce.empty() || fields.key_id.empty()) {
    decision.failure = GrantFailure::Malformed;
    return decision;
  }
  if (fields.status != "active") {
    decision.failure = GrantFailure::NotActive;
    return decision;
  }
  if (detail::expired_at(fields.expires_at, expected.now_iso)) {
    decision.failure = GrantFailure::Expired;
    return decision;
  }
  if (fields.application_id != expected.application_id) {
    decision.failure = GrantFailure::ApplicationMismatch;
    return decision;
  }
  if (!expected.key_id.empty() && fields.key_id != expected.key_id) {
    decision.failure = GrantFailure::KeyMismatch;
    return decision;
  }
  if (fields.nonce != expected.nonce) {
    decision.failure = GrantFailure::NonceMismatch;
    return decision;
  }
  std::string message;
  try {
    message = encode_entitlement(fields);
  } catch (const CanonicalError&) {
    decision.failure = GrantFailure::Malformed;
    return decision;
  }
  if (!signature_valid(public_key_base64, message, signature_base64)) {
    decision.failure = GrantFailure::BadSignature;
    return decision;
  }
  decision.active = true;
  decision.failure = GrantFailure::None;
  return decision;
}

}  // namespace kernauth

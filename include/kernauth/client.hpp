#pragma once

#include "kernauth/canonical.hpp"
#include "kernauth/http.hpp"
#include "kernauth/nonce.hpp"
#include "kernauth/verify.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace kernauth {

struct ClientOptions {
  std::string base_url;
  std::string public_app_id;
  std::string public_key_base64;
  std::string key_id;
  std::string client_version = "0.4.0";
  int fingerprint_version = 1;
  std::string device_fingerprint;
  std::string installation_id;
  std::string device_label;
  /** From App.initialize() — required when the application has a payload key. */
  std::string session_salt;
  std::string time_bucket;
  std::function<std::string()> nonce_generator;
  std::function<std::string()> now_iso;
};

struct ClientResult {
  bool ok = false;
  bool active = false;
  int http_status = 0;
  std::string code;
  std::string message;
  std::string request_id;
  EntitlementFields entitlement;
  std::string signature_base64;
};

struct VersionInfo {
  bool ok = false;
  int http_status = 0;
  int protocol_version = 0;
  std::string key_id;
  std::string public_key_base64;
  std::string request_id;
  std::string code;
  std::string message;
};

namespace detail {

inline std::string join_url(std::string_view base_url, std::string_view path) {
  std::string url(base_url);
  while (!url.empty() && url.back() == '/') {
    url.pop_back();
  }
  url.append(path);
  return url;
}

inline std::string redact_key(std::string message, std::string_view license_key) {
  if (!license_key.empty() && message.find(license_key) != std::string::npos) {
    return "License validation failed";
  }
  return message;
}

inline ClientResult failure_result(int status, std::string code, std::string message) {
  ClientResult result;
  result.http_status = status;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

inline ClientResult post_entitlement(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key,
    std::string_view path) {
  if (options.base_url.empty() || options.public_app_id.empty() || options.device_fingerprint.empty() ||
      options.installation_id.empty()) {
    return failure_result(0, "invalid_request", "Client options are incomplete");
  }
  const std::string nonce = options.nonce_generator ? options.nonce_generator() : random_nonce();
  const std::string now_iso = options.now_iso ? options.now_iso() : utc_now_iso();
  nlohmann::json body = {
      {"protocol_version", kProtocolVersion},
      {"public_app_id", options.public_app_id},
      {"client_version", options.client_version},
      {"license_key", license_key},
      {"save_hwid", true},
      {"fingerprint_version", options.fingerprint_version},
      {"device_fingerprint", options.device_fingerprint},
      {"installation_id", options.installation_id},
      {"nonce", nonce},
  };
  if (!options.device_label.empty()) {
    body["device_label"] = options.device_label;
  }
  if (!options.session_salt.empty() && !options.time_bucket.empty()) {
    body["session_salt"] = options.session_salt;
    body["time_bucket"] = options.time_bucket;
  }

  HttpRequest request;
  request.method = "POST";
  request.url = join_url(options.base_url, path);
  request.body = body.dump();
  const HttpResponse response = transport.exchange(request);
  if (!response.transport_error.empty()) {
    return failure_result(0, "transport", "The license service could not be reached");
  }

  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(response.body);
  } catch (const nlohmann::json::exception&) {
    return failure_result(response.status, "malformed_response", "The license service returned invalid JSON");
  }

  if (response.status != 200) {
    std::string code = "license_invalid";
    std::string message = "License validation failed";
    if (parsed.contains("error") && parsed["error"].is_object()) {
      if (parsed["error"].contains("code") && parsed["error"]["code"].is_string()) {
        code = parsed["error"]["code"].get<std::string>();
      }
      if (parsed["error"].contains("message") && parsed["error"]["message"].is_string()) {
        message = redact_key(parsed["error"]["message"].get<std::string>(), license_key);
      }
    }
    auto result = failure_result(response.status, code, message);
    if (parsed.contains("error") && parsed["error"].contains("request_id") &&
        parsed["error"]["request_id"].is_string()) {
      result.request_id = parsed["error"]["request_id"].get<std::string>();
    }
    return result;
  }

  if (!parsed.contains("entitlement") || !parsed["entitlement"].is_object() || !parsed.contains("signature") ||
      !parsed["signature"].is_string()) {
    return failure_result(response.status, "malformed_response", "Entitlement response was incomplete");
  }
  const auto& entitlement = parsed["entitlement"];
  EntitlementFields fields;
  try {
    fields.protocol_version = entitlement.at("protocol_version").get<int>();
    fields.entitlement_id = entitlement.at("entitlement_id").get<std::string>();
    fields.application_id = entitlement.at("application_id").get<std::string>();
    fields.license_id = entitlement.at("license_id").get<std::string>();
    fields.status = entitlement.at("status").get<std::string>();
    fields.features = entitlement.at("features").dump();
    fields.device_id = entitlement.at("device_id").get<std::string>();
    fields.issued_at = entitlement.at("issued_at").get<std::string>();
    fields.expires_at = entitlement.at("expires_at").get<std::string>();
    fields.server_time = entitlement.at("server_time").get<std::string>();
    fields.nonce = entitlement.at("nonce").get<std::string>();
    fields.key_id = entitlement.at("key_id").get<std::string>();
  } catch (const nlohmann::json::exception&) {
    return failure_result(response.status, "malformed_response", "Entitlement fields were incomplete");
  }

  const std::string signature = parsed["signature"].get<std::string>();
  const GrantDecision decision = decide_grant(
      fields,
      signature,
      options.public_key_base64,
      GrantExpectation{
          .application_id = options.public_app_id,
          .key_id = options.key_id,
          .nonce = nonce,
          .now_iso = now_iso,
      });
  ClientResult result;
  result.http_status = response.status;
  result.entitlement = fields;
  result.signature_base64 = signature;
  if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
    result.request_id = parsed["request_id"].get<std::string>();
  }
  if (!decision.active) {
    result.code = "not_active";
    result.message = "Entitlement was not accepted";
    return result;
  }
  result.ok = true;
  result.active = true;
  result.code = "active";
  return result;
}

inline ClientResult post_heartbeat(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key) {
  if (options.base_url.empty() || options.public_app_id.empty() || options.device_fingerprint.empty() ||
      options.installation_id.empty()) {
    return failure_result(0, "invalid_request", "Client options are incomplete");
  }
  const std::string nonce = options.nonce_generator ? options.nonce_generator() : random_nonce();
  nlohmann::json body = {
      {"protocol_version", kProtocolVersion},
      {"public_app_id", options.public_app_id},
      {"client_version", options.client_version},
      {"license_key", license_key},
      {"fingerprint_version", options.fingerprint_version},
      {"device_fingerprint", options.device_fingerprint},
      {"installation_id", options.installation_id},
      {"nonce", nonce},
  };
  if (!options.device_label.empty()) {
    body["device_label"] = options.device_label;
  }
  HttpRequest request;
  request.method = "POST";
  request.url = join_url(options.base_url, "/v1/client/heartbeat");
  request.body = body.dump();
  const HttpResponse response = transport.exchange(request);
  if (!response.transport_error.empty()) {
    return failure_result(0, "transport", "The license service could not be reached");
  }
  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(response.body);
  } catch (const nlohmann::json::exception&) {
    return failure_result(response.status, "malformed_response", "The license service returned invalid JSON");
  }
  if (response.status != 200) {
    std::string code = "session_ended";
    std::string message = "Session ended";
    if (parsed.contains("error") && parsed["error"].is_object()) {
      if (parsed["error"].contains("code") && parsed["error"]["code"].is_string()) {
        code = parsed["error"]["code"].get<std::string>();
      }
      if (parsed["error"].contains("message") && parsed["error"]["message"].is_string()) {
        message = redact_key(parsed["error"]["message"].get<std::string>(), license_key);
      }
    }
    return failure_result(response.status, code, message);
  }
  if (!parsed.contains("ok") || parsed["ok"] != true) {
    return failure_result(response.status, "malformed_response", "Heartbeat response was incomplete");
  }
  ClientResult result;
  result.ok = true;
  result.active = true;
  result.http_status = response.status;
  result.code = "active";
  if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
    result.request_id = parsed["request_id"].get<std::string>();
  }
  return result;
}

}  // namespace detail

inline VersionInfo fetch_version(HttpTransport& transport, std::string_view base_url) {
  HttpRequest request;
  request.method = "GET";
  request.url = detail::join_url(base_url, "/v1/client/version");
  const HttpResponse response = transport.exchange(request);
  VersionInfo info;
  info.http_status = response.status;
  if (!response.transport_error.empty()) {
    info.code = "transport";
    info.message = "The license service could not be reached";
    return info;
  }
  try {
    const auto parsed = nlohmann::json::parse(response.body);
    if (response.status != 200) {
      info.code = "version_failed";
      info.message = "Version request failed";
      return info;
    }
    info.protocol_version = parsed.at("protocol_version").get<int>();
    info.key_id = parsed.at("key_id").get<std::string>();
    info.public_key_base64 = parsed.at("public_key").get<std::string>();
    if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
      info.request_id = parsed["request_id"].get<std::string>();
    }
    if (info.protocol_version != kProtocolVersion || info.key_id.empty() || info.public_key_base64.empty() ||
        parsed.contains("private_key")) {
      info.code = "malformed_response";
      info.message = "Version response was not usable";
      return info;
    }
    info.ok = true;
    info.code = "ok";
    return info;
  } catch (const nlohmann::json::exception&) {
    info.code = "malformed_response";
    info.message = "Version response was not JSON";
    return info;
  }
}

/**
 * POST /v1/client/initialize. Caller supplies session_salt; on success options.time_bucket
 * is filled from the server. Derive the AES session key with derive_session_key afterwards.
 */
inline ClientResult initialize_session(HttpTransport& transport, ClientOptions& options) {
  if (options.base_url.empty() || options.public_app_id.empty() || options.device_fingerprint.empty() ||
      options.installation_id.empty() || options.session_salt.empty()) {
    return detail::failure_result(0, "invalid_request", "Call initialize with a complete session");
  }
  const std::string nonce = options.nonce_generator ? options.nonce_generator() : random_nonce();
  nlohmann::json body = {
      {"protocol_version", kProtocolVersion},
      {"public_app_id", options.public_app_id},
      {"client_version", options.client_version},
      {"fingerprint_version", options.fingerprint_version},
      {"device_fingerprint", options.device_fingerprint},
      {"installation_id", options.installation_id},
      {"session_salt", options.session_salt},
      {"nonce", nonce},
  };
  HttpRequest request;
  request.method = "POST";
  request.url = detail::join_url(options.base_url, "/v1/client/initialize");
  request.body = body.dump();
  const HttpResponse response = transport.exchange(request);
  if (!response.transport_error.empty()) {
    return detail::failure_result(0, "transport", "The license service could not be reached");
  }
  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(response.body);
  } catch (const nlohmann::json::exception&) {
    return detail::failure_result(response.status, "malformed_response", "Initialize returned invalid JSON");
  }
  if (response.status != 200) {
    std::string code = "initialize_failed";
    std::string message = "Initialize failed";
    if (parsed.contains("error") && parsed["error"].is_object()) {
      if (parsed["error"].contains("code") && parsed["error"]["code"].is_string()) {
        code = parsed["error"]["code"].get<std::string>();
      }
      if (parsed["error"].contains("message") && parsed["error"]["message"].is_string()) {
        message = parsed["error"]["message"].get<std::string>();
      }
    }
    auto result = detail::failure_result(response.status, code, message);
    if (parsed.contains("error") && parsed["error"].contains("request_id") &&
        parsed["error"]["request_id"].is_string()) {
      result.request_id = parsed["error"]["request_id"].get<std::string>();
    }
    return result;
  }
  try {
    if (!parsed.value("ok", false) || !parsed.contains("time_bucket") || !parsed["time_bucket"].is_string()) {
      return detail::failure_result(response.status, "malformed_response", "Initialize response was incomplete");
    }
    options.time_bucket = parsed.at("time_bucket").get<std::string>();
    if (options.time_bucket.size() != 10) {
      return detail::failure_result(response.status, "malformed_response", "Invalid time_bucket");
    }
  } catch (const nlohmann::json::exception&) {
    return detail::failure_result(response.status, "malformed_response", "Initialize fields were incomplete");
  }
  ClientResult result;
  result.ok = true;
  result.active = true;
  result.http_status = response.status;
  result.code = "ok";
  result.message = "Session ready";
  if (parsed.contains("request_id") && parsed["request_id"].is_string()) {
    result.request_id = parsed["request_id"].get<std::string>();
  }
  return result;
}

inline ClientResult validate_license(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key) {
  return detail::post_entitlement(transport, options, license_key, "/v1/client/validate");
}

inline ClientResult heartbeat_license(
    HttpTransport& transport,
    const ClientOptions& options,
    std::string_view license_key) {
  return detail::post_heartbeat(transport, options, license_key);
}

}  // namespace kernauth

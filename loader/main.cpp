#include "kernauth.hpp"
#include "resource.h"
#include "../shared/payload_crypto.hpp"

#include <windows.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

using payload_run_fn = int (*)();
using payload_stop_fn = void (*)();

std::string trim(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

std::string license_key() {
  if (const char* env = std::getenv("KERN_LICENSE_KEY")) {
    const std::string value = trim(env);
    if (!value.empty()) {
      return value;
    }
  }
  std::cout << "Enter license: " << std::flush;
  std::string line;
  std::getline(std::cin, line);
  return trim(line);
}

void wipe(std::string& value) {
  if (!value.empty()) {
    sodium_memzero(value.data(), value.size());
  }
  value.clear();
}

bool load_resource(std::vector<unsigned char>& out) {
  const HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_PAYLOAD), RT_RCDATA);
  if (!res) {
    return false;
  }
  const HGLOBAL handle = LoadResource(nullptr, res);
  if (!handle) {
    return false;
  }
  const auto* data = static_cast<const unsigned char*>(LockResource(handle));
  const DWORD size = SizeofResource(nullptr, res);
  if (!data || !size) {
    return false;
  }
  out.assign(data, data + size);
  return true;
}

HMODULE write_and_load_dll(const std::vector<unsigned char>& bytes, std::wstring& path_out) {
  wchar_t temp_dir[MAX_PATH]{};
  wchar_t temp_file[MAX_PATH]{};
  if (!GetTempPathW(MAX_PATH, temp_dir)) {
    return nullptr;
  }
  if (!GetTempFileNameW(temp_dir, L"ka", 0, temp_file)) {
    return nullptr;
  }

  DeleteFileW(temp_file);
  std::wstring path(temp_file);
  const auto dot = path.find_last_of(L'.');
  if (dot != std::wstring::npos) {
    path.resize(dot);
  }
  path += L".dll";

  HANDLE file = CreateFileW(
      path.c_str(),
      GENERIC_WRITE,
      0,
      nullptr,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_TEMPORARY,
      nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return nullptr;
  }

  DWORD written = 0;
  const BOOL ok = WriteFile(
      file,
      bytes.data(),
      static_cast<DWORD>(bytes.size()),
      &written,
      nullptr);
  CloseHandle(file);
  if (!ok || written != bytes.size()) {
    DeleteFileW(path.c_str());
    return nullptr;
  }

  HMODULE module = LoadLibraryW(path.c_str());
  if (!module) {
    DeleteFileW(path.c_str());
    return nullptr;
  }

  path_out = std::move(path);
  return module;
}

}  // namespace

int main() {
  kernauth::App app(
      "https://api.kernauth.com",
      "__PUBLIC_APP_ID__",
      "__PUBLIC_KEY__");

  const kernauth::ClientResult init = app.initialize();
  if (!init.ok) {
    std::cout << init.message << "\n";
    return 1;
  }

  const std::string key = license_key();
  kernauth::ClientResult result = app.validate(key);
  if (!result.active) {
    std::cout << result.message << "\n";
    return 1;
  }

  kernauth::PayloadUnwrap unwrapped = app.unwrap_payload();
  wipe(result.entitlement.features);
  if (!unwrapped.ok) {
    std::cout << unwrapped.message << "\n";
    return 1;
  }

  unsigned char file_key[payload_crypto::key_size]{};
  if (!payload_crypto::derive_file_key(unwrapped.payload_key, file_key)) {
    wipe(unwrapped.payload_key);
    std::cout << "Could not derive file key\n";
    return 1;
  }
  wipe(unwrapped.payload_key);

  std::vector<unsigned char> sealed;
  if (!load_resource(sealed)) {
    sodium_memzero(file_key, sizeof(file_key));
    std::cout << "Missing sealed payload resource (build seal + loader)\n";
    return 1;
  }

  std::vector<unsigned char> plain;
  if (!payload_crypto::open(sealed.data(), sealed.size(), file_key, plain)) {
    sodium_memzero(file_key, sizeof(file_key));
    std::cout << "Payload decrypt failed (seal key must match dashboard Payload key)\n";
    return 1;
  }
  sodium_memzero(file_key, sizeof(file_key));

  std::wstring dll_path;
  HMODULE module = write_and_load_dll(plain, dll_path);
  sodium_memzero(plain.data(), plain.size());
  plain.clear();
  if (!module) {
    std::cout << "Failed to load payload DLL\n";
    return 1;
  }

  const auto run = reinterpret_cast<payload_run_fn>(GetProcAddress(module, "payload_run"));
  const auto stop = reinterpret_cast<payload_stop_fn>(GetProcAddress(module, "payload_stop"));
  if (!run || !stop) {
    FreeLibrary(module);
    DeleteFileW(dll_path.c_str());
    std::cout << "Payload exports missing\n";
    return 1;
  }

  std::cout << "Status: " << result.entitlement.status << "\n";
  std::cout << "License: " << result.entitlement.license_id << "\n";
  std::cout << "Check expires: " << result.entitlement.expires_at << "\n";
  std::cout << "Loading sealed payload...\n";

  std::thread heartbeat([&]() {
    for (;;) {
      std::this_thread::sleep_for(std::chrono::seconds(60));
      const kernauth::ClientResult beat = app.heartbeat(key);
      if (!beat.ok) {
        std::cout << beat.message << "\n";
        stop();
        return;
      }
    }
  });
  heartbeat.detach();

  const int code = run();
  FreeLibrary(module);
  DeleteFileW(dll_path.c_str());
  return code;
}

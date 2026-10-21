#include "../../shared/payload_crypto.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

static std::vector<unsigned char> read_file(const char* path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<unsigned char>(
      (std::istreambuf_iterator<char>(in)),
      std::istreambuf_iterator<char>());
}

static bool write_file(const char* path, const unsigned char* data, std::size_t size) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  return static_cast<bool>(out);
}

static std::string trim(std::string value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return {};
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

/** Same string as KernAuth dashboard → Application → Payload key. */
static std::string load_payload_key(const char* solution_dir) {
  if (const char* env = std::getenv("KERN_PAYLOAD_KEY")) {
    const std::string value = trim(env);
    if (!value.empty()) {
      return value;
    }
  }

  std::string path = solution_dir ? solution_dir : "";
  if (!path.empty() && path.back() != '\\' && path.back() != '/') {
    path.push_back('\\');
  }
  path += "shared\\seal_key.txt";
  std::ifstream in(path);
  if (!in) {
    return {};
  }
  std::string line;
  std::getline(in, line);
  return trim(line);
}

int main(int argc, char** argv) {
  if (argc != 4) {
    std::fprintf(stderr, "usage: seal <input.dll> <output.enc> <solution_dir>\n");
    return 1;
  }

  if (!payload_crypto::ready()) {
    std::fprintf(stderr, "sodium_init failed\n");
    return 1;
  }

  const std::string payload_key = load_payload_key(argv[3]);
  if (payload_key.empty()) {
    std::fprintf(
        stderr,
        "set KERN_PAYLOAD_KEY or create shared\\seal_key.txt (same as KernAuth Payload key)\n");
    return 1;
  }

  unsigned char file_key[payload_crypto::key_size]{};
  if (!payload_crypto::derive_file_key(payload_key, file_key)) {
    std::fprintf(stderr, "derive_file_key failed\n");
    return 1;
  }

  const auto plain = read_file(argv[1]);
  if (plain.empty()) {
    std::fprintf(stderr, "failed to read %s\n", argv[1]);
    return 1;
  }

  std::vector<unsigned char> out;
  if (!payload_crypto::seal(plain.data(), plain.size(), file_key, out)) {
    std::fprintf(stderr, "encrypt failed\n");
    return 1;
  }

  sodium_memzero(file_key, sizeof(file_key));

  if (!write_file(argv[2], out.data(), out.size())) {
    std::fprintf(stderr, "failed to write %s\n", argv[2]);
    return 1;
  }

  std::printf("sealed %zu bytes -> %s\n", plain.size(), argv[2]);
  return 0;
}

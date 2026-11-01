// Minimal SHA-256 (FIPS 180-4). No dependencies, no allocations.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sonekk {
namespace detail {

class Sha256 {
 public:
  Sha256();
  void update(const void* data, std::size_t length);
  // Returns 32 raw bytes.
  void finish(unsigned char out[32]);

 private:
  void transform(const unsigned char block[64]);

  std::uint32_t state_[8];
  std::uint64_t bit_length_;
  unsigned char buffer_[64];
  std::size_t buffer_length_;
};

}  // namespace detail

// Lowercase hex digest of the given bytes.
std::string sha256_hex(const void* data, std::size_t length);
std::string sha256_hex(const std::string& data);

}  // namespace sonekk

// Flat C API consumed by Unity through DllImport. No JNI, no Java layer.
#include <cstdlib>
#include <cstring>
#include <string>

#include "collect.h"
#include "sonekk_guard.h"

#if defined(_WIN32)
#define SG_EXPORT __declspec(dllexport)
#else
#define SG_EXPORT __attribute__((visibility("default")))
#endif

namespace {

constexpr const char* kVersion = "0.1.0";

// Reads a tiny JSON object of {"expectedSelfHash":"...","signatureOk":true}.
// A full parser would be overkill for three fields, but the scanner below still
// validates the shape so malformed input fails closed.
sonekk::CollectConfig parse_config(const char* json) {
  sonekk::CollectConfig config;
  if (json == nullptr) return config;

  const std::string text(json);
  const auto find_string = [&](const char* key) -> std::string {
    const std::string needle = std::string("\"") + key + "\"";
    const auto key_pos = text.find(needle);
    if (key_pos == std::string::npos) return {};
    const auto colon = text.find(':', key_pos + needle.size());
    if (colon == std::string::npos) return {};
    const auto quote = text.find('"', colon + 1);
    if (quote == std::string::npos) return {};
    const auto end = text.find('"', quote + 1);
    if (end == std::string::npos) return {};
    return text.substr(quote + 1, end - quote - 1);
  };

  config.expected_self_hash = find_string("expectedSelfHash");

  const auto sig_pos = text.find("\"signatureOk\"");
  if (sig_pos != std::string::npos) {
    const auto colon = text.find(':', sig_pos);
    if (colon != std::string::npos) {
      config.signature_ok = text.find("false", colon) != std::string::npos ? false : true;
    }
  }

  const auto debug_pos = text.find("\"debuggable\"");
  if (debug_pos != std::string::npos) {
    const auto colon = text.find(':', debug_pos);
    if (colon != std::string::npos) {
      config.app_debuggable = text.find("true", colon) != std::string::npos;
    }
  }
  return config;
}

}  // namespace

extern "C" {

// Returns a heap allocated JSON report. Free it with sonekk_guard_free.
SG_EXPORT const char* sonekk_guard_analyze(const char* config_json) {
  const sonekk::CollectConfig config = parse_config(config_json);
  const sonekk::Report report = sonekk::analyze(sonekk::collect(config));
  const std::string json = sonekk::to_json(report, kVersion);

  auto* buffer = static_cast<char*>(std::malloc(json.size() + 1));
  if (buffer == nullptr) return nullptr;
  std::memcpy(buffer, json.c_str(), json.size() + 1);
  return buffer;
}

SG_EXPORT void sonekk_guard_free(const char* pointer) {
  std::free(const_cast<char*>(pointer));
}

SG_EXPORT const char* sonekk_guard_version(void) { return kVersion; }

}  // extern "C"

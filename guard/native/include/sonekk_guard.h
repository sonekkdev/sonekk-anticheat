// Sonekk Guard - standalone Android VR anti-cheat core.
// Portable detection logic: no Android headers here so it can be unit tested on a desktop.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sonekk {

enum class Severity : int { Info = 1, Low = 2, Medium = 3, High = 4, Critical = 5 };

struct Finding {
  std::string id;
  Severity severity = Severity::Info;
  int weight = 0;
  std::string detail;
};

// Everything the collector can observe. Tests fill this in directly, the Android
// platform layer fills it from /proc and the filesystem.
struct Environment {
  std::string maps;                          // /proc/self/maps
  std::string status;                        // /proc/self/status
  std::string mounts;                        // /proc/self/mounts
  std::vector<std::string> existing_paths;   // root / hook artefact paths that exist
  std::vector<std::string> properties;       // "key=value" from android.os.Build / getprop
  std::vector<std::string> loaded_modules;   // dl_iterate_phdr names
  std::vector<std::string> thread_names;     // /proc/self/task/<tid>/comm
  bool app_debuggable = false;               // ApplicationInfo.FLAG_DEBUGGABLE
  bool frida_port_listening = false;         // loopback 27042 or a frida pipe name
  bool debugger_attached = false;            // platform level ptrace check
  bool signature_ok = true;                  // package signature equals the pinned value
  bool memory_text_checked = false;          // was the loaded .text compared against disk
  bool memory_text_ok = true;                // does the mapped text match the file on disk
  std::string expected_self_hash;            // sha256 of the pinned library, hex
  std::string actual_self_hash;              // sha256 measured at runtime, hex
  std::vector<std::pair<std::string, std::string>> hooked_symbols; // name, expected prologue hex vs actual
  std::vector<std::string> actual_prologues; // matching actual hex values, same order
};

struct Report {
  std::vector<Finding> findings;
  int score = 0;
  Severity highest = Severity::Info;

  // Client side hint only. The server recomputes the score and owns the decision.
  std::string verdict() const;
};

// Runs every check against the supplied environment.
Report analyze(const Environment& env);

// Deterministic scoring table shared with the server. Exposed for tests.
int weight_for(const std::string& id);

// JSON envelope posted to the server. Contains no device identifiers.
std::string to_json(const Report& report, const std::string& sdk_version);

std::string lowercase(std::string value);
bool contains_ci(const std::string& haystack, const std::string& needle);
std::string severity_name(Severity severity);

}  // namespace sonekk

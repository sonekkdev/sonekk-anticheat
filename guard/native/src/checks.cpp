#include "sonekk_guard.h"

#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <map>
#include <sstream>

namespace sonekk {
namespace {

const std::map<std::string, int>& weights() {
  static const std::map<std::string, int> table = {
      {"frida.maps", 90},        {"frida.module", 80},      {"frida.thread", 85},
      {"frida.port", 70},        {"emulator.host", 20},     {"app.debuggable", 15},
      {"frida.anon_exec", 25},   {"root.paths", 60},        {"root.mounts", 45},
      {"root.props", 35},        {"debug.tracer", 50},      {"integrity.self_hash", 95},
      {"integrity.symbol_hook", 95}, {"integrity.signature", 90},
      {"integrity.memory_text", 95}, {"instrumentation.inconsistent", 70}};
  return table;
}

Severity severity_for(const std::string& id) {
  if (id == "frida.maps" || id == "integrity.self_hash" || id == "integrity.symbol_hook" ||
      id == "integrity.memory_text") {
    return Severity::Critical;
  }
  if (id == "frida.module" || id == "frida.thread" || id == "frida.port" || id == "integrity.signature" ||
      id == "instrumentation.inconsistent" ||
      id == "root.paths" || id == "debug.tracer") {
    return Severity::High;
  }
  if (id == "root.mounts" || id == "root.props") return Severity::Medium;
  if (id == "frida.anon_exec" || id == "emulator.host" || id == "app.debuggable") return Severity::Low;
  return Severity::Info;
}

void add(Report& report, const std::string& id, const std::string& detail) {
  const auto it = std::find_if(report.findings.begin(), report.findings.end(),
                               [&](const Finding& f) { return f.id == id; });
  if (it != report.findings.end()) {
    if (it->detail.find(detail) == std::string::npos && it->detail.size() < 240) {
      it->detail += "; " + detail;
    }
    return;
  }

  Finding finding;
  finding.id = id;
  finding.severity = severity_for(id);
  finding.weight = weight_for(id);
  finding.detail = detail.size() > 200 ? detail.substr(0, 200) : detail;
  report.findings.push_back(finding);
}

std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::istringstream stream(text);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (!line.empty()) lines.push_back(line);
  }
  return lines;
}

// Maps lines look like: start-end perms offset dev inode path
bool map_line_is_executable(const std::string& line) {
  const auto first = line.find(' ');
  if (first == std::string::npos) return false;
  const auto second = line.find(' ', first + 1);
  if (second == std::string::npos) return false;
  const std::string perms = line.substr(first + 1, second - first - 1);
  return perms.find('x') != std::string::npos;
}

std::string map_line_path(const std::string& line) {
  // Fields: addr perms offset dev inode [path]
  std::size_t cursor = 0;
  for (int field = 0; field < 5; ++field) {
    cursor = line.find(' ', cursor);
    if (cursor == std::string::npos) return {};
    ++cursor;
  }
  const auto start = line.find_first_not_of(' ', cursor);
  if (start == std::string::npos) return {};
  return line.substr(start);
}

void check_maps(Report& report, const Environment& env) {
  static const char* kNeedles[] = {"frida", "gum-js", "linjector", "libsubstrate",
                                   "substrate", "xposed", "lsposed", "riru"};
  int anonymous_exec = 0;

  for (const std::string& line : split_lines(env.maps)) {
    const std::string lowered = lowercase(line);
    for (const char* needle : kNeedles) {
      if (lowered.find(needle) != std::string::npos) {
        add(report, "frida.maps", "mapping name matches " + std::string(needle));
        break;
      }
    }

    if (!map_line_is_executable(line)) continue;
    const std::string path = lowercase(map_line_path(line));
    if (path.empty() || path.front() == '[') {
      // ART's JIT cache, stacks, heaps and the vdso are normal. Everything else is not.
      if (path.find("jit") != std::string::npos) continue;
      if (path.find("dalvik") != std::string::npos) continue;
      if (path.find("scudo") != std::string::npos) continue;
      if (path.find("stack") != std::string::npos) continue;
      if (path.find("heap") != std::string::npos) continue;
      if (path.find("vdso") != std::string::npos) continue;
      if (path.find("vectors") != std::string::npos) continue;
      if (path.find("linker") != std::string::npos) continue;
      ++anonymous_exec;
    }
  }

  if (anonymous_exec > 0) {
    add(report, "frida.anon_exec",
        std::to_string(anonymous_exec) + " anonymous executable mapping(s)");
  }
}

void check_modules(Report& report, const Environment& env) {
  static const char* kNeedles[] = {"frida-agent", "frida-gadget", "libfrida", "gum-js",
                                   "libsubstrate", "libxposed"};
  for (const std::string& module : env.loaded_modules) {
    const std::string lowered = lowercase(module);
    for (const char* needle : kNeedles) {
      if (lowered.find(needle) != std::string::npos) {
        add(report, "frida.module", lowered);
        return;
      }
    }
  }
}

void check_threads(Report& report, const Environment& env) {
  // GumJS and Frida rename their worker threads. Deliberately narrow: gmain and
  // gdbus are also used by legitimate GLib consumers, so they are not matched.
  static const char* kNeedles[] = {"gum-js-loop", "gum-js", "frida"};
  for (const std::string& name : env.thread_names) {
    const std::string lowered = lowercase(name);
    for (const char* needle : kNeedles) {
      if (lowered.find(needle) != std::string::npos) {
        add(report, "frida.thread", lowered);
        return;
      }
    }
  }
}

void check_emulator(Report& report, const Environment& env) {
  for (const std::string& entry : env.properties) {
    const auto equals = entry.find('=');
    if (equals == std::string::npos) continue;
    const std::string key = lowercase(entry.substr(0, equals));
    const std::string value = lowercase(entry.substr(equals + 1));

    if (key == "ro.kernel.qemu" && value == "1") add(report, "emulator.host", "ro.kernel.qemu=1");
    if (key == "ro.hardware" &&
        (value == "goldfish" || value == "ranchu" || value.find("qemu") != std::string::npos)) {
      add(report, "emulator.host", "ro.hardware=" + value);
    }
  }
}

void check_app(Report& report, const Environment& env) {
  if (env.app_debuggable) add(report, "app.debuggable", "ApplicationInfo.FLAG_DEBUGGABLE set");
}

void check_status(Report& report, const Environment& env) {
  for (const std::string& line : split_lines(env.status)) {
    if (line.rfind("TracerPid:", 0) != 0) continue;
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    const std::string value = line.substr(colon + 1);
    const auto first = value.find_first_not_of(" \t");
    const int pid = first == std::string::npos ? 0 : std::atoi(value.c_str() + first);
    if (pid != 0) add(report, "debug.tracer", "TracerPid " + std::to_string(pid));
  }
  if (env.debugger_attached) add(report, "debug.tracer", "ptrace attach succeeded");
}

void check_mounts(Report& report, const Environment& env) {
  // Deliberately does not match "overlay": stock Android mounts /system that way.
  static const char* kNeedles[] = {"magisk", "kernelsu", "/data/adb", "apatch", "ksu"};
  for (const std::string& line : split_lines(env.mounts)) {
    const std::string lowered = lowercase(line);
    for (const char* needle : kNeedles) {
      if (lowered.find(needle) != std::string::npos) {
        add(report, "root.mounts", "mount entry contains " + std::string(needle));
        return;
      }
    }
  }
}

void check_paths(Report& report, const Environment& env) {
  if (env.existing_paths.empty()) return;
  std::string detail = env.existing_paths.front();
  for (std::size_t i = 1; i < env.existing_paths.size() && i < 4; ++i) {
    detail += ", " + env.existing_paths[i];
  }
  if (env.existing_paths.size() > 4) detail += ", ...";
  add(report, "root.paths", detail);
}

void check_properties(Report& report, const Environment& env) {
  for (const std::string& entry : env.properties) {
    const auto equals = entry.find('=');
    if (equals == std::string::npos) continue;
    const std::string key = lowercase(entry.substr(0, equals));
    const std::string value = lowercase(entry.substr(equals + 1));

    if (key == "ro.debuggable" && value == "1") add(report, "root.props", "ro.debuggable=1");
    if (key == "ro.secure" && value == "0") add(report, "root.props", "ro.secure=0");
    if (key == "ro.build.tags" && value.find("test-keys") != std::string::npos) {
      add(report, "root.props", "ro.build.tags=test-keys");
    }
    if (key == "ro.boot.verifiedbootstate" && value != "green") {
      add(report, "root.props", "verifiedbootstate=" + value);
    }
    if (key == "ro.boot.flash.locked" && value == "0") {
      add(report, "root.props", "flash.locked=0");
    }
  }
}

void check_memory_text(Report& report, const Environment& env) {
  if (!env.memory_text_checked) return;
  if (!env.memory_text_ok) {
    add(report, "integrity.memory_text", "mapped code differs from the file on disk");
  }
}

// A library that is loaded but absent from /proc/self/maps means one of the two
// views was tampered with. This catches naive open/read hooks that sanitise maps.
void check_instrumentation(Report& report, const Environment& env) {
  if (env.loaded_modules.empty() || env.maps.empty()) return;
  const std::string maps = lowercase(env.maps);
  int missing = 0;
  std::string example;

  for (const std::string& path : env.loaded_modules) {
    const std::string lowered = lowercase(path);
    if (lowered.size() < 4 || lowered.compare(lowered.size() - 3, 3, ".so") != 0) continue;
    const auto slash = lowered.find_last_of('/');
    const std::string base = slash == std::string::npos ? lowered : lowered.substr(slash + 1);
    if (base.empty()) continue;
    if (maps.find(base) == std::string::npos) {
      if (missing == 0) example = base;
      ++missing;
    }
  }

  if (missing > 0) {
    add(report, "instrumentation.inconsistent",
        std::to_string(missing) + " loaded module(s) missing from maps, e.g. " + example);
  }
}

void check_integrity(Report& report, const Environment& env) {
  if (!env.expected_self_hash.empty() && !env.actual_self_hash.empty() &&
      lowercase(env.expected_self_hash) != lowercase(env.actual_self_hash)) {
    add(report, "integrity.self_hash", "library hash mismatch");
  }

  const std::size_t pairs =
      std::min(env.hooked_symbols.size(), env.actual_prologues.size());
  for (std::size_t i = 0; i < pairs; ++i) {
    if (lowercase(env.hooked_symbols[i].second) != lowercase(env.actual_prologues[i])) {
      add(report, "integrity.symbol_hook",
          "prologue changed for " + env.hooked_symbols[i].first);
      break;
    }
  }

  if (!env.signature_ok) add(report, "integrity.signature", "package signature mismatch");
}

}  // namespace

int weight_for(const std::string& id) {
  const auto it = weights().find(id);
  return it == weights().end() ? 0 : it->second;
}

std::string lowercase(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
  return lowercase(haystack).find(lowercase(needle)) != std::string::npos;
}

std::string severity_name(Severity severity) {
  switch (severity) {
    case Severity::Critical:
      return "critical";
    case Severity::High:
      return "high";
    case Severity::Medium:
      return "medium";
    case Severity::Low:
      return "low";
    default:
      return "info";
  }
}

Report analyze(const Environment& env) {
  Report report;
  check_maps(report, env);
  check_modules(report, env);
  check_threads(report, env);
  check_status(report, env);
  check_mounts(report, env);
  check_paths(report, env);
  check_properties(report, env);
  check_emulator(report, env);
  check_app(report, env);
  check_integrity(report, env);
  check_memory_text(report, env);
  check_instrumentation(report, env);

  for (const Finding& finding : report.findings) {
    report.score += finding.weight;
    if (static_cast<int>(finding.severity) > static_cast<int>(report.highest)) {
      report.highest = finding.severity;
    }
  }
  return report;
}

std::string Report::verdict() const {
  if (score >= 70) return "block";
  if (score >= 40) return "flag";
  if (score >= 15) return "watch";
  return "clean";
}

namespace {

std::string json_escape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += ' ';
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

}  // namespace

std::string to_json(const Report& report, const std::string& sdk_version) {
  std::ostringstream out;
  out << "{\"v\":1,\"sdk\":\"" << json_escape(sdk_version) << "\",\"score\":" << report.score
      << ",\"verdict\":\"" << report.verdict() << "\",\"findings\":[";

  for (std::size_t i = 0; i < report.findings.size(); ++i) {
    const Finding& finding = report.findings[i];
    if (i != 0) out << ',';
    out << "{\"id\":\"" << json_escape(finding.id) << "\",\"sev\":\""
        << severity_name(finding.severity) << "\",\"w\":" << finding.weight
        << ",\"d\":\"" << json_escape(finding.detail) << "\"}";
  }

  out << "]}";
  return out.str();
}

}  // namespace sonekk

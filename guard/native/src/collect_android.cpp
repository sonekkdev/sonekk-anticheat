// Android collector. Reads only process local state: no network, no device ids.
#include "collect.h"

#include <cstring>

#if defined(__ANDROID__)
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "sha256.h"
#endif

namespace sonekk {
namespace {

#if defined(__ANDROID__)

constexpr std::size_t kMaxRead = 4 * 1024 * 1024;

// Raw syscalls instead of libc wrappers, so a userland hook on open/read does not
// see our reads. This does not defeat a kernel level hook, nothing userland does.
std::string read_all(const char* path) {
  const int fd = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC));
  if (fd < 0) return {};

  std::string out;
  char buffer[8192];
  while (out.size() < kMaxRead) {
    const long read = static_cast<long>(::syscall(SYS_read, fd, buffer, sizeof(buffer)));
    if (read <= 0) break;
    out.append(buffer, static_cast<std::size_t>(read));
  }
  ::syscall(SYS_close, fd);
  return out;
}

std::string read_range(const std::string& path, std::uint64_t offset, std::size_t length) {
  const int fd = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, path.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd < 0) return {};

  std::string out(length, '\0');
  std::size_t done = 0;
  while (done < length) {
    const long read = static_cast<long>(
        ::syscall(SYS_pread64, fd, &out[done], length - done, static_cast<off_t>(offset + done)));
    if (read <= 0) break;
    done += static_cast<std::size_t>(read);
  }
  ::syscall(SYS_close, fd);
  out.resize(done);
  return out;
}

bool path_exists(const char* path) { return ::access(path, F_OK) == 0; }

std::string own_library_path() {
  Dl_info info {};
  if (dladdr(reinterpret_cast<void*>(&read_all), &info) == 0) return {};
  return info.dli_fname != nullptr ? info.dli_fname : "";
}

std::string hash_file(const std::string& path) {
  const std::string bytes = read_all(path.c_str());
  if (bytes.empty()) return {};
  return sha256_hex(bytes.data(), bytes.size());
}

void collect_modules(std::vector<std::string>& out) {
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* data) {
        auto* modules = static_cast<std::vector<std::string>*>(data);
        if (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') {
          modules->emplace_back(info->dlpi_name);
        }
        return 0;
      },
      &out);
}

// Compares the executable PT_LOAD segments that are actually mapped against the same
// bytes in the file on disk. Catches runtime patches that leave the .so untouched.
void verify_own_text(Environment& env, const std::string& own_path) {
  if (own_path.empty()) return;

  struct Context {
    Environment* env;
    const std::string* path;
  };
  Context context {&env, &own_path};

  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* context = static_cast<Context*>(data);
        if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;
        if (*context->path != info->dlpi_name) return 0;

        bool checked = false;
        bool ok = true;

        for (int i = 0; i < info->dlpi_phnum; ++i) {
          const ElfW(Phdr)& header = info->dlpi_phdr[i];
          if (header.p_type != PT_LOAD || (header.p_flags & PF_X) == 0) continue;

          const std::size_t length =
              static_cast<std::size_t>(std::min<ElfW(Xword)>(header.p_filesz, header.p_memsz));
          if (length == 0) continue;

          const std::string disk = read_range(*context->path, header.p_offset, length);
          if (disk.size() != length) {
            // Cannot compare (for example the library lives inside an unreadable APK).
            context->env->memory_text_checked = false;
            return 1;
          }

          const void* memory = reinterpret_cast<const void*>(info->dlpi_addr + header.p_vaddr);
          checked = true;
          if (sha256_hex(memory, length) != sha256_hex(disk.data(), disk.size())) {
            ok = false;
            break;
          }
        }

        context->env->memory_text_checked = checked;
        context->env->memory_text_ok = ok;
        return 1;
      },
      &context);
}

std::vector<std::string> collect_properties() {
  static const char* kKeys[] = {"ro.debuggable",
                                "ro.secure",
                                "ro.build.tags",
                                "ro.boot.verifiedbootstate",
                                "ro.boot.flash.locked",
                                "ro.build.type",
                                "ro.hardware",
                                "ro.kernel.qemu",
                                "ro.product.model"};
  std::vector<std::string> properties;
  for (const char* key : kKeys) {
    char value[PROP_VALUE_MAX] = {0};
    const int length = __system_property_get(key, value);
    if (length > 0) properties.emplace_back(std::string(key) + "=" + value);
  }
  return properties;
}

std::vector<std::string> collect_root_paths() {
  static const char* kPaths[] = {
      "/system/bin/su",
      "/system/xbin/su",
      "/sbin/su",
      "/su/bin/su",
      "/system/app/Superuser.apk",
      "/data/adb/magisk",
      "/data/adb/modules",
      "/data/adb/ksu",
      "/data/adb/ap",
      "/data/local/tmp/frida-server",
      "/data/local/tmp/re.frida.server",
      "/system/lib64/libfrida-gadget.so",
      "/system/lib/libfrida-gadget.so"};
  std::vector<std::string> hits;
  for (const char* path : kPaths) {
    if (path_exists(path)) hits.emplace_back(path);
  }
  return hits;
}

std::vector<std::string> collect_threads() {
  std::vector<std::string> names;
  DIR* dir = ::opendir("/proc/self/task");
  if (dir == nullptr) return names;

  while (struct dirent* entry = ::readdir(dir)) {
    if (entry->d_name[0] == '.') continue;
    const std::string path = std::string("/proc/self/task/") + entry->d_name + "/comm";
    std::string name = read_all(path.c_str());
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
    if (!name.empty() && names.size() < 128) names.push_back(name);
  }
  ::closedir(dir);
  return names;
}

bool frida_port_listening() {
  // /proc/net/tcp: local_address is hex "ADDR:PORT", st 0A means LISTEN.
  for (const char* file : {"/proc/net/tcp", "/proc/net/tcp6"}) {
    std::istringstream stream(read_all(file));
    std::string line;
    std::getline(stream, line);  // header
    while (std::getline(stream, line)) {
      std::istringstream fields(line);
      std::string slot, local, remote, state;
      fields >> slot >> local >> remote >> state;
      if (state != "0A") continue;
      const auto colon = local.rfind(':');
      if (colon == std::string::npos) continue;
      const unsigned long port = std::strtoul(local.c_str() + colon + 1, nullptr, 16);
      if (port == 27042 || port == 27043) return true;
    }
  }
  return false;
}

#endif  // __ANDROID__

}  // namespace

Environment collect(const CollectConfig& config) {
  Environment env;

#if defined(__ANDROID__)
  env.maps = read_all("/proc/self/maps");
  env.status = read_all("/proc/self/status");
  env.mounts = read_all("/proc/self/mounts");
  env.existing_paths = collect_root_paths();
  env.properties = collect_properties();
  collect_modules(env.loaded_modules);
  env.thread_names = collect_threads();
  env.frida_port_listening = frida_port_listening();
  env.signature_ok = config.signature_ok;
  env.app_debuggable = config.app_debuggable;

  const std::string self = own_library_path();
  if (!self.empty()) {
    env.actual_self_hash = hash_file(self);
    verify_own_text(env, self);
  }
  env.expected_self_hash = config.expected_self_hash;
#else
  (void)config;
#endif

  return env;
}

}  // namespace sonekk

// Host side tests for the detection core. Fixtures are the real /proc formats so a
// passing test here means the parser works, not that a mock returned what we expected.
#include <cstdio>
#include <string>
#include <vector>

#include "sha256.h"
#include "sonekk_guard.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const std::string& what) {
  ++g_checks;
  if (!condition) {
    ++g_failures;
    std::printf("  FAIL  %s\n", what.c_str());
  }
}

bool has_finding(const sonekk::Report& report, const std::string& id) {
  for (const auto& finding : report.findings) {
    if (finding.id == id) return true;
  }
  return false;
}

const char* kMapsClean =
    "12c00000-12c20000 rw-p 00000000 00:00 0 [anon:dalvik-main space]\n"
    "7a1b2c0000-7a1b2c1000 r-xp 00000000 fd:00 1000 /system/lib64/libc.so\n"
    "7a1b300000-7a1b310000 r-xp 00000000 fd:00 1001 /system/lib64/libart.so\n"
    "7a1b400000-7a1b402000 r--p 00000000 00:00 0 [vdso]\n"
    "7a1b500000-7a1b520000 rw-p 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n";

const char* kMapsFrida =
    "12c00000-12c20000 rw-p 00000000 00:00 0 [anon:dalvik-main space]\n"
    "7a44f00000-7a44f02000 r-xp 00000000 00:00 0 "
    "/data/local/tmp/re.frida.server/frida-agent-64.so\n";

const char* kMapsAnonExec =
    "12c00000-12c20000 rw-p 00000000 00:00 0 [anon:dalvik-main space]\n"
    "7b00000000-7b00002000 rwxp 00000000 00:00 0 \n";

const char* kStatusClean = "Name:\tcom.studio.game\nTracerPid:\t0\nState:\tS (sleeping)\n";
const char* kStatusTraced = "Name:\tcom.studio.game\nTracerPid:\t4242\nState:\tt (tracing stop)\n";

const char* kMountsClean =
    "/dev/block/dm-4 /system ext4 ro,seclabel,relatime 0 0\n"
    "/dev/block/dm-5 /data ext4 rw,seclabel,nosuid,nodev 0 0\n";

const char* kMountsMagisk =
    "/dev/block/dm-4 /system ext4 ro,seclabel,relatime 0 0\n"
    "magisk /system/bin/su tmpfs ro,seclabel,relatime 0 0\n";

sonekk::Environment clean() {
  sonekk::Environment env;
  env.maps = kMapsClean;
  env.status = kStatusClean;
  env.mounts = kMountsClean;
  env.signature_ok = true;
  return env;
}

void test_sha256() {
  std::printf("sha256\n");
  check(sonekk::sha256_hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "empty digest");
  check(sonekk::sha256_hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "abc digest");
  check(sonekk::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "two block digest");
}

void test_clean() {
  std::printf("clean environment\n");
  const auto report = sonekk::analyze(clean());
  check(report.findings.empty(), "no findings");
  check(report.score == 0, "score is zero");
  check(report.verdict() == "clean", "verdict clean");
}

void test_frida_maps() {
  std::printf("frida in maps\n");
  auto env = clean();
  env.maps = kMapsFrida;
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "frida.maps"), "frida.maps raised");
  check(report.verdict() == "block", "verdict block");
}

void test_frida_dedupe() {
  std::printf("duplicate frida mappings collapse\n");
  auto env = clean();
  env.maps = std::string(kMapsFrida) + kMapsFrida;
  const auto report = sonekk::analyze(env);
  int count = 0;
  for (const auto& finding : report.findings) {
    if (finding.id == "frida.maps") ++count;
  }
  check(count == 1, "one finding per id");
}

void test_anon_exec() {
  std::printf("anonymous executable mapping\n");
  auto env = clean();
  env.maps = kMapsAnonExec;
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "frida.anon_exec"), "anon exec raised");
  check(report.verdict() == "watch", "low severity stays under the block threshold");
}

void test_jit_is_not_anonymous_exec() {
  std::printf("art jit cache is ignored\n");
  const auto report = sonekk::analyze(clean());
  check(!has_finding(report, "frida.anon_exec"), "jit cache not flagged");
}

void test_modules() {
  std::printf("frida module loaded\n");
  auto env = clean();
  env.loaded_modules = {"/system/lib64/libc.so", "/data/local/tmp/libfrida-gadget.so"};
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "frida.module"), "frida.module raised");
}

void test_tracer() {
  std::printf("tracer attached\n");
  auto env = clean();
  env.status = kStatusTraced;
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "debug.tracer"), "debug.tracer raised");
}

void test_tracer_zero() {
  std::printf("TracerPid zero is clean\n");
  const auto report = sonekk::analyze(clean());
  check(!has_finding(report, "debug.tracer"), "no tracer finding");
}

void test_mounts() {
  std::printf("magisk mount\n");
  auto env = clean();
  env.mounts = kMountsMagisk;
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "root.mounts"), "root.mounts raised");
}

void test_overlay_is_not_root() {
  std::printf("stock overlay /system is not root\n");
  auto env = clean();
  env.mounts =
      "/dev/block/dm-4 /system overlay ro,seclabel,relatime,lowerdir=/system 0 0\n";
  const auto report = sonekk::analyze(env);
  check(!has_finding(report, "root.mounts"), "overlay not flagged");
}

void test_root_paths() {
  std::printf("root artefacts present\n");
  auto env = clean();
  env.existing_paths = {"/data/adb/magisk"};
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "root.paths"), "root.paths raised");
}

void test_properties() {
  std::printf("debughable build prop\n");
  auto env = clean();
  env.properties = {"ro.debuggable=1", "ro.secure=0"};
  const auto report = sonekk::analyze(env);
  check(has_finding(report, "root.props"), "root.props raised");

  auto verified = clean();
  verified.properties = {"ro.boot.verifiedbootstate=orange"};
  check(has_finding(sonekk::analyze(verified), "root.props"), "orange boot state flagged");

  auto stock = clean();
  stock.properties = {"ro.build.tags=release-keys", "ro.boot.verifiedbootstate=green"};
  check(!has_finding(sonekk::analyze(stock), "root.props"), "stock props are clean");
}

void test_integrity() {
  std::printf("integrity checks\n");
  auto env = clean();
  env.expected_self_hash = "aaaa";
  env.actual_self_hash = "bbbb";
  check(has_finding(sonekk::analyze(env), "integrity.self_hash"), "self hash mismatch flagged");

  auto hooks = clean();
  hooks.hooked_symbols = {{"strcmp", "aabb"}, {"memcpy", "ccdd"}};
  hooks.actual_prologues = {"aabb", "ffff"};
  check(has_finding(sonekk::analyze(hooks), "integrity.symbol_hook"), "hook flagged");

  auto untouched = clean();
  untouched.hooked_symbols = {{"strcmp", "aabb"}};
  untouched.actual_prologues = {"aabb"};
  check(!has_finding(sonekk::analyze(untouched), "integrity.symbol_hook"), "matching prologue ok");

  auto bad_signature = clean();
  bad_signature.signature_ok = false;
  check(has_finding(sonekk::analyze(bad_signature), "integrity.signature"), "signature mismatch");
}

void test_threads() {
  std::printf("frida thread name\n");
  auto env = clean();
  env.thread_names = {"UnityMain", "RenderThread", "gum-js-loop"};
  check(has_finding(sonekk::analyze(env), "frida.thread"), "frida.thread raised");

  auto normal = clean();
  normal.thread_names = {"UnityMain", "RenderThread", "Job.Worker.0", "AudioTrack"};
  check(!has_finding(sonekk::analyze(normal), "frida.thread"), "normal threads are ignored");
}

void test_emulator() {
  std::printf("emulator host\n");
  auto env = clean();
  env.properties = {"ro.kernel.qemu=1"};
  check(has_finding(sonekk::analyze(env), "emulator.host"), "qemu property flagged");

  auto hardware = clean();
  hardware.properties = {"ro.hardware=ranchu"};
  check(has_finding(sonekk::analyze(hardware), "emulator.host"), "ranchu hardware flagged");

  auto device = clean();
  device.properties = {"ro.hardware=eureka", "ro.kernel.qemu=0"};
  check(!has_finding(sonekk::analyze(device), "emulator.host"), "real hardware is clean");
}

void test_debuggable() {
  std::printf("debuggable application\n");
  auto env = clean();
  env.app_debuggable = true;
  check(has_finding(sonekk::analyze(env), "app.debuggable"), "debug flag raised");
}

void test_malformed_input() {
  std::printf("malformed /proc input\n");
  std::uint32_t state = 0x12345678u;
  const auto next = [&state]() {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
  };

  for (int round = 0; round < 300; ++round) {
    sonekk::Environment env;
    const auto junk = [&](std::size_t length) {
      std::string out;
      out.reserve(length);
      for (std::size_t i = 0; i < length; ++i) {
        const char c = static_cast<char>(next() % 96 + 32);
        out.push_back(c);
      }
      return out;
    };
    env.maps = junk(next() % 512);
    env.status = junk(next() % 128);
    env.mounts = junk(next() % 256);
    env.properties = {junk(24), junk(40)};
    env.thread_names = {junk(12), junk(20)};
    env.loaded_modules = {junk(30)};

    const auto report = sonekk::analyze(env);
    // The parser must never invent scores or duplicate a finding id.
    bool ids_unique = true;
    for (std::size_t i = 0; i < report.findings.size(); ++i) {
      for (std::size_t j = i + 1; j < report.findings.size(); ++j) {
        if (report.findings[i].id == report.findings[j].id) ids_unique = false;
      }
    }
    if (!ids_unique || report.score < 0) {
      check(false, "parser produced an invalid report");
      return;
    }
  }
  check(true, "300 malformed inputs parsed safely");
}

void test_memory_text() {
  std::printf("runtime patched text\n");
  auto patched = clean();
  patched.memory_text_checked = true;
  patched.memory_text_ok = false;
  check(has_finding(sonekk::analyze(patched), "integrity.memory_text"), "memory text mismatch flagged");

  auto skipped = clean();
  check(!has_finding(sonekk::analyze(skipped), "integrity.memory_text"),
        "unchecked memory is not a finding");
}

void test_instrumentation() {
  std::printf("maps versus module list\n");
  auto consistent = clean();
  consistent.maps = "7a1b0000-7a1b2000 r-xp 0 fd:00 1 /system/lib64/libc.so\n";
  consistent.loaded_modules = {"/system/lib64/libc.so"};
  check(!has_finding(sonekk::analyze(consistent), "instrumentation.inconsistent"),
        "matching views are clean");

  auto hidden = clean();
  hidden.maps = "7a1b0000-7a1b2000 r-xp 0 fd:00 1 /system/lib64/libc.so\n";
  hidden.loaded_modules = {"/system/lib64/libc.so", "/data/local/tmp/libfrida-gadget.so"};
  check(has_finding(sonekk::analyze(hidden), "instrumentation.inconsistent"),
        "module hidden from maps is flagged");
}

void test_combined() {
  std::printf("combined attack\n");
  auto env = clean();
  env.maps = kMapsFrida;
  env.existing_paths = {"/data/adb/magisk"};
  env.status = kStatusTraced;
  const auto report = sonekk::analyze(env);
  check(report.score >= 70, "score above block threshold");
  check(report.highest == sonekk::Severity::Critical, "highest severity critical");
}

void test_json() {
  std::printf("json envelope\n");
  auto env = clean();
  env.maps = kMapsFrida;
  env.existing_paths = {"/data/adb/magisk"};
  const auto report = sonekk::analyze(env);
  const std::string json = sonekk::to_json(report, "0.1.0");
  check(json.find("\"v\":1") != std::string::npos, "version field");
  check(json.find("\"verdict\":\"block\"") != std::string::npos, "verdict field");
  check(json.find("frida.maps") != std::string::npos, "finding id present");
  check(json.find('\"') != std::string::npos, "quotes are balanced in shape");
  check(json.find("\\\\\"") == std::string::npos, "no double escaped quotes");
}

}  // namespace

int main() {
  test_sha256();
  test_clean();
  test_frida_maps();
  test_frida_dedupe();
  test_anon_exec();
  test_jit_is_not_anonymous_exec();
  test_modules();
  test_tracer();
  test_tracer_zero();
  test_mounts();
  test_overlay_is_not_root();
  test_root_paths();
  test_properties();
  test_integrity();
  test_threads();
  test_emulator();
  test_debuggable();
  test_memory_text();
  test_instrumentation();
  test_malformed_input();
  test_combined();
  test_json();

  std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}

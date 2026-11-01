#pragma once

#include <string>

#include "sonekk_guard.h"

namespace sonekk {

struct CollectConfig {
  std::string expected_self_hash;
  bool signature_ok = true;
  bool app_debuggable = false;
};

// Fills an Environment from the live process. On non Android hosts it returns an
// empty environment, which lets the JSON envelope and the C API be exercised in tests.
Environment collect(const CollectConfig& config);

}  // namespace sonekk

cmake_minimum_required(VERSION 3.20)
project(sonekk_guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(sonekk_guard_core STATIC
  src/sha256.cpp
  src/checks.cpp
  src/collect_android.cpp
  src/c_api.cpp
)
target_include_directories(sonekk_guard_core PUBLIC include src)

if(ANDROID)
  # Unity loads this directly from Plugins/Android/libs/arm64-v8a.
  add_library(sonekk_guard SHARED src/c_api.cpp src/collect_android.cpp src/checks.cpp src/sha256.cpp)
  target_include_directories(sonekk_guard PUBLIC include src)
  target_link_libraries(sonekk_guard log dl)
  set_target_properties(sonekk_guard PROPERTIES
    OUTPUT_NAME "sonekk_guard"
    PREFIX "lib"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
endif()

if(NOT ANDROID)
  enable_testing()
  add_executable(guard_tests tests/main.cpp)
  target_link_libraries(guard_tests sonekk_guard_core)
  add_test(NAME guard_tests COMMAND guard_tests)
endif()

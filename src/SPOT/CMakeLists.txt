add_library(SPOT-Patching STATIC
    patching.cpp
)

target_include_directories(SPOT-Patching PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
add_subdirectory(utils)
add_subdirectory(OT)
add_subdirectory(Millionaire)
add_subdirectory(NonLinear)
add_subdirectory(LinearHE)
add_subdirectory(SPOT)

add_library(OCEAN-Protocols INTERFACE)

target_link_libraries(OCEAN-Protocols
    INTERFACE
    SCI-OT
    SCI-NonLinear
    OCEAN-LinearHE
    SPOT-Patching
)

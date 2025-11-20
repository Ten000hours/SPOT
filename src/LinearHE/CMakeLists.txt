find_package(SEAL 3.3.2 EXACT REQUIRED)
find_package(OpenMP REQUIRED)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)

add_library(OCEAN-LinearHE
    conv-field.cpp
    utils-HE.cpp
)

target_link_libraries(OCEAN-LinearHE
    PRIVATE
    SCI-utils
    OpenMP::OpenMP_CXX
    PUBLIC
    SEAL::seal
    Eigen3::Eigen
)

get_target_property(SEAL_INCLUDES SEAL::seal INTERFACE_INCLUDE_DIRECTORIES)
if(SEAL_INCLUDES)
  target_include_directories(OCEAN-LinearHE PRIVATE ${SEAL_INCLUDES})
endif()

# Derive include dir from SEAL_DIR if needed
if(DEFINED SEAL_DIR)
  # SEAL_DIR typically points to <install>/lib/cmake/SEAL
  get_filename_component(SEAL_INSTALL_DIR "${SEAL_DIR}/../../.." ABSOLUTE)
  set(SEAL_INCLUDE_DIR "${SEAL_INSTALL_DIR}/include")
  if(EXISTS "${SEAL_INCLUDE_DIR}/seal/seal.h")
    target_include_directories(OCEAN-LinearHE PRIVATE "${SEAL_INCLUDE_DIR}")
  endif()
endif()

# Fallback: user-provided SEAL install include path
target_include_directories(OCEAN-LinearHE PRIVATE /cis/home/zwang/yuanzhong/SEAL/native/build/install/include)



if(!APPLE)
    target_compile_options(OCEAN-LinearHE PRIVATE "-fopenmp")
endif()
target_compile_options(OCEAN-LinearHE PUBLIC "-fpermissive")

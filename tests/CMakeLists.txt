set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

macro (add_test _name)
	add_executable(${_name} "test_${_name}.cpp")
    target_link_libraries(${_name} OCEAN-Protocols) 
endmacro()

# Tests
add_test(relu)
add_test(conv)
add_test(reluconv)
add_test(spot)
add_executable(spot_plan "test_spot_plan.cpp")
target_link_libraries(spot_plan SPOT-Patching)
add_executable(spot_minconvrelu "test_spot_minconvrelu.cpp")
target_link_libraries(spot_minconvrelu OCEAN-Protocols)
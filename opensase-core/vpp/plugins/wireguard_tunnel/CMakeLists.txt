# OpenSASE WireGuard Tunnel Plugin - CMakeLists.txt

cmake_minimum_required(VERSION 3.16)

# Sources
set(WG_SOURCES
    wireguard.c
)

# Create plugin
add_library(wireguard_tunnel_plugin SHARED ${WG_SOURCES})

# Include directories
target_include_directories(wireguard_tunnel_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${VPP_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(wireguard_tunnel_plugin
    ${VPP_LIBRARIES}
)

# Compiler flags
target_compile_options(wireguard_tunnel_plugin PRIVATE
    -fPIC
    -Wall
    -Wextra
    -O3
    -march=native
)

# Output
set_target_properties(wireguard_tunnel_plugin PROPERTIES
    OUTPUT_NAME "wireguard_tunnel_plugin"
    PREFIX ""
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

# Install
install(TARGETS wireguard_tunnel_plugin
    LIBRARY DESTINATION ${VPP_PLUGIN_DIR}
)

install(FILES wireguard.h
    DESTINATION include/vpp_plugins/wireguard_tunnel
)

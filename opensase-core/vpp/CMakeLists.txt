# OpenSASE VPP Engine - Top Level CMakeLists
# Builds all VPP plugins for the SASE data plane

cmake_minimum_required(VERSION 3.16)
project(opensase-vpp VERSION 1.0.0 LANGUAGES C)

# VPP plugin requirements
find_package(PkgConfig REQUIRED)
pkg_check_modules(VPP REQUIRED vpp)

# DPDK (usually bundled with VPP)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Optional dependencies
pkg_check_modules(HYPERSCAN hyperscan)
pkg_check_modules(NDPI libndpi)

# Compiler flags for performance
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -mtune=native")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fstack-protector-strong")

# VPP-specific flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCLIB_DEBUG")

# Include VPP headers
include_directories(${VPP_INCLUDE_DIRS})
include_directories(${DPDK_INCLUDE_DIRS})

if(HYPERSCAN_FOUND)
    include_directories(${HYPERSCAN_INCLUDE_DIRS})
    add_definitions(-DHAVE_HYPERSCAN)
endif()

if(NDPI_FOUND)
    include_directories(${NDPI_INCLUDE_DIRS})
    add_definitions(-DHAVE_NDPI)
endif()

# Plugin output directory
set(VPP_PLUGIN_DIR "/usr/lib/vpp_plugins" CACHE PATH "VPP plugin directory")

# Build plugins
add_subdirectory(plugins/opensase)
add_subdirectory(plugins/wireguard_tunnel)

# Install configuration files
install(DIRECTORY config/ DESTINATION /etc/vpp/opensase)
install(PROGRAMS scripts/setup_hugepages.sh DESTINATION /usr/local/bin)
install(PROGRAMS scripts/bind_dpdk.sh DESTINATION /usr/local/bin)

# Testing
enable_testing()
add_subdirectory(tests)

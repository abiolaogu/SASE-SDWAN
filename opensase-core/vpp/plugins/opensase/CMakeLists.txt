# OpenSASE VPP Plugin - CMakeLists.txt
# Builds the main SASE data plane plugin
# Target: 100 Gbps with <5μs latency - Single-Pass Processing

cmake_minimum_required(VERSION 3.16)

# Sources for the opensase plugin - ordered by VPP graph flow
# dpdk-input → tenant-classifier → acl → security-inspect → nat → wireguard → dpdk-output
set(OPENSASE_SOURCES
    opensase.c              # Plugin registration
    node_vxlan_classifier.c # VXLAN VNI to tenant (entry point)
    node_tenant.c           # IP-based tenant lookup (fallback)
    node_security.c         # Session tracking
    node_security_inspect.c # IPS with Hyperscan
    node_policy.c           # Policy enforcement
    node_dlp.c              # DLP inspection
    node_classify.c         # App classification
    node_qos.c              # QoS marking
    node_nat.c              # NAT/PAT
    node_encap.c            # Encapsulation (output)
)


# Create the plugin shared library
add_library(opensase_plugin SHARED ${OPENSASE_SOURCES})

# Include directories
target_include_directories(opensase_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${VPP_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(opensase_plugin
    ${VPP_LIBRARIES}
)

# Optional Hyperscan support
if(HYPERSCAN_FOUND)
    target_link_libraries(opensase_plugin ${HYPERSCAN_LIBRARIES})
    target_compile_definitions(opensase_plugin PRIVATE HAVE_HYPERSCAN)
endif()

# Optional nDPI support  
if(NDPI_FOUND)
    target_link_libraries(opensase_plugin ${NDPI_LIBRARIES})
    target_compile_definitions(opensase_plugin PRIVATE HAVE_NDPI)
endif()

# Compiler flags for VPP plugins
target_compile_options(opensase_plugin PRIVATE
    -fPIC
    -Wall
    -Wextra
    -O3
    -march=native
    -DCLIB_DEBUG=0
)

# Set output name and location
set_target_properties(opensase_plugin PROPERTIES
    OUTPUT_NAME "opensase_plugin"
    PREFIX ""
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

# Install target
install(TARGETS opensase_plugin
    LIBRARY DESTINATION ${VPP_PLUGIN_DIR}
)

# Install header for external users
install(FILES opensase.h
    DESTINATION include/vpp_plugins/opensase
)

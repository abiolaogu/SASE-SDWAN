# OpenSASE VPP Engine Makefile
# Convenience wrapper for CMake build

.PHONY: all build clean install test dev-install

BUILD_DIR := build
CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=Release

all: build

# Create build directory and run CMake
$(BUILD_DIR)/Makefile:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake $(CMAKE_FLAGS) ..

# Build all plugins
build: $(BUILD_DIR)/Makefile
	@echo "Building OpenSASE VPP plugins..."
	@$(MAKE) -C $(BUILD_DIR) -j$$(nproc)
	@echo "Build complete."

# Debug build
debug: CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=Debug -DCLIB_DEBUG=1
debug: clean build

# Clean build artifacts
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned."

# Install plugins to system
install: build
	@echo "Installing VPP plugins..."
	@sudo $(MAKE) -C $(BUILD_DIR) install
	@echo "Plugins installed to /usr/lib/vpp_plugins"

# Development install (symlinks)
dev-install: build
	@echo "Creating development symlinks..."
	@sudo ln -sf $(PWD)/$(BUILD_DIR)/plugins/opensase/opensase_plugin.so /usr/lib/vpp_plugins/
	@sudo ln -sf $(PWD)/$(BUILD_DIR)/plugins/wireguard_tunnel/wireguard_tunnel_plugin.so /usr/lib/vpp_plugins/
	@echo "Development symlinks created."

# Run tests
test: build
	@echo "Running tests..."
	@cd $(BUILD_DIR) && ctest --output-on-failure
	@echo "Tests complete."

# Setup development environment
setup-dev:
	@echo "Setting up development environment..."
	@sudo apt-get update
	@sudo apt-get install -y \
		vpp vpp-dev vpp-plugin-core vpp-plugin-dpdk \
		libhyperscan-dev libndpi-dev \
		cmake pkg-config build-essential
	@echo "Development environment ready."

# Setup hugepages for VPP
setup-hugepages:
	@sudo ./scripts/setup_hugepages.sh

# Bind NICs to DPDK
bind-dpdk:
	@echo "Usage: make bind-dpdk NICS='0000:81:00.0 0000:81:00.1'"
	@if [ -n "$(NICS)" ]; then \
		sudo ./scripts/bind_dpdk.sh $(NICS); \
	fi

# Start VPP with our config
start-vpp:
	@sudo vpp -c config/startup.conf

# VPP CLI
vppctl:
	@sudo vppctl -s /run/vpp/cli.sock

# Show stats
stats:
	@sudo vppctl -s /run/vpp/cli.sock show runtime
	@sudo vppctl -s /run/vpp/cli.sock show errors

# Format code
format:
	@find plugins -name '*.c' -o -name '*.h' | xargs clang-format -i
	@echo "Code formatted."

# Help
help:
	@echo "OpenSASE VPP Engine Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build          - Build all plugins (release)"
	@echo "  debug          - Build with debug symbols"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install plugins to system"
	@echo "  dev-install    - Create development symlinks"
	@echo "  test           - Run test suite"
	@echo "  setup-dev      - Install development dependencies"
	@echo "  setup-hugepages- Configure hugepages for VPP"
	@echo "  bind-dpdk      - Bind NICs to DPDK driver"
	@echo "  start-vpp      - Start VPP with config"
	@echo "  vppctl         - Open VPP CLI"
	@echo "  stats          - Show VPP statistics"
	@echo "  format         - Format source code"

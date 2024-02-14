ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif

# ifeq ($(strip $(CAPDL_SPEC)),)
# $(error CAPDL_SPEC must be specified)
# endif

ifeq ($(strip $(KERNEL_INSTALL_DIR)),)
$(error KERNEL_INSTALL_DIR must be specified)
endif

ifeq ($(strip $(TOOLCHAIN)),)
$(error TOOLCHAIN must be specified)
endif

### Common Rust definitions

ifeq ($(ARCH),aarch64)
	rust_sel4_target := aarch64-sel4-minimal
	rust_bare_metal_target := aarch64-unknown-none
else ifeq ($(ARCH),x86_64)
	rust_sel4_target := x86_64-sel4-minimal
	rust_bare_metal_target := x86_64-unknown-none
else
	$(error ARCH must be aarch64 or x86_64)
endif

rust_source_path := rust-seL4
rust_target_path := $(rust_source_path)/support/targets
target_dir := $(BUILD_DIR)/capdl/target
cargo_root_dir := $(BUILD_DIR)/capdl/cargo-root

common_env := \
	RUST_TARGET_PATH=$(abspath $(rust_target_path)) \

cross_env := \
	$(common_env) \
	SEL4_PREFIX=$(abspath $(KERNEL_INSTALL_DIR)) \

# @ivanv: removed "--release" from common options
CARGO_OPTIONS := \
	--locked \
	--manifest-path $(rust_source_path)/Cargo.toml \
	--target-dir $(abspath $(target_dir)) \
	--out-dir $(abspath $(BUILD_DIR)) \
	--config $(abspath $(rust_source_path)/.cargo/config)

CARGO_CROSS_OPTIONS := \
	$(CARGO_OPTIONS) \
    -Z unstable-options \
    -Z build-std=core,alloc,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem \

### CapDL tools

capdl_source_dir := capdl
capdl_tool := $(BUILD_DIR)/capDL-tool/parse-capDL
capdl_tool_intermediate := $(BUILD_DIR)/capdl/capdl_tool.intermediate
stack_root := $(BUILD_DIR)/capdl/stack-root # outlive docker container

$(capdl_tool): $(capdl_tool_intermediate)

.INTERMDIATE: $(capdl_tool_intermediate)
$(capdl_tool_intermediate):
	$(MAKE) -C $(capdl_source_dir)/capDL-tool STACK_ROOT=$(abspath $(stack_root))
	mv $(capdl_source_dir)/capDL-tool/parse-capDL $(BUILD_DIR)/parse-capDL

capdl_loader_crate := sel4-capdl-initializer
capdl_loader := $(BUILD_DIR)/$(capdl_loader_crate).elf
capdl_loader_intermediate := $(BUILD_DIR)/capdl_loader.intermediate

$(capdl_loader): $(capdl_loader_intermediate)

.INTERMDIATE: $(capdl_loader_intermediate)
$(capdl_loader_intermediate):
	$(cross_env) \
		cargo build \
			$(CARGO_CROSS_OPTIONS) \
			-p $(capdl_loader_crate) \
			--target $(rust_sel4_target)

### Demo

# prebuilt_dir := prebuilt
# fill_dir := $(prebuilt_dir)
# spec_json := $(BUILD_DIR)/spec.json
object_sizes := $(BUILD_DIR)/object-sizes.yaml

$(object_sizes):
	$(TOOLCHAIN)gcc -E -P - \
		-I $(KERNEL_INSTALL_DIR)/libsel4/include \
		< $(capdl_source_dir)/object_sizes/object_sizes.yaml \
		> $@

# $(spec_json): $(CAPDL_SPEC) $(capdl_tool) $(object_sizes)
# 	$(capdl_tool) --object-sizes=$(object_sizes) --json=$@ $(CAPDL_SPEC)

all: $(object_sizes) $(capdl_loader_intermediate)

# ifeq ($(SMALL),1)

# app_crate := capdl-loader-with-embedded-spec
# app := $(BUILD_DIR)/initialiser.elf
# app_intermediate := $(BUILD_DIR)/app.intermediate

# $(app): $(app_intermediate)

# .INTERMDIATE: $(app_intermediate)
# $(app_intermediate): $(spec_json) $(fill_dir)
# 	$(cross_env) \
#     	CAPDL_SPEC_FILE=$(abspath $(spec_json)) \
#     	CAPDL_FILL_DIR=$(abspath $(fill_dir)) \
# 		cargo build \
# 			$(CARGO_CROSS_OPTIONS) \
# 			-p $(app_crate) \
# 			--target $(rust_sel4_target)
# 		mv $(BUILD_DIR)/$(app_crate).elf $(app)

# all: $(app_intermediate)

# else

# app := $(BUILD_DIR)/app.elf
# app_intermediate := $(BUILD_DIR)/app.intermediate

# $(app): $(app_intermediate)

# .INTERMDIATE: $(app_intermediate)
# $(app_intermediate): $(spec_json) $(capdl_loader) $(capdl_add_spec_to_loader)
# 	$(capdl_add_spec_to_loader) \
# 		-e $(capdl_loader) \
# 		-f $(spec_json) \
# 		-d $(fill_dir) \
# 		-o $(app)

# all: $(app_intermediate)

# endif

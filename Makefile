# NetBee OS Top-Level Build Wrapper
BUILDROOT_DIR := $(CURDIR)/buildroot-2026.08.2
EXTERNAL_DIR  := $(CURDIR)/netbee-external
OUTPUT_DIR    := $(CURDIR)/output
DEFCONFIG     := netbee_rpi5_defconfig

BR_MAKE := $(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT_DIR) BR2_EXTERNAL=$(EXTERNAL_DIR)

.PHONY: help defconfig build menuconfig linux-menuconfig savedefconfig qemu clean distclean

help:
	@echo "NetBee OS (Raspberry Pi 5 Router/Firewall) Build Targets:"
	@echo "  make defconfig        - Load $(DEFCONFIG) into output/"
	@echo "  make build            - Build full SD card image (output/images/sdcard.img)"
	@echo "  make qemu             - Boot NetBee OS in QEMU ARM64 (SSH:2222)"
	@echo "  make menuconfig       - Customize Buildroot packages & settings"
	@echo "  make linux-menuconfig - Customize Linux kernel configuration"
	@echo "  make savedefconfig    - Save current config back to $(DEFCONFIG)"
	@echo "  make clean            - Clean Buildroot build directory"

defconfig:
	$(BR_MAKE) $(DEFCONFIG)

NPROC := $(shell nproc)

build:
	$(BR_MAKE) -j$(NPROC)

menuconfig:
	$(BR_MAKE) menuconfig

linux-menuconfig:
	$(BR_MAKE) linux-menuconfig

savedefconfig:
	$(BR_MAKE) savedefconfig BR2_DEFCONFIG=$(EXTERNAL_DIR)/configs/$(DEFCONFIG)

qemu:
	bash $(CURDIR)/scripts/run-qemu.sh

clean:
	$(BR_MAKE) clean

distclean:
	rm -rf $(OUTPUT_DIR)


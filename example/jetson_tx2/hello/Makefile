#
# Copyright 2021, Breakaway Consulting Pty. Ltd.
#
# SPDX-License-Identifier: BSD-2-Clause
#
ifeq ($(strip $(BUILD_DIR)),)
$(error BUILD_DIR must be specified)
endif

ifeq ($(strip $(MICROKIT_SDK)),)
$(error MICROKIT_SDK must be specified)
endif

ifeq ($(strip $(MICROKIT_BOARD)),)
$(error MICROKIT_BOARD must be specified)
endif

ifeq ($(strip $(MICROKIT_CONFIG)),)
$(error MICROKIT_CONFIG must be specified)
endif

TOOLCHAIN := aarch64-none-elf

CPU := cortex-a53

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AS := $(TOOLCHAIN)-as
MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit

RESTARTER_OBJS := restarter.o
CRASHER_OBJS := crasher.o
HELLO_OBJS := hello.o

BOARD_DIR := $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

IMAGES := restarter.elf crasher.elf hello.elf
CFLAGS := -mcpu=$(CPU) -mstrict-align -nostdlib -ffreestanding -g -O3 -Wall  -Wno-unused-function -Werror -I$(BOARD_DIR)/include
LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := -lmicrokit -Tmicrokit.ld

IMAGE_FILE = $(BUILD_DIR)/loader.img
UIMAGE_FILE = $(BUILD_DIR)/loader.uimage
REPORT_FILE = $(BUILD_DIR)/report.txt

all: $(UIMAGE_FILE)

$(BUILD_DIR)/%.o: %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: %.s Makefile
	$(AS) -g -mcpu=$(CPU) $< -o $@

$(BUILD_DIR)/restarter.elf: $(addprefix $(BUILD_DIR)/, $(RESTARTER_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/crasher.elf: $(addprefix $(BUILD_DIR)/, $(CRASHER_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/hello.elf: $(addprefix $(BUILD_DIR)/, $(HELLO_OBJS))
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

$(IMAGE_FILE) $(REPORT_FILE): $(addprefix $(BUILD_DIR)/, $(IMAGES)) hello.system
	$(MICROKIT_TOOL) hello.system --search-path $(BUILD_DIR) --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) -o $(IMAGE_FILE) -r $(REPORT_FILE)

$(UIMAGE_FILE): $(IMAGE_FILE)
	mkimage -A arm64 -O linux -T kernel -C none -a 81000000 -e 81000000 -d $(IMAGE_FILE) $(UIMAGE_FILE)

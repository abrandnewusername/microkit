#!/bin/sh

set -e

./pyenv/bin/python dev_build.py --board vb_105 --example hello --rebuild
x86_64-linux-gnu-objcopy -O elf32-i386 release/microkit-sdk-1.2.6/board/x86_64_virt/debug/elf/sel4.elf tmp_build/kernel.elf


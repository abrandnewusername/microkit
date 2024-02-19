#!/bin/sh

set -e

./pyenv/bin/python dev_build.py --board x86_64_virt --example hello --rebuild
x86_64-linux-gnu-objcopy -O elf32-i386 tmp_build/sel4.elf tmp_build/kernel.elf

qemu-system-x86_64                                                                         \
        -cpu Nehalem,-vme,+pdpe1gb,-xsave,-xsaveopt,-xsavec,+fsgsbase,-invpcid,+syscall,+lm,enforce \
        -m "3G"                                                                             \
        -display none                                                                       \
        -serial mon:stdio                                                                   \
	-kernel tmp_build/kernel.elf \
	-initrd tmp_build/capdl-initialiser-with-spec.elf

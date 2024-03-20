/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define SERVER_CH 3
#define IOPORT 1

uintptr_t test_mr = 0x4000000;

void
init(void)
{
    char *c = (char *)test_mr;
    c[0] = 'a';
    c[0x10000] = 'b';
    if (c[0] == 'a') {
        microkit_dbg_puts("CLIENT: correctly set to 'a'\n");
    }
    if (c[0x10000] == 'b') {
        microkit_dbg_puts("CLIENT: correctly set to 'b'\n");
    }
    microkit_dbg_puts("CLIENT: init\n");
    microkit_msginfo msginfo = microkit_msginfo_new(1, 0);
    msginfo = microkit_ppcall(SERVER_CH, msginfo);
    microkit_dbg_puts("CLIENT: back!\n");
    microkit_dbg_puts("CLIENT: about to access IOPORT!\n");
    microkit_x86_ioport_write_8(IOPORT, 3, 1);
}

void
notified(microkit_channel ch)
{
}

/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define SERVER_CH 3
#define IOPORT 1

void
init(void)
{
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

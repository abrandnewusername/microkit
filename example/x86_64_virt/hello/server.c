/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

void
init(void)
{
    microkit_dbg_puts("SERVER: init\n");
}

void
notified(microkit_channel ch)
{
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo) {
    if (ch == 2) {
        microkit_dbg_puts("SERVER: GOT PPC\n");
        if (microkit_msginfo_get_label(msginfo) == 1) {
            microkit_dbg_puts("SERVER: correct label!\n");
        }
        uintptr_t test_mr = 0x3000000;
        char *c = (char *) test_mr;
        if (c[0] != 'a') {
            microkit_dbg_puts("SERVER: UH OH\n");
        }
        if (c[0x10000] != 'b') {
            microkit_dbg_puts("SERVER: UH OH\n");
        }

        return microkit_msginfo_new(2, 0);
    }
    return microkit_msginfo_new(0, 0);
}

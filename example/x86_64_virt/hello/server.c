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

        return microkit_msginfo_new(2, 0);
    }
    return microkit_msginfo_new(0, 0);
}

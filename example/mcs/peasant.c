/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

#define SIX_MEGABYTES   (6 * 1024 * 1024)
#define EIGHT_MEGABYTES (8 * 1024 * 1024)


// doing cache pollution here.
// CPU cache for skylake i5-6500 is 6MB, skylake i7-6700 is 8MB
void do_work(void)
{
    int size = EIGHT_MEGABYTES;
    char array[size];
    for (;;) {
        for (int i = 0; i < size; i++) {
            array[i]++;
        }
    }
}

void init(void)
{
    // microkit_dbg_puts("peasant, starting\n");
    do_work();
}

void notified(microkit_channel ch)
{
    do_work();
}

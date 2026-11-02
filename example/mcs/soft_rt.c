/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>

/* [1] "Vendor Identification String" page "3-240 Vol. 2A" */
#define CPUID_VENDOR_ID_LEAF 0x0
#define CPUID_VENDOR_ID_INTEL_EBX 0x756e6547 // "Genu"
#define CPUID_VENDOR_ID_INTEL_ECX 0x6c65746e // "ineI"
#define CPUID_VENDOR_ID_INTEL_EDX 0x49656e69 // "ntel"

/* [1] "Time Stamp Counter and Nominal Core Crystal Clock Information Leaf" page "Vol. 2A 3-231" */
#define CPUID_TSC_LEAF 0x15

/* [1] "Processor Frequency Information Leaf" page "3-232 Vol. 2A" */
#define CPUID_PROC_FREQ_LEAF 0x16

/* [1] "Maximum Input Value for Extended Function CPUID Information." page "Vol. 2A 3-245" */
#define CPUID_MAX_EXT_LEAF 0x80000000

/* [1] "Invariant TSC available if 1" page "Vol. 2A 3-239" */
#define CPUID_INVARIANT_TSC_LEAF 0x80000007
#define CPUID_INVARIANT_TSC_EDX_BIT 8

#define ONE_GHZ (1ULL * (1000ULL * 1000ULL * 1000ULL))

#define BIT(nr) (1UL << (nr))

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(subleaf));
}

static bool is_invariant_tsc(void)
{
    /* [1] page "Vol. 2A 3-245" */
    /* Check "Maximum Input Value for Extended Function CPUID Information." */
    uint32_t max_ext_leaf, a, b, c, d;
    cpuid(CPUID_MAX_EXT_LEAF, 0, &max_ext_leaf, &b, &c, &d);

    if (max_ext_leaf < CPUID_INVARIANT_TSC_LEAF) {
        return false;
    }

    /* Then check whether Invariant TSC is true */
    uint32_t invariant_tsc;
    cpuid(CPUID_INVARIANT_TSC_LEAF, 0, &a, &b, &c, &invariant_tsc);
    return !!(invariant_tsc & BIT(CPUID_INVARIANT_TSC_EDX_BIT));
}

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    asm volatile("rdtscp" : "=a"(lo), "=d"(hi) : : "ecx");
    asm volatile("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static char decchar(unsigned int v)
{
    return '0' + v;
}

static void put64(uint64_t x)
{
    char tmp[25];
    unsigned i = 24;
    tmp[24] = 0;
    do {
        uint8_t c = x % 10;
        tmp[--i] = decchar(c);
        x /= 10;
    } while (x);
    microkit_dbg_puts(&tmp[i]);
}

static inline uint64_t period_transform(uint64_t period, uint64_t input_freq)
{
    // We use a split-remainder technique to divide and multiply the `period` without
    // any overflow until `period` is very large.
    // See https://gist.github.com/midnightveil/23fc4dc16cad52114a94fb1978550a98
    uint64_t out_period_whole = (period / input_freq) * ONE_GHZ;
    uint64_t period_remainder = period % input_freq;
    uint64_t out_period_remainder = (period_remainder * ONE_GHZ) / input_freq;
    return out_period_whole + out_period_remainder;
}

static uint64_t get_tsc_frequency(void)
{
    uint32_t max_basic_leaf, b, c, d;
    /* Checks whether the CPU expose TSC/Crystal ratio and Crystal frequency via cpuid leaf 0x15. */
    cpuid(CPUID_VENDOR_ID_LEAF, 0, &max_basic_leaf, &b, &c, &d);
    if (max_basic_leaf < CPUID_TSC_LEAF) {
        return 0;
    }

    uint32_t denominator, numerator, crystal_khz;
    cpuid(CPUID_TSC_LEAF, 0, &denominator, &numerator, &crystal_khz, &d);
    if (!denominator || !numerator) {
        return 0;
    }

    double tsc_to_crystal_freq_ratio = numerator / (double)denominator;

    uint32_t crystal_hz;
    if (!crystal_khz) {

        /* From [2]: "Some Intel SoCs like Skylake and Kabylake don't report the crystal
         * clock, but we can easily calculate it to a high degree of accuracy
         * by considering the crystal ratio and the CPU speed." */
        if (max_basic_leaf < CPUID_PROC_FREQ_LEAF) {
            return 0;
        }

        uint32_t proc_base_mhz;
        cpuid(CPUID_PROC_FREQ_LEAF, 0, &proc_base_mhz, &b, &c, &d);
        uint64_t proc_base_hz = proc_base_mhz * 1000ull * 1000ull;
        crystal_hz = proc_base_hz * (1 / tsc_to_crystal_freq_ratio);

    } else {
        crystal_hz = crystal_khz * 1000;
    }

    /* From [1]:
     * EAX: denominator of the TSC/”core crystal clock” ratio.
     * EBX: numerator of the TSC/”core crystal clock” ratio.
     * ECX: nominal frequency of the core crystal clock in Hz.
     * So “TSC frequency” = “core crystal clock frequency” * EBX/EAX.
     */

    uint64_t tsc_hz = crystal_hz * tsc_to_crystal_freq_ratio;
    return tsc_hz;
}

void do_work(void)
{
    int i = 0;
    for (;;) {
        i++;
    }
    return;
}

void init(void)
{
    uint64_t tsc = rdtsc();
    uint64_t freq = get_tsc_frequency();

    microkit_dbg_puts(microkit_name);
    microkit_dbg_puts(": timestamp: ");
    put64(period_transform(tsc, freq));
    microkit_dbg_puts("\n");

    do_work();
}

void notified(microkit_channel ch)
{
    do_work();
}

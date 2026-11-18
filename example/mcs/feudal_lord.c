/*
 * Copyright 2021, Breakaway Consulting Pty. Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <microkit.h>
#include <sel4/benchmark_track_types.h>
#include <sel4/benchmark_utilisation_types.h>

#define UART_CH 1

uint64_t com1_ioport_id;
uint64_t com1_ioport_addr;

#define BIT(nr)           (1 << nr)

#define SERIAL_THR  0 /* Transmitter Holding Buffer (W ) DLAB = 0 */
#define SERIAL_RBR  0 /* Receiver Buffer            (R ) DLAB = 0 */
#define SERIAL_DLL  0 /* Divisor Latch Low Byte     (RW) DLAB = 1 */
#define SERIAL_IER  1 /* Interrupt Enable Register  (RW) DLAB = 0 */
#define SERIAL_DLH  1 /* Divisor Latch High Byte    (RW) DLAB = 1 */
#define SERIAL_IIR  2 /* Interrupt Identification   (R ) */
#define SERIAL_FCR  2 /* FIFO Control Register      (W ) */
#define SERIAL_LCR  3 /* Line Control Register      (RW) */
#define SERIAL_MCR  4 /* Modem Control Register     (RW) */
#define SERIAL_LSR  5 /* Line Status Register       (R ) */
#define SERIAL_MSR  6 /* Modem Status Register      (R ) */
#define SERIAL_SR   7 /* Scratch Register           (RW) */
#define SERIAL_DLAB BIT(7)
#define SERIAL_LSR_DATA_READY BIT(0)
#define SERIAL_LSR_TRANSMITTER_EMPTY BIT(5)


void write(uint16_t port_offset, uint8_t v)
{
    microkit_x86_ioport_write_8((com1_ioport_id), com1_ioport_addr + port_offset, v);
}

uint8_t read(uint16_t port_offset)
{
    return microkit_x86_ioport_read_8((com1_ioport_id), com1_ioport_addr + port_offset);
}

int tx_ready(void)
{
    return read(SERIAL_LSR) & SERIAL_LSR_TRANSMITTER_EMPTY;
}

static inline void uart_putchar(char ch)
{
    // Danger: may overflow hardware FIFO, but we are only writing a small message.
    microkit_x86_ioport_write_8(com1_ioport_id, com1_ioport_addr, ch);
}

static inline void uart_putchars(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            while (!tx_ready());
            uart_putchar('\r');
        }
        while (!tx_ready());
        uart_putchar(*s++);
    }
}

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
    uart_putchars(&tmp[i]);
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

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES

#define LOG_BUFFER_CAP 7

benchmark_track_kernel_entry_t *log_buffer;

static void dump_log_summary(uint64_t log_size)
{
    seL4_Word index = 0;
    seL4_Word irq_index = 0;
    seL4_Word prev_start_time = 0;

    seL4_Word wc_timeout = 0;
    seL4_Word wc_preempt = 0;

    seL4_Word timeout_index = 0;
    seL4_Word preempt_index = 0;

    uint64_t freq = get_tsc_frequency();


    while (log_buffer[index].start_time != 0 && index < log_size) {
        seL4_Word exec_time_us = period_transform(log_buffer[index].start_time - prev_start_time, freq);
        
        if ((log_buffer[index].entry.path == Entry_Interrupt) && 
            (exec_time_us > 990000)) {

            if (index > 4000 && index < 4200) {
                uart_putchars("[");
                put64(irq_index);
                uart_putchars("]: ");
    
                put64(exec_time_us);
    
                uart_putchars(", ");
                put64(period_transform(log_buffer[index].duration, freq));
    
                uart_putchars("\n");
            }

            irq_index++;
            prev_start_time = log_buffer[index].start_time;

            // highest prio partial budget thread, will expire
            if (exec_time_us > 2950000 && exec_time_us < 3050000){
                if (wc_timeout < period_transform(log_buffer[index].duration, freq)) {
                    wc_timeout = period_transform(log_buffer[index].duration, freq);
                }
                timeout_index++;

            // full budget background thread, only gets preempted
            } else if (exec_time_us > 1050000)  {

                if (wc_preempt < period_transform(log_buffer[index].duration, freq)) {
                    wc_preempt = period_transform(log_buffer[index].duration, freq);
                }
                preempt_index++;
            }
        }

        index++;
    }
        uart_putchars("\n");
        uart_putchars("Total: ");
        put64(index);
        uart_putchars("\n");


        uart_putchars("WC preempt: ");
        put64(wc_preempt);
        uart_putchars(", # preempt: ");
        put64(preempt_index);
        uart_putchars("\n");

        uart_putchars("WC timeout: ");
        put64(wc_timeout);
        uart_putchars(", # timeout: ");
        put64(timeout_index);
        uart_putchars("\n");
}

void kernel_benchmark_init(void)
{
    int res_buf = seL4_BenchmarkSetLogBuffer(7);
    if (res_buf) {
        uart_putchars("monitor: Could not set log buffer\n");
    } else {
        // uart_putchars("monitor: Log buffer set\n");
        return;
    }
}

#endif

void init(void)
{
    // microkit_pd_stop(1);
    // microkit_pd_stop(2);
    // microkit_pd_stop(3);

// #if !ENABLE_BENCHMARKS
//     uart_putchars("monitor: ENABLE_BENCHMARKS is disabled\n");
//     return;
// #endif

    while (!(read(SERIAL_LSR) & 0x60)); /* wait until not busy */

    write(SERIAL_LCR, 0x00); /* line control register: command: set divisor */

    write(SERIAL_IER, 0x00); /* disable generating interrupts */

    write(SERIAL_LCR, 0x80); /* line control register: command: set divisor */
    write(SERIAL_DLL, 0x01); /* set low byte of divisor to 0x01 = 115200 baud */
    write(SERIAL_DLH, 0x00); /* set high byte of divisor to 0x00 */
    write(SERIAL_LCR, 0x03); /* line control register: set 8 bit, no parity, 1 stop bit */
    write(SERIAL_MCR, 0x0b); /* modem control register: set DTR/RTS/OUT2 */
    write(SERIAL_FCR, 0x00); /* set IRQ trigger level to 1 byte */

    read(SERIAL_RBR); /* clear receiver port */
    read(SERIAL_LSR); /* clear line status port */
    read(SERIAL_MSR); /* clear modem status port */

#if !CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
    uart_putchars("monitor: CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES is disabled\n");
    return;
#endif

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
    kernel_benchmark_init();
#endif

    if (!is_invariant_tsc()) {

        uart_putchars("monitor: is_invariant_tsc fails...");
    }

    uint64_t freq = get_tsc_frequency();

    uart_putchars("monitor: starting, timestamp: ");
    put64(period_transform(rdtsc(), freq));
    
    uart_putchars(", frequency: ");
    put64(freq);
    uart_putchars("\n");

    seL4_BenchmarkResetLog();
}

void notified(microkit_channel ch)
{
#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
    uint64_t entries = seL4_BenchmarkFinalizeLog();
    dump_log_summary(entries);

    seL4_BenchmarkResetLog();
#endif
}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    uart_putchars("monitor: received protected message\n");

    return microkit_msginfo_new(0, 0);
}


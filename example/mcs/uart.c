/*
 * Copyright 2025, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stdint.h>
#include <microkit.h>

#define BIT(nr)           (1 << nr)

// TODO: the retain and used attributes are necessary as nothing uses/refers to this section
// in release mode in this driver.
// The solution is to fix our tooling to generate device resources for this driver as well
// and then remove 'retain,used'.

// @billn Need a way to express io port in Acacia config structure
#define IOPORT_ID 0
#define IOPORT_BASE 0x3f8
// @billn need some sort of "machine description" format for x86 Acacia to automatically pull in IRQ
#define IRQ_ID 1

/*
 * Port offsets
 * W    - write
 * R    - read
 * RW   - read and write
 * DLAB - Alternate register function bit
 */

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

enum irq_state { MODEM_STATUS = 0, TX_HOLD_REG_EMPTY, RX_DATA_AVAIL, RX_LINE_STS };

void write(uint16_t port_offset, uint8_t v)
{
    microkit_x86_ioport_write_8((IOPORT_ID), IOPORT_BASE + port_offset, v);
}

uint8_t read(uint16_t port_offset)
{
    return microkit_x86_ioport_read_8((IOPORT_ID), IOPORT_BASE + port_offset);
}

int tx_ready(void)
{
    return read(SERIAL_LSR) & SERIAL_LSR_TRANSMITTER_EMPTY;
}

int rx_ready(void)
{
    return read(SERIAL_LSR) & SERIAL_LSR_DATA_READY;
}

void init(void)
{
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
}

void notified(microkit_channel ch)
{

}

seL4_MessageInfo_t protected(microkit_channel ch, microkit_msginfo msginfo)
{
    char c = seL4_GetMR(0);
    write(SERIAL_THR, c);

    return microkit_msginfo_new(0, 0);
}

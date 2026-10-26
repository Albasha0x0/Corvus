; NROM-128: 16 KiB PRG-ROM at 0x8000 (mirrored at 0xC000), 8 KiB CHR-ROM. reset -> middle -> leaf; nmi -> leaf.
.segment "HEADER"
    .byte "NES", $1A, 1, 1, $01, $00, 0, 0, 0, 0, 0, 0, 0, 0
.segment "CODE"
reset:  sei
        cld
        ldx #$FF
        txs
        jsr middle
loop:   jmp loop
middle: jsr leaf
        jsr leaf
        rts
leaf:   clc
        adc #7
        rts
nmi:    pha
        jsr leaf
        pla
        rti
irq:    rti
.segment "VECTORS"
    .word nmi, reset, irq
.segment "CHARS"
    .res $2000, $00

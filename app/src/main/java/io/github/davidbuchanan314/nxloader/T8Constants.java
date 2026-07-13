package io.github.davidbuchanan314.nxloader;

public class T8Constants {
    // Values taken from targets/t8006/t8020 offsets.h examples
    public static final long NEW_SP = 0x1801D8BC0L;

    public static final long MEMCPY = 0x100010C10L;
    public static final long STRLCAT = 0x100010BB8L;

    public static final long CALCULATE_HEAP_BLOCK_SUM = 0x10000F5ECL;

    public static final long TRAMP_BASE = 0x1801C8000L;
    public static final long ROM_TRAMP = 0x100007A00L;
    public static final int ROM_TRAMP_LEN = 0x480;

    public static final long BOOT_TRAMP_PTEP = 0x1801B4390L;
    public static final long BOOT_TRAMP_PTE = 0x1801C86E3L;

    public static final long DMA_BUF_LO = 0x801D9600L;
    public static final long USB_DMA_DEST = 0x230100B14L;

    public static final long JUMP_STATE = 0x1801C4030L;

    public static final long HEAP_BLOCK_TO_REPAIR_DMA = 0x1801D95C0L;
    public static final long HEAP_BLOCK_TO_REPAIR_IO_BUF = 0x1801D8BC0L;
    public static final long HEAP_WHATEVER_THAT_IS = 0x1801C0C78L;

    public static final long USB_SN_STR = 0x1801BB3D8L;
    public static final long USB_DEV_DESC_SN_IDX = 0x1801B897AL;
    public static final long USB_DESC_MAKE_STR = 0x10000D510L;

    public static final long USB_REQ_HANDLER_CB_ADDR = 0x1801C03F8L;

    public static final long RETURN_TO_EL0_ADDR = 0x10000C370L;

    // Generic values used by PrimaryLoader (defaults)
    public static final int RCM_PAYLOAD_ADDR = 0x40010000;
    public static final int INTERMEZZO_LOCATION = 0x4001F000;
    public static final int PAYLOAD_LOAD_BLOCK = 0x40020000;
    public static final int MAX_LENGTH = 0x30298;
    public static final int STACK_END = 0x7000;

    // Example heap blocks (from t8006 example blocks.S)
    public static final long[] HEAP_BLOCKS = new long[] {
        0x1801D8BC0L,
        0x1801D9400L,
        0x1801D9480L,
        0x1801D9500L,
        0x1801D95C0L
    };

    public static final String PWND_STR = " PWND:[usbliter8]";
}

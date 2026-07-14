package io.github.davidbuchanan314.nxloader;
public class T8Constants {
    // Minimal constants used by the usbliter8-based PrimaryLoader

    // Payload layout constants (defaults)
    public static final int RCM_PAYLOAD_ADDR = 0x40010000;
    public static final int INTERMEZZO_LOCATION = 0x4001F000;
    public static final int PAYLOAD_LOAD_BLOCK = 0x40020000;
    public static final int MAX_LENGTH = 0x30298;
    public static final int STACK_END = 0x7000;

    // Example heap blocks used by the payload construction
    public static final long[] HEAP_BLOCKS = new long[] {
        0x1801D8BC0L,
        0x1801D9400L,
        0x1801D9480L,
        0x1801D9500L,
        0x1801D95C0L
    };

    // PWND tag inserted into the USB serial string
    public static final String PWND_STR = " PWND:[usbliter8]";
}

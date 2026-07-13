package io.github.davidbuchanan314.nxloader;

import android.app.Activity;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Bundle;

// Ideally, this would be a Service, but Services can't handle USB Intents :(
public class USBHandlerActivity extends Activity {

    private static final int APX_VID = 0x05ac;
    private static final int APX_PID = 0x1227;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            Intent intent = getIntent();
            if (intent == null) {
                Logger.log(this, "[-] No intent received in USBHandlerActivity");
                finish();
                return;
            }

            String action = intent.getAction();
            Logger.log(this, "[*] USBHandlerActivity started with action: " + action);
            if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                if (device == null) {
                    Logger.log(this, "[-] No USB device information in attached intent");
                    finish();
                    return;
                }

                int vid = device.getVendorId();
                int pid = device.getProductId();
                Logger.log(this, "[*] USB device connected: " + device.getDeviceName() + " vid=0x" + Integer.toHexString(vid) + " pid=0x" + Integer.toHexString(pid));

                if (vid == APX_VID && pid == APX_PID) {
                    Intent launchIntent = new Intent(this, MainActivity.class);
                    launchIntent.setAction(Constants.ACTION_USB_DEVICE_PENDING);
                    launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                    launchIntent.putExtra(Constants.EXTRA_USB_DEVICE_NAME, device.getDeviceName());
                    launchIntent.putExtra(Constants.EXTRA_USB_VENDOR_ID, vid);
                    launchIntent.putExtra(Constants.EXTRA_USB_PRODUCT_ID, pid);
                    startActivity(launchIntent);
                    Logger.log(this, "[*] Forwarded pending USB attach to MainActivity");
                } else {
                    Logger.log(this, "[-] No handler found for this USB device");
                }

                Logger.log(this, "[*] Done processing attach for device: " + device.getDeviceName());
            } else {
                Logger.log(this, "[-] Ignored USB action: " + action);
            }
        } catch (Exception e) {
            Logger.log(this, "[-] Exception in USBHandlerActivity: " + e.toString());
        } finally {
            finish();
        }
    }

}

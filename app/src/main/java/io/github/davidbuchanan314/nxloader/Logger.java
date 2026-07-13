package io.github.davidbuchanan314.nxloader;

import android.content.Context;
import android.content.Intent;
import android.support.annotation.StringRes;
import android.util.Log;

public class Logger {
    private static final String TAG = "NXLoader";

    public static void log(Context context, String message) {
        Log.i(TAG, message);
        Intent intent = new Intent(Constants.LOGGER_ACTION);
        intent.putExtra("msg", message);
        context.sendBroadcast(intent);
    }
}
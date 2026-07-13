package com.obbedcode.inlinehookinvalidate.pm;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Looper;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.List;

public final class AppIndexer {

    private static final int ICON_SIZE = 64;
    private static final int ICON_QUALITY = 80;

    public static void main(String[] arguments) {
        boolean includeIcons = false;
        String outputPath = null;
        for (int index = 0; index < arguments.length; index++) {
            if (arguments[index].equals("--icons")) {
                includeIcons = true;
            } else if (arguments[index].equals("--out") && index + 1 < arguments.length) {
                outputPath = arguments[index + 1];
            }
        }

        try {
            StringBuilder jsonBuilder = new StringBuilder();
            buildIndex(jsonBuilder, includeIcons);

            if (outputPath != null) {
                FileWriter writer = new FileWriter(outputPath);
                writer.write(jsonBuilder.toString());
                writer.close();
            } else {
                System.out.println(jsonBuilder.toString());
            }
        } catch (Throwable error) {
            System.err.println("AppIndexer failed: " + error);
        }

        Runtime.getRuntime().halt(0);
    }

    private static void buildIndex(StringBuilder jsonBuilder, boolean includeIcons) throws Exception {
        bypassHiddenApiRestrictions();
        PackageManager packageManager = systemPackageManager();

        List<ApplicationInfo> installedApplications = getInstalledApplicationsCompat(packageManager);

        jsonBuilder.append('[');
        boolean first = true;
        for (ApplicationInfo applicationInfo : installedApplications) {
            if (!first) jsonBuilder.append(',');
            first = false;

            String label = packageManager.getApplicationLabel(applicationInfo).toString();
            boolean isSystemApplication = (applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;

            jsonBuilder.append('{');
            jsonBuilder.append("\"pkg\":").append(jsonString(applicationInfo.packageName)).append(',');
            jsonBuilder.append("\"label\":").append(jsonString(label)).append(',');
            jsonBuilder.append("\"uid\":").append(applicationInfo.uid).append(',');
            jsonBuilder.append("\"system\":").append(isSystemApplication);

            if (includeIcons) {
                String encodedIcon = encodeIcon(packageManager.getApplicationIcon(applicationInfo));
                if (encodedIcon != null) {
                    jsonBuilder.append(",\"icon\":").append(jsonString(encodedIcon));
                }
            }

            jsonBuilder.append('}');
        }
        jsonBuilder.append(']');
    }

    private static String jsonString(String value) {
        StringBuilder builder = new StringBuilder();
        builder.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') builder.append('\\').append(character);
            else if (character == '\n') builder.append("\\n");
            else if (character < 0x20) builder.append(' ');
            else builder.append(character);
        }
        builder.append('"');
        return builder.toString();
    }

    private static String encodeIcon(Drawable drawable) {
        try {
            Bitmap bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888);
            Canvas canvas = new Canvas(bitmap);
            drawable.setBounds(0, 0, ICON_SIZE, ICON_SIZE);
            drawable.draw(canvas);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            Bitmap.CompressFormat format = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                ? Bitmap.CompressFormat.WEBP_LOSSY
                : Bitmap.CompressFormat.WEBP;
            bitmap.compress(format, ICON_QUALITY, stream);
            return Base64.encodeToString(stream.toByteArray(), Base64.NO_WRAP);
        } catch (Throwable error) {
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static List<ApplicationInfo> getInstalledApplicationsCompat(PackageManager packageManager) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            try {
                return packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0));
            } catch (NoSuchMethodError | NoSuchFieldError ignored) {
            }
        }
        return packageManager.getInstalledApplications(0);
    }

    private static void bypassHiddenApiRestrictions() {
        try {
            Class<?> runtimeClass = Class.forName("dalvik.system.VMRuntime");
            Method getRuntimeMethod = runtimeClass.getDeclaredMethod("getRuntime");
            Object runtimeInstance = getRuntimeMethod.invoke(null);
            Method setExemptionsMethod = runtimeClass.getDeclaredMethod("setHiddenApiExemptions", String[].class);
            setExemptionsMethod.invoke(runtimeInstance, (Object) new String[]{"L"});
        } catch (Throwable ignored) {
        }
    }

    private static PackageManager systemPackageManager() throws Exception {
        if (Looper.getMainLooper() == null) {
            Looper.prepareMainLooper();
        }
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method systemMainMethod = activityThreadClass.getDeclaredMethod("systemMain");
        Object activityThreadInstance = systemMainMethod.invoke(null);
        Method getSystemContextMethod = activityThreadClass.getDeclaredMethod("getSystemContext");
        Context systemContext = (Context) getSystemContextMethod.invoke(activityThreadInstance);
        return systemContext.getPackageManager();
    }

    private AppIndexer() {
    }
}

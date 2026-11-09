package com.obbedcode.inlinehookinvalidate.webui;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Collections;
import java.util.regex.Pattern;

public final class MainActivity extends Activity {

    private static final String MODULE_DIR = "/data/adb/modules/inline_hook_invalidate";

    private static final String ASSET_BASE = "file:///android_asset/webroot/";
    private static final Pattern CALLBACK = Pattern.compile("__iahs_cb_[0-9]+");

    private WebView webView;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(false);
        settings.setBlockNetworkLoads(true);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                return !(url.equals(ASSET_BASE + "index.html") || url.equals(localBase() + "index.html"));
            }

            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                for (String file : new String[]{"index.html", "app.js", "fastscroll.js", "style.css"}) {
                    if (url.equals(ASSET_BASE + file) || url.equals(localBase() + file)) return null;
                }
                if (!request.isForMainFrame() && url.startsWith("data:image/webp;base64,")) return null;
                return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden",
                    Collections.emptyMap(), new ByteArrayInputStream(new byte[0]));
            }
        });

        webView.addJavascriptInterface(new RootBridge(), "ksu");

        loadUi();
    }

    private String localBase() {
        return "file://" + new File(getFilesDir(), "webroot").getAbsolutePath() + "/";
    }

    private void loadUi() {
        executor.execute(() -> {
            File destination = new File(getFilesDir(), "webroot");
            boolean synced = runRoot(
                "source=" + MODULE_DIR + "/webroot; "
                    + "if [ -f \"$source/index.html\" ]; then "
                    + "mkdir -p '" + destination.getAbsolutePath() + "' && cp -af \"$source/.\" '" + destination.getAbsolutePath() + "/' && chmod -R a+rX '" + destination.getAbsolutePath() + "' && echo 1; "
                    + "else echo 0; fi"
            ).stdout.trim().equals("1");

            String target = synced && new File(destination, "index.html").exists()
                ? localBase() + "index.html"
                : ASSET_BASE + "index.html";

            webView.post(() -> webView.loadUrl(target));
        });
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    private static final class RootResult {
        final int exitCode;
        final String stdout;
        final String stderr;

        RootResult(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
        }
    }

    private RootResult runRoot(String command) {
        File errorFile = null;
        Process process = null;
        try {
            errorFile = File.createTempFile("root-err-", ".txt", getCacheDir());
            process = new ProcessBuilder("su", "-c", command).redirectError(errorFile).start();
            String stdout = readAll(process.getInputStream());
            int exitCode = process.waitFor();
            return new RootResult(exitCode, stdout, readAll(new FileInputStream(errorFile)));
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return new RootResult(-1, "", "Root command interrupted");
        } catch (Exception error) {
            return new RootResult(-1, "", error.getMessage() == null ? "root unavailable" : error.getMessage());
        } finally {
            if (process != null) process.destroy();
            if (errorFile != null) errorFile.delete();
        }
    }

    private static String readAll(java.io.InputStream stream) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        StringBuilder builder = new StringBuilder();
        String line;
        boolean first = true;
        while ((line = reader.readLine()) != null) {
            if (!first) builder.append('\n');
            builder.append(line);
            first = false;
        }
        return builder.toString();
    }

    private final class RootBridge {

        @JavascriptInterface
        public String moduleInfo() {
            try {
                return new JSONObject().put("moduleDir", MODULE_DIR).toString();
            } catch (Throwable error) {
                return "{}";
            }
        }

        @JavascriptInterface
        public String exec(String command) {
            return runRoot(command).stdout;
        }

        @JavascriptInterface
        public void exec(String command, String optionsJson, String callbackName) {
            if (callbackName == null || !CALLBACK.matcher(callbackName).matches()) return;
            executor.execute(() -> {
                RootResult result = runRoot(command);
                String script = "if(window['" + callbackName + "'])window['" + callbackName + "']("
                    + result.exitCode + "," + JSONObject.quote(result.stdout) + "," + JSONObject.quote(result.stderr) + ");";
                webView.post(() -> webView.evaluateJavascript(script, null));
            });
        }
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}

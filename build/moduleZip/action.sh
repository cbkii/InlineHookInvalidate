#!/system/bin/sh

MODULE_ID="inline_hook_invalidate"
MODULE_NAME="Inline Hook Invalidate"

open_webui() {
    am start -n "$1/.WebUIActivity" --es id "$MODULE_ID" --es name "$MODULE_NAME" >/dev/null 2>&1
}

if pm path com.obbedcode.inlinehookinvalidate.webui >/dev/null 2>&1; then
    echo "[*] Opening Inline Hook Invalidate WebUI"
    am start -n com.obbedcode.inlinehookinvalidate.webui/.MainActivity >/dev/null 2>&1
    exit 0
fi

for host in io.github.a13e300.ksuwebui $(pm list packages 2>/dev/null | sed 's/package://' | grep -i ksuwebui); do
    if pm path "$host" >/dev/null 2>&1; then
        echo "[*] Opening WebUI via $host"
        if open_webui "$host"; then
            exit 0
        fi
    fi
done

echo "[!] No WebUI host app found."
echo "    Install the companion WebUI app, or open this module from a"
echo "    WebUI-capable manager (KernelSU / APatch / MMRL)."
exit 1

SKIPUNZIP=0

config="$MODPATH/config.txt"
previous=/data/adb/modules/inline_hook_invalidate/config.txt
if [ -L "$config" ]; then
  abort "Refusing symlinked Inline Hook Invalidate configuration"
fi
if [ ! -f "$config" ]; then
  if [ -f "$previous" ] && [ ! -L "$previous" ]; then
    cp "$previous" "$config" || abort "Could not preserve existing configuration"
  else
    printf '%s\n' '0:libart.so:mmap-once' > "$config" || abort "Could not initialise configuration"
  fi
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$config" 0 0 0600
set_perm "$MODPATH/action.sh" 0 0 0755

SKIPUNZIP=0

if [ ! -f "$MODPATH/config.txt" ]; then
  echo "0:libart.so" > "$MODPATH/config.txt"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/config.txt" 0 0 0666
set_perm "$MODPATH/action.sh" 0 0 0755

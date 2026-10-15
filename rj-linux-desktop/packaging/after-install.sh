#!/bin/sh
set -eu
app='/opt/${sanitizedProductName}'
name='${executable}'

update-alternatives --install "/usr/bin/$name" "$name" "$app/$name" 100
# Keep a working SUID fallback when unprivileged user namespaces are restricted.
# Chromium continues to use its sandbox; no --no-sandbox switch is added.
chown root:root "$app/chrome-sandbox"
chmod 4755 "$app/chrome-sandbox"
if [ -d "$app/resources/tools/browsers" ]; then
  find "$app/resources/tools/browsers" -type f -name chrome_sandbox \
    -exec chown root:root {} + -exec chmod 4755 {} +
fi

if command -v apparmor_parser >/dev/null 2>&1 && apparmor_status --enabled >/dev/null 2>&1; then
  source="$app/resources/apparmor-profile"
  if apparmor_parser --skip-kernel-load "$source" >/dev/null 2>&1; then
    cp "$source" "/etc/apparmor.d/$name"
    if ! ischroot; then apparmor_parser --replace "/etc/apparmor.d/$name"; fi
  fi
fi
if command -v update-mime-database >/dev/null 2>&1; then update-mime-database /usr/share/mime; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications; fi

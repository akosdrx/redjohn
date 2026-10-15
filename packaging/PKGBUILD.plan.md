# Arch Linux packaging plan (PKGBUILD) — x86_64 ONLY (verified plan, not yet built here)

Status: **plan**. The desktop app targets macOS dmg (x64+arm64) and Linux
deb + AppImage (x64) via electron-builder. This document describes the
verified approach for an Arch package. ARM Arch (aarch64) is **not**
currently supported and must not be claimed: the engine binary
(`resources/engine/redjohn-engine`) is built per-platform via PyInstaller
and no aarch64 engine build exists yet.

## Approach

Package from the built artifacts (not from source) — the standard approach
for Electron apps on Arch:

1. Build once on x86_64:
   - `pnpm install && pnpm build`
   - `bash scripts/build-engine.sh` (produces `resources/engine/redjohn-engine`)
   - `cd app && pnpm exec electron-builder --config ../packaging/electron-builder.yml --linux dir`
     (the `dir` target produces an unpacked `release/linux-unpacked/` tree)
2. The PKGBUILD then installs `linux-unpacked/` into `/opt/redjohn/` and
   symlinks `/usr/bin/redjohn -> /opt/redjohn/redjohn`.

## PKGBUILD sketch

```pkgbuild
# Maintainer: RedJohn
pkgname=redjohn
pkgver=0.1.0
pkgrel=1
pkgdesc="RedJohn — authorized security-testing orchestration desktop client"
arch=('x86_64')   # NO aarch64 until an arm64 engine binary exists
url="https://redjohn.dev"
license=('custom')
depends=('gtk3' 'nss' 'alsa-lib' 'libxss')
source=("${pkgname}-${pkgver}.tar.gz")  # tarball of release/linux-unpacked
sha256sums=('SKIP')                     # pin a real hash for release

package() {
  install -dm755 "$pkgdir/opt/redjohn"
  cp -a "$srcdir/linux-unpacked/." "$pkgdir/opt/redjohn/"
  install -dm755 "$pkgdir/usr/bin"
  ln -s /opt/redjohn/redjohn "$pkgdir/usr/bin/redjohn"
  install -Dm644 "$srcdir/redjohn.desktop" "$pkgdir/usr/share/applications/redjohn.desktop"
  install -Dm644 "$srcdir/icon.png" "$pkgdir/usr/share/pixmaps/redjohn.png"
}
```

## redjohn.desktop

```ini
[Desktop Entry]
Name=RedJohn
Comment=Authorized security-testing orchestration
Exec=/opt/redjohn/redjohn %U
Icon=redjohn
Type=Application
Categories=Development;Security;
```

## Verification checklist (must pass on a clean Arch x86_64 VM)

- `makepkg -si` installs without errors.
- `redjohn` launches; engine attaches or spawns from
  `/opt/redjohn/resources/engine/redjohn-engine`.
- Loopback-only API: `ss -ltnp | grep redjohn` shows 127.0.0.1 binding only.
- Uninstall leaves no engine processes (`pgrep -f redjohn-engine` empty
  after quit with "Stop engine and quit").

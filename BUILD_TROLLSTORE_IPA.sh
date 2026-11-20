#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/example"

echo "== Flutter dependencies =="
flutter pub get

echo "== CocoaPods =="
cd ios
pod install --repo-update
cd ..

echo "== Build iOS app without Apple code signing =="
flutter build ios --release --no-codesign

APP="$ROOT/example/build/ios/iphoneos/Runner.app"
EXT="$APP/PlugIns/sstp_extension.appex"

if [[ ! -d "$APP" ]]; then
  echo "ERROR: Runner.app was not produced"
  exit 2
fi

if [[ ! -d "$EXT" ]]; then
  echo "ERROR: Packet Tunnel extension is missing from Runner.app"
  exit 3
fi

echo "== Install ldid and embed TrollStore entitlements =="
if ! command -v ldid >/dev/null 2>&1; then
  brew install ldid
fi
APP_EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$APP/Info.plist")"
EXT_EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$EXT/Info.plist")"
ldid -S"$ROOT/example/ios/Runner/Runner.entitlements" "$APP/$APP_EXECUTABLE"
ldid -S"$ROOT/example/ios/sstp_extension/sstp_extension.entitlements" "$EXT/$EXT_EXECUTABLE"

mkdir -p "$ROOT/dist/Payload"
rm -rf "$ROOT/dist/Payload/Runner.app"
cp -R "$APP" "$ROOT/dist/Payload/Runner.app"

(
  cd "$ROOT/dist"
  rm -f SA_SSTP_TrollStore.ipa
  zip -qry SA_SSTP_TrollStore.ipa Payload
)

echo
echo "IPA_READY: $ROOT/dist/SA_SSTP_TrollStore.ipa"
echo "APP_BUNDLE: $(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$APP/Info.plist")"
echo "EXTENSION: $EXT"

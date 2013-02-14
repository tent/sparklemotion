#!/bin/sh

# Example XCode build script
#
# Add it as a "Run Script" phase at the end of your app target build.
#
# Copy your dsa_priv.pem to PROJECT_ROOT/config and create PROJECT_ROOT/config/release
# with the url and key for your Sparkle Motion server:
#
# smurl=https://sparkle-motion-42.herokuapp.com
# smkey=supersecret

set -e -x

if [ $CONFIGURATION = "Debug" ]; then
    echo "This is not a release build. Skipping build packaging."
    exit
fi

. "$PROJECT_DIR/config/release"

plist=""

if [ -f "$INFOPLIST_FILE" ]; then
  plist="$INFOPLIST_FILE"
else
  if [ -f "$SRCROOT/$INFOPLIST_FILE" ]; then
    plist="$SRCROOT/$INFOPLIST_FILE"
  else
    echo "Missing version in plist"
    exit 1
  fi
fi

# get the bundle version from the plist
version=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" $plist)

mkdir -p "$PROJECT_DIR/release"

zipname="$FULL_PRODUCT_NAME-$version.zip"
zip="$PROJECT_DIR/release/$zipname"
app="$CODESIGNING_FOLDER_PATH"

cd "$app/.."
rm -f "$zip"
zip -qr "$zip" "$FULL_PRODUCT_NAME"

sig=$(ruby "$PROJECT_DIR/vendor/Sparkle/sign_update.rb" "$zip" "$PROJECT_DIR/config/dsa_priv.pem")
length=$(stat -f%z "$zip")

url=$(curl -F "version=$version" -F "file=@$zip" "$smurl/upload?key=$smkey&length=$length")
url="${url?}" # strip trailing newline

if [[ $url != http* ]]; then
  echo "Upload error: $url"
  exit 1
fi

open "$smurl/?version=$version&length=$length&signature=$sig&url=$url"

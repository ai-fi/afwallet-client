#!/bin/sh

platform=$1

build_ios() {

    rm -rf /usr/local/lib/libgmp.a
    ln -s /usr/local/lib/libgmp.ios.a /usr/local/lib/libgmp.a
    echo "Build for iOS..."
    rm -rf ./Cargo.toml #./Cargo.lock
    cp ios/Cargo.toml .
    cargo lipo
    echo "Done!"
}

build_android() {
    echo "Build for Android..."
    rm -rf ./Cargo.toml #./Cargo.lock
    cp android/Cargo.toml .
    echo "Done!"
}

build_desktop() {

    rm -rf /usr/local/lib/libgmp.a
    ln -s /usr/local/lib/libgmp.osx.a /usr/local/lib/libgmp.a

    echo "Build for Desktop..."
    rm -rf ./Cargo.toml #./Cargo.lock
    cp desktop/Cargo.toml .
    cargo build
    echo "Done!"
}

if [ "w$platform" = "wios" ]; then
    build_ios
elif [ "w$platform" = "wandroid" ]; then
    build_android
else
    build_desktop
fi

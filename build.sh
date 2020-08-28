#!/bin/sh

platform=$1

build_ios() {
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

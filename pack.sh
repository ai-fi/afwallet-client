#!/bin/sh

mkdir -p ../release
cp target/release/afwallet-client ../release/
cp target/release/afwallet-signcli ../release/
cp target/release/afwallet-keygencli ../release/
cp -r static ../release/
cp Rocket.toml ../release/
cp run.sh ../release/







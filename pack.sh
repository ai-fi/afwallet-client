#!/bin/sh

mkdir -p ../release
cp target/release/counterseal ../release/
cp target/release/signcli ../release/
cp target/release/keygencli ../release/
cp -r static ../release/
cp Rocket.toml ../release/
cp run.sh ../release/



tar -czvf ../counterseal.$(date "+%Y%m%d%H%M%S").tar.gz ../release



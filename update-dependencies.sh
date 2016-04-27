#!/bin/bash

function update_repo() {
    echo -e "\n--> $2"
    if [ -e "$1" ]; then
        (cd "$1" || exit; git pull origin master)
    else
        git clone --depth 1 "https://github.com/$2" -b master
    fi
}

function third_parties() {
    update_repo mbedtls ARMmbed/mbedtls
    update_repo Catch philsquared/Catch
}

echo -e "preparing the latest version of 3rd-party dependencies ..."
mkdir -p 3rdparty
(cd 3rdparty || exit; third_parties)

echo -e "\ndone. the latest updates: ./3rdparty/"

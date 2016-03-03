#!/bin/bash

echo -e "preparing the latest version of 3rd-party dependencies ...\n"

mkdir -p 3rdparty
cd 3rdparty

echo -e "\n--> ARMmbed/mbedtls"
if [ -e mbedtls ]; then
    cd mbedtls
    git pull origin master
    cd ..
else
    git clone --depth 1 https://github.com/ARMmbed/mbedtls -b master
fi

echo -e "\n--> philsquared/Catch"
if [ -e Catch ]; then
    cd Catch
    git pull origin master
    cd ..
else
    git clone --depth 1 https://github.com/philsquared/Catch.git -b master
fi



cd ..
echo -e "\ndone."

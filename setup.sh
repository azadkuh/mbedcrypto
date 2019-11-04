#!/bin/bash

DEPDIR=.3rdparty
CATCH=catchorg/Catch2
MBEDTLS=ARMmbed/mbedtls

function help() {
    echo -e "
$> $0 [all | mbedtls | catch]

downloads following dependencies from github.com:
- github.com:${MBEDTLS}: crypto backend
- github.com:${CATCH}: for unit testing
into ./${DEPDIR}/

as <${CATCH}> and <${MBEDTLS}> are large repositories
with deep histories, this script just downloads the files from master branch
rather than git cloning (or adding them as git submodules/subtree).
"
}

function status() {
    echo -e "downloading github.com:$1 into ./${DEPDIR}/ ..."
}

function fetch_catch2() {
    status ${CATCH}
    mkdir -p catch2
    curl -ss -L "https://github.com/${CATCH}/raw/master/single_include/catch2/catch.hpp" -o catch2/catch.hpp
    echo "    done."
}

function fetch_mbedtls() {
    status ${MBEDTLS}
    rm -rf mbedtls*
    curl -ss -L "https://github.com/${MBEDTLS}/archive/master.tar.gz" | tar xz
    mv mbedtls-master mbedtls
    echo "    done."
}

function make_ctags() {
    ctags --exclude=.build --exclude=.3rdparty \
        --c++-kinds=+cefgnps --fields=+iaS --extra=+fq -R .
}


CMD="help"
[[ -n "$1" ]] && CMD="$1"

case $CMD in
    catch|catch2)
        mkdir -p $DEPDIR
        (cd $DEPDIR || exit; fetch_catch2)
        ;;

    mbedtls)
        mkdir -p $DEPDIR
        (cd $DEPDIR || exit; fetch_mbedtls)
        ;;

    all)
        mkdir -p $DEPDIR
        (cd $DEPDIR || exit; fetch_catch2 && fetch_mbedtls)
        ;;

    tags|ctag|ctags)
        make_ctags
        ;;

    help|*)
        help
        ;;
esac

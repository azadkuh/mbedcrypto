workspace "mbedcrypto"
    configurations {"Release"}
    objdir "tmp"
    targetdir "xbin"

    language "C++"
    includedirs { ".", "./include", "./3rdparty/mbedtls/include" }

    filter "configurations:Release"
        optimize "On"
        if os.is("linux") or os.is("macosx") then
            buildoptions{"-O3 -g0 -Wall -Wextra -Wnon-virtual-dtor -pedantic -Wcast-align -Wunused -Woverloaded-virtual -Wno-unused-parameter"}

        elseif os.is("windows") then
            defines {"NDEBUG"}
            buildoptions{"-nologo -Zc:wchar_t -FS -O2 -MD -Zc:strictStrings -W3" }
        end

project "mbedtls"
    kind "StaticLib"
    location "tmp"
    language "C"
    defines { "MBEDTLS_CONFIG_FILE=\"\\\"./src/mbedtls_config.h\\\"\"" }
    files {"./src/mbedtls_config.h",
    "./3rdparty/mbedtls/library/base64.c",
    "./3rdparty/mbedtls/library/md4.c",
    "./3rdparty/mbedtls/library/md5.c",
    "./3rdparty/mbedtls/library/sha1.c",
    "./3rdparty/mbedtls/library/sha256.c",
    "./3rdparty/mbedtls/library/sha512.c",
    "./3rdparty/mbedtls/library/md_wrap.c",
    "./3rdparty/mbedtls/library/md.c",
    "./3rdparty/mbedtls/library/blowfish.c",
    "./3rdparty/mbedtls/library/aes.c",
    "./3rdparty/mbedtls/library/aesni.c",
    "./3rdparty/mbedtls/library/des.c",
    "./3rdparty/mbedtls/library/cipher_wrap.c",
    "./3rdparty/mbedtls/library/cipher.c",
    "./3rdparty/mbedtls/library/entropy.c",
    "./3rdparty/mbedtls/library/entropy_poll.c",
    "./3rdparty/mbedtls/library/ctr_drbg.c",
    "./3rdparty/mbedtls/library/rsa.c",
    "./3rdparty/mbedtls/library/pem.c",
    "./3rdparty/mbedtls/library/bignum.c",
    "./3rdparty/mbedtls/library/oid.c",
    "./3rdparty/mbedtls/library/asn1parse.c",
    "./3rdparty/mbedtls/library/pkparse.c",
    "./3rdparty/mbedtls/library/pk_wrap.c",
    "./3rdparty/mbedtls/library/pk.c",
    "./3rdparty/mbedtls/library/oid.c",
    "./3rdparty/mbedtls/library/platform.c",
    }


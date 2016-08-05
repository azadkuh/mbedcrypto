#mbedcrypto
`mbedcrypto` is a portable, small, easy to use, feature rich and fast
`c++14` library for cryptography based on fantastic and clean
[mbedtls](https://github.com/ARMmbed/mbedtls)<sup>[note](#mbedtls)</sup>
<sup>[note](#cryptography)</sup>.

a sister project for `Qt5` developers is available as
[qpolarssl](https://github.com/azadkuh/qpolarssl), although `mbedcrypto` is
newer and has more features with smaller footprint and can be configured to
support `QByteArray` through the api.


for more information see [wiki](https://github.com/azadkuh/mbedcrypto/wiki) page.

----

## features and highlights

- *small size*: the `mbedcrypto` is less than `250KB` in size (as single shared
 library and stripped under Linux and OS X) with all *predefined* algorithms.
 it can be easily embedded into your service or application.
- *easy to use*: although cryptography<sup>[note](#cryptography)</sup> is
 complex and complicated, `mbedcrypto` hides most of the complexities, tries to
 be easy to use and hard to misuse.
- *portable*: needs an standard `c++14` compiler and compliant `stl`,
 compiled and tested by:
  - `g++ 5.x+ / 6+` under `linux`
  - `clang 3.6+` under `os x`
  - `mingw 5.x+` under `msys2` (windows 8.1)
  - `msvc 2015` community edition under `windows 7`
- *low dependency*:
  - the `mbedtls`<sup>[note](#mbedtls)</sup> as underlying cryptography engine,
   is the only mandatory dependency.
  - [catch](https://github.com/philsquared/Catch): only for unit testing.
  - `cmake` for building the library and the unit test app.
- *high+low level*: both high level (c++ objects / exception) and low level (c
 pointer / error code) functions are available.
- *highly configurable*: to add or remove the algorithms, simply change `cmake`
 build options. see [build options](#build-options)
- *optional suppport for Qt5*: optional support for **Qt5**'s `QByteArray` is also
available.


## supported algorithms
following algorithms are included in `mbedcrypto` in *default build* (see
 [wiki usage](https://github.com/azadkuh/mbedcrypto/wiki/usage:-general)):

- **binary/text conversions**: see [wiki:
samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-text-binary-conversion)
  - `hex`
  - `base64`

- **hashes (message digest)**: see [wiki:
samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-hash-and-message-digest)
  - `md5`
  - `sha1`
  - `sha224` / `sha256`
  - `sha384` / `sha512`
  - `hmac`
  - optional hashes: `ripemd160`, `md4`, `md2` (deprecated)

- **ciphers (symmetric)**: see [wiki:
samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-cipher-(symmetric))
  - `aes` (128, 192, 256 bits) and `aes-ni` (hardware accelerated)
  - `des` and `3des` (triple-des)
  - optional ciphers: `blowfish`, `camellia` and `arc4`

- **cipher block modes**:
  - `ecb` electronic codebook
  - `cbc` cipher block chaining
  - `ctr` counter mode
  - `gcm` Galois/counter and `ccm` (counter cbc-mac) modes.
   see [authneticated encryption with additional data
   (AEAD)](https://en.wikipedia.org/wiki/Authenticated_encryption)
  - optional block modes: `cfb`, `stream` (for `arc4`)

- **paddings**:
  - `pkcs7`
  - *one and zeros*
  - *zeros and length*
  - *zeros*

- **random byte generator**: see [wiki
samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-random-byte-generator)
  - `ctr_drbg` counter mode deterministic random byte generator based on
   `aes-256` [NIST SP 800-90](https://en.wikipedia.org/wiki/NIST_SP_800-90A)

- **pki (asymmetric)**: public key infrastructure, see [wiki: rsa
samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-PK-(asymmetric)-RSA)
and [wiki: ec samples](https://github.com/azadkuh/mbedcrypto/wiki/how-to:-PK-(asymmetric)-EC)
  - `rsa`
  - `pem` and `der` key formats (ASN.1)
  - optional pks: `eckey` elliptic curve, `eckey_dh` elliptic key
   Diffie–Hellman, `ecdsa` elliptic key digital signature algorithm, `rsa_alt`
   and `rsassa_pss` RSA standard signature algorithm, probabilistic signature
   scheme
  - optional `rsa` key generator
  - optional `ec curves` from well known domain parameters as `NIST`, `Kolbitz`,
  `brainpool` and `Curve25519`.

total number of supported algorithms:

- hashes: 9
- paddings: 5
- ciphers: 47
- pki: 6

see [types.hpp](./include/mbedcrypto/types.hpp)


## setup
after cloning this repository, first update the dependencies:
```bash
#on mbedcrypto directory
$medcrypto/> ./update-dependencies.sh
```
this script automatically setups `3rdparty` directory, then tries to pull or
update dependencies from github.

```bash
$medcrypto/> mkdir build
$medcrypto/> cd build
$build/> cmake ..
$build/> make
```

> the `mbedcrypto` library and the companion unit test app would be built into
> `xbin` directory.

see [wiki: setup and build](https://github.com/azadkuh/mbedcrypto/wiki/setup-and-build)
---

## build options
these are the most important build options:

| options          | default | message                                                         |
| :---             | :---:   | :---                                                            |
| BUILD_MD2        | OFF     | enable md2 hash (unsecure and deprecated)                       |
| BUILD_MD4        | OFF     | enable md4 hash                                                 |
| BUILD_RIPEMD160  | OFF     | enable ripemd160 hash                                           |
| BUILD_CFB        | OFF     | enable cfb (cipher feedback mode)                               |
| BUILD_CTR        | ON      | enable ctr (cipher counter mode)                                |
| BUILD_GCM        | ON      | enable gcm (Galois cipher mode, for aead cryptography)          |
| BUILD_CCM        | ON      | enable ccm (counter cbc-mac cipher mode, for aead cryptography) |
| BUILD_DES        | ON      | enable des and triple-des cipher                                |
| BUILD_BLOWFISH   | OFF     | enable blowfish cipher                                          |
| BUILD_CAMELLIA   | OFF     | enable camellia cipher                                          |
| BUILD_ARC4       | OFF     | enable arc4 cipher (unsecure)                                   |
| BUILD_PK_EXPORT  | ON      | enable export keys in pem or der format                         |
| BUILD_RSA_KEYGEN | ON      | enable rsa key generator                                        |
| BUILD_EC         | OFF     | enable eckey, eckey_dh and ecdsa algorithms                     |
| BUILD_QT5_BIND   | OFF     | also adds adaptors around **Qt5**'s `QByteArray`                |

please see [CMakeLists.txt](./CMakeLists.txt) for the full list.


---

## tests
samples and unit tests are available under [tests/tdd](./tests/tdd/) folder.

```bash
#run the tests
$xbin/> ./tests
```

possible output:
```text
supports 6 hash algorithms: MD5 , SHA1 , SHA224 , SHA256 , SHA384 , SHA512 ,
supports 5 padding algorithms: PKCS7 , ONE_AND_ZEROS , ZEROS_AND_LEN , ZEROS ,
         NONE ,
supports 6 block modes: NONE , ECB , CBC , CTR , GCM , CCM ,
supports 21 cipher algorithms: AES-128-ECB , AES-192-ECB , AES-256-ECB ,
         AES-128-CBC , AES-192-CBC , AES-256-CBC , AES-128-CTR , AES-192-CTR ,
         AES-256-CTR , AES-128-GCM , AES-192-GCM , AES-256-GCM , DES-ECB ,
         DES-CBC , DES-EDE-ECB , DES-EDE-CBC , DES-EDE3-ECB , DES-EDE3-CBC ,
         AES-128-CCM , AES-192-CCM , AES-256-CCM ,
 this system supports AESNI (hardware accelerated AES)
 this build supports AEAD (authenticated encryption with additional data)
supports 4 pk (public key) algorithms: RSA , EC , EC_DH , ECDSA ,
 this build supports PK export (*.pem, *.der) facility
 this build supports RSA key generation
 this build supports EC (elliptic curve) key generation
supports 12 elliptic curves: SECP192R1 , SECP224R1 , SECP256R1 , SECP384R1 ,
         SECP521R1 , SECP192K1 , SECP224K1 , SECP256K1 , BP256R1 , BP384R1 ,
         BP512R1 , CURVE25519 ,

===============================================================================
All tests passed (952 assertions in 17 test cases)

```
---

## notes

### cryptography
[cryptography](https://en.wikipedia.org/wiki/Outline_of_cryptography) is both
complex and complicated, it requires a vast knowledge of mathematics, concepts,
principles, algorithms, standards, conventions, continuous investigation of
attacks, ...

> As cryptography is mostly used to protect sensitive data, writing a library
> for it is a daunting task and difficult by any factor.

So instead of writing a library from scratch, `mbedcrypto` stands on the
shoulders of giants, `mbedtls` is this case.

### mbedtls
Although [mbedtls](https://github.com/ARMmbed/mbedtls) is mostly a `TLS/SSL`
library for embedded devices, it has already implemented the most famous and
widely used cryptographic algorithms and actively developed and maintained.

Arguably `mbedtls` has cleaner code than `openssl`, it's easier to read, use
and maintain, and it has been designed for efficiency and portability from
scratch (for embedded devices), and has many advantages over `openssl` like as
readability, size, compiling and setup, … to name a few.


## disclaimer

- implementing an easy-to-use, lightweight and portable `c++` library for
cryptography are the main purpose of `mbedcrypto`.
- there are many more algorithms in cryptographic libraries, the focus of
`mbedcrypto` is on the most important or widely used algorithms, tries to be
simple and not to bloat your application.
- as mentioned in [notes](#notes), the cryptography can be divided into several
areas of study and best practices, I'm not a guru nor a specialist in this
field.


> If you have any ideas, critiques, suggestions or whatever you want to call
> it, please open an issue. I'll be happy to hear from you what you'd see in
> this lib. I think about all suggestions, and I try to add those that make
> sense.


## license
Distributed under the MIT license. Copyright (c) 2016, Amir Zamani.

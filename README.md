# mbedcrypto
`mbedcypto` is a portable, small, easy to use, feature rich and fast `c++11/14` library for cryptography based on fantastic and clean [mbedtls](https://github.com/ARMmbed/mbedtls)<sup>[note](#mbedtls)</sup> <sup>[note](#cryptography)</sup>.

a sister project for `Qt5` developers is available as [qpolarssl](https://github.com/azadkuh/qpolarssl), `mbedcrypto` is newer and has more feature, cleaner api with smaller footprint.



## features and highlights

- *small size*: the `mbedcrypto` is less than `250KB` in size (under Linux and OS X) with all *predefined* algorithms. it can be easily embedded into your service or application.
- *easy to use*: although cryptography<sup>[note](#cryptography)</sup> is complex and complicated, `mbedcrypto` hides most of the complexities, tries to be easy to use and hard to misuse. see [samples](#usage)
- *portable*: needs an standard `c++11/14` compiler and compliant `stl`, compiled and tested by:
  - `gcc 5.x` under `linux`
  - `clang` under `os x`
  - `msvc 2015` community edition under `windows 7`
- *low dependency*:
  - the `mbedtls`<sup>[note](#mbedtls)</sup> as underlying cryptography engine, is the only mandatory dependency.
  - [catch](https://github.com/philsquared/Catch): only for unit testing.
  - `cmake` (or optionally `premake5`) for building the library and the unit test app.
- *high+low level*: both high level (c++ objects / exception) and low level (c pointer / error code) functions are available. see [samples](#usage)
- *highly configurable*: by updating [src/mbedtls_config.h](./src/mbedtls_config.h) adding or removing algorithms are quite easy.


## supported algorithms
following algorithms are included in `mbedcrypto` in *default build* (see [samples](#usage)):

- **binary/text conversions**:
  - `hex`
  - `base64`

- **hashes (message digest)**:
  - `md4`
  - `md5`
  - `sha1`
  - `sha224` / `sha256`
  - `sha384` / `sha512`
  - `hmac`
  - optional hashes: `ripemd160`, `md2` (deprecated)

- **ciphers (symmetric)**:
  - `aes` (128, 192, 256 bits) and `aes-ni` (hardware accelerated)
  - `des` and `3des` (triple des)
  - `blowfish`
  - optional ciphers: `camellia` and `arc4`

- **cipher block modes**:
  - `ecb` electronic codebook
  - `cbc` cipher block chaining
  - `cfb` cipher feedback
  - `ctr` counter mode
  - optional block modes: `gcm` Galois/counter mode, `stream` (for `arc4`) and `ccm` (= cbc + mac)

- **paddings**:
  - `pkcs7`
  - *one and zeros*
  - *zeros and length*
  - *zeros*

- **random byte generator**:
  - `ctr_drbg` counter mode deterministic random byte generator based on `aes-256` [NIST SP 800-90](https://en.wikipedia.org/wiki/NIST_SP_800-90A)

- **pki (asymmetric)**: public key infrastructure
  - `rsa`
  - optional pks: `eckey` elliptic curve, `eckey_dh` elliptic key Diffie–Hellman, `ecdsa` elliptic key digital signature algorithm, `rsa_alt` and `rsassa_pss` RSA standard signature algorithm, probabilistic signature scheme



## setup
after cloning this repository, first update the dependencies:
```bash
# on mbedcrypto directory
$> ./update-dependencies.sh
```
this script automatically setups `3rdparty` directory, then tries to fetch or update dependencies from github.

### cmake
to make the project by `cmake`:
```bash
$> mkdir build
$> cd build

# under Linux or OS X
$> cmake ..
$> make

# under Windows (MSVC)
$> cmake ..
$> cmake --build . --config Release
```


optionally if you use `gcc` or `clang`, you can also build `mbedcrypto` as a shared library as:
```bash
$> cmake .. -DBUILD_SHARED_LIBS=ON
$> make
```

### premake5
it's also possible to build the project by `premake5` as:
```bash
# on mbedcrypto directory

# under Linux / OSX
$> premake5 gmake
$> make

# under Windows (MSVC)
$> premake5.exe vs2015 # or any other installed toolset
$> msbuild.exe mbedcrypto.sln /p:Configuration=Release
```

---
`premake5` script may have less feature or maintained less frequently than `cmake`.
> the `mbedcrypto` library and the companion unit test app would be built on `xbin` directory.

## usage

### error handling
```cpp
//
```

### available algorithms

```cpp
//
```

### hashes
```cpp
auto hvalue = hash::make(source, hash_t::sha256);
std::cout << to_base64(hvalue) << std::endl;
```

### ciphers
```cpp
//
```

### random byte generator
```cpp
//
```

### pk
```cpp
//
```


## notes

### cryptography
[cryptography](https://en.wikipedia.org/wiki/Outline_of_cryptography) is both complex and complicated, it requires a vast knowledge of mathematics, concepts, principles, algorithms, standards, conventions, continuous investigation of attacks, ...
> As cryptography is mostly used to protect sensitive data, writing a library for it is a daunting task and difficult by any factor.

So instead of writing a library from scratch, `mbedcrypto` stands on the shoulders of giants, `mbedtls` is this case.

### mbedtls
Although [mbedtls](https://github.com/ARMmbed/mbedtls) is mostly a `TLS/SSL` library for embedded devices, it has already implemented the most famous and widely used cryptographic algorithms and actively developed and maintained.

Arguably `mbedtls` has cleaner code than `openssl`, it's easier to read, use and maintain, and it has been designed for efficiency and portability from scratch (for embedded devices), and has many advantages over `openssl` like as readability, size, compiling and setup, … to name a few.


## disclaimer

- implementing an easy-to-use, lightweight and portable `c++` library for cryptography are the main purpose of `mbedcrypto`.
- there are many more algorithms in cryptographic libraries, the focus of `mbedcrypto` is on the most important or widely used algorithms, tries to be simple and not to bloat your application.
- as mentioned in [notes](#notes), cryptography is a huge subject, I'm not a guru nor a specialist in this field.


> If you have any ideas, critiques, suggestions or whatever you want to call it, please open an issue. I'll be happy to hear from you what you'd see in this lib. I think about all suggestions, and I try to add those that make sense.


## license
Distributed under the MIT license. Copyright (c) 2016, Amir Zamani.


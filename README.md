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

- **binary/text conversions**: see [samples](#text-binary-conversion)
  - `hex`
  - `base64`

- **hashes (message digest)**: see [samples](#hashes)
  - `md4`
  - `md5`
  - `sha1`
  - `sha224` / `sha256`
  - `sha384` / `sha512`
  - `hmac`
  - optional hashes: `ripemd160`, `md2` (deprecated)

- **ciphers (symmetric)**: see [samples](#ciphers)
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

- **random byte generator**: see [samples](#random-byte-generator)
  - `ctr_drbg` counter mode deterministic random byte generator based on `aes-256` [NIST SP 800-90](https://en.wikipedia.org/wiki/NIST_SP_800-90A)

- **pki (asymmetric)**: public key infrastructure, see [samples](#pks)
  - `rsa`
  - optional pks: `eckey` elliptic curve, `eckey_dh` elliptic key Diffie–Hellman, `ecdsa` elliptic key digital signature algorithm, `rsa_alt` and `rsassa_pss` RSA standard signature algorithm, probabilistic signature scheme



## setup
after cloning this repository, first update the dependencies:
```bash
# on mbedcrypto directory
$> ./update-dependencies.sh
```
this script automatically setups `3rdparty` directory, then tries to fetch or update dependencies from github.

there are two methods to build the `mbedcrypto`, although my `premake5` script may have less feature or maintained less frequently than the `cmake` one.

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

> the `mbedcrypto` library and the companion unit test app would be built on `xbin` directory.

---

## usage

### buffer_t
`buffer_t` (synonym for `std::string`)
```cpp
namespace mbedcrypto {
  using buffer_t = std::string;
}
```
is widely used in `mbedcrypto` api as main data container for input / output methods.

current `std::string` implementations are known to be contiguous, so I prefer `std::string` over `std::vector<unsigned char>` because it helps users to easily feed both text and binary buffers into `mbedtls` api without any cast or conversion.

see [configs.hpp](./include/mbedcrypto/configs.hpp)


### error handling
`mbedcrypto` objects and functions throw [`mbedcrypro::exception`](./include/mbedcrypto/exception.hpp) unless they're tagged by `noexcept` keyword.
```cpp
try {
  //
  // mbedcrypto codes ...
  //
} catch ( mbedcrypto::exception& cerr ) {
  std::cerr << "the expanded error message is: " << cerr.to_string() << std::endl;
}

```

the low level functions returns a non-zero `int` as an error:
```cpp
int ret = an_object.a_low_level_method(...);
if ( ret != 0 ) {
  std::cout << "underlying error code: " << mbedcrypto::mbedtls_error_string(ret) << std::endl;
}
```

### available algorithms
to list all available (included in build) algorithms:
```cpp
using namespace mbedcrypto;

auto hashes = installed_hashes(); // returns std::vector<mbedcrypto::hasht_t>
// similarly
auto paddings = installed_paddings();
auto ciphers  = installed_ciphers();
auto pks      = installed_pks();

std::cout << "supports " << hashes.size() << " hash algorithms: ";
for ( auto h : hashes ) {
  // convert type to string
  std::cout << to_string(h) << " , ";
}

// convert from string to a type
auto htype = from_string<hash_t>("sha384");
if ( htype != hash_t::none ) {
}
```

to check for availability of a feature:
```cpp
// to check a single feature
if ( cipher::supports_aes_ni() ) {
  std::cout << "this system supports AESNI (hardware accelerated AES)" << std::endl;
}

// check by enum class
if ( supports(cipher_t::aes_256_cbc)   &&   supports(padding_t::pkcs7) ) {
  // do stuff
}
// check by algorithm name
if ( supports_hash("sha1")    &&    supports_pk("rsa") ) {
  // sign a message ...
}
// both upper and lower case are supported
if ( supports_cipher("CAMELLIA_128_CBC") ) {
}
```

see [types.hpp](./include/mbedcrypto/types.hpp)


### text-binary conversion
```cpp
using namespace mbedcrypto;

std::fstream fpng = open_a_png_file(...);
std::string png_data; // binary data
fpng >> png_data;

auto png_hex = to_hex(png_data);
auto png_b64 = to_base64(png_data);

REQUIRE( from_hex(png_hex) == from_base64(png_b64) );

// to get the required base64 size
size_t encode_size = base64::encode_size(png_data);
png_b64 = base64::encode(png_data);

REQUIRE( base64::decode_size(png_b64) == png_data.size() );

REQUIRE_THROWS( base64::decode("invalid base64 string @#$%#^$") );
```

see [tcodec.hpp](./include/mbedcrypto/tcodec.hpp)


### hashes
```cpp
using namespace mbedcrypto;

// by single shot functions
auto hvalue = make_hash(hash_t::sha256, source_data);
std::cout << to_base64(hvalue) << std::endl;

auto hmac_value = hmac::make(hash_t::md5, key_data, source_data);
```
or
```cpp
hash h0(hash_t::ripemd160);
hash h1(from_string<hash_t>("sha1"));

h1.start();
while ( ... ) {
  h1.update(read_some_data());
}
auto hvalue = h1.finish();

// re-use
h1.start();
h1.update();
h1.finish();
```

see [hash.hpp](./include/mbedcrypto/hash.hpp)


### ciphers
If a cipher block mode allows, the `cipher` class automatically breaks input data into chunks (`cipher::block_size()`) and frees the user from breaking/merging of input/output data:

```cpp
using namespace mbedcrypto;

std::string source_plain_data = read_from_somewhere();

// encrypt and decrypt by single-shot functions
auto ciphered_buffer = cipher::encrypt(
    cipher_t::aes_256_cbc,
    padding_t::pkcs7,
    initial_vector_data,  // get iv size from cipher::iv_size()
    key_data,             // get key length in bit by cipher::key_bitlen()
    source_plain_data     // could be in any size because of cbc block mode
    );

auto decrypted_buffer = cipher::decrypt(
    cipher_t::aes_256_cbc,
    padding_t::pkcs7,
    initial_vector_data,
    key_data,
    ciphered_buffer
    );

REQUIRE( source_plain_data == decrypted_buffer );
```

or
```cpp
// construct and setup properties
cipher cipdec(cipher_t::aes_256_cbc);
cipdec
  .padding(padding_t::pkcs7)
  .iv(iv_data)
  .key(key_data, cipher::decrypt_mode);

// by start() / update()s / finish()
cipdec.start();
std::string decrypted_data;
while ( ... ) {
  decrypted_data += cipdec.update(read_some_encrypted_data());
}
decrypted_data += cipdec.finish();
REQUIRE( source_plain_data == decrypted_data );

// re-use the object
cipdec.start();
cipdec.update(...); // or multiple updates
cipdec.finish();

// single shot re-use
auto other_decrypted = cipdec.crypt(other_encrypted_data);
```

see [cipher.hpp](./include/mbedcrypto/cipher.hpp)


### random byte generator
```cpp
mbedcrypto::random rnd_generator;
auto random_data1 = rnd_generator.make(256); // in bytes
auto random_data2 = rnd_generator.make(32);  // in bytes
//
```

see [random.hpp](./include/mbedcrypto/random.hpp)


### pks
sign and verify:
```cpp
using namespace mbedcrypto;

std::string message = read_message_from_somewhere();

pki pri;
pri.parse_key(private_key_data, optional_password);
// or load from a file
pri.load_key("private_key.pem");

auto signature = pri.sign(message, hash_t::sha1);


pki pub;
pub.parse_public_key(public_key_data);
REQUIRE( pub.verify(signature, message, hash_t::sha1);
```
to encrypt and decrypt by pki:
```cpp
const auto hvalue = hash::make(hash_t::sha256, message);

pki pke;
pke.parse_public_key(public_key_data);

auto encv = pke.encrypt(message, hash_t::sha256);
// or
auto encv = pke.encrypt(hvalue);

pki pkd;
pkd.parse_key(private_key_data);
auto decv = pkd.decrypt(encv);
REQUIRE( decv == hvalue );
```

see [pki.hpp](./include/mbedcrypto/pki.hpp)

---

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
- as mentioned in [notes](#notes), the cryptography can be divided into several areas of study and best practices, I'm not a guru nor a specialist in this field.


> If you have any ideas, critiques, suggestions or whatever you want to call it, please open an issue. I'll be happy to hear from you what you'd see in this lib. I think about all suggestions, and I try to add those that make sense.


## license
Distributed under the MIT license. Copyright (c) 2016, Amir Zamani.


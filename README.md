# mbedcrypto
`mbedcrypto` is a portable, small, easy to use, feature rich and fast
`c++11/14` library for cryptography based on fantastic and clean
[mbedtls](https://github.com/ARMmbed/mbedtls)<sup>[note](#mbedtls)</sup>
<sup>[note](#cryptography)</sup>.

a sister project for `Qt5` developers is available as
[qpolarssl](https://github.com/azadkuh/qpolarssl), also `mbedcrypto` is newer
and has more features with smaller footprint.



## features and highlights

- *small size*: the `mbedcrypto` is less than `250KB` in size (stripped under Linux and
 OS X) with all *predefined* algorithms. it can be easily embedded into
 your service or application.
- *easy to use*: although cryptography<sup>[note](#cryptography)</sup> is
 complex and complicated, `mbedcrypto` hides most of the complexities, tries to
 be easy to use and hard to misuse. see [samples](#usage)
- *portable*: needs an standard `c++11/14` compiler and compliant `stl`,
 compiled and tested by:
  - `gcc 5.x+` under `linux`
  - `clang 3.6+` under `os x`
  - `msvc 2015` community edition under `windows 7`
- *low dependency*:
  - the `mbedtls`<sup>[note](#mbedtls)</sup> as underlying cryptography engine,
   is the only mandatory dependency.
  - [catch](https://github.com/philsquared/Catch): only for unit testing.
  - `cmake` for building the library and the unit test app.
- *high+low level*: both high level (c++ objects / exception) and low level (c
 pointer / error code) functions are available. see [samples](#usage)
- *highly configurable*: to add or remove the algorithms, simply change `cmake`
 build options. see [build options](#build-options)


## supported algorithms
following algorithms are included in `mbedcrypto` in *default build* (see
 [samples](#usage)):

- **binary/text conversions**: see [samples](#text-binary-conversion)
  - `hex`
  - `base64`

- **hashes (message digest)**: see [samples](#hashes)
  - `md5`
  - `sha1`
  - `sha224` / `sha256`
  - `sha384` / `sha512`
  - `hmac`
  - optional hashes: `ripemd160`, `md4`, `md2` (deprecated)

- **ciphers (symmetric)**: see [samples](#ciphers)
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

- **random byte generator**: see [samples](#random-byte-generator)
  - `ctr_drbg` counter mode deterministic random byte generator based on
   `aes-256` [NIST SP 800-90](https://en.wikipedia.org/wiki/NIST_SP_800-90A)

- **pki (asymmetric)**: public key infrastructure, see [samples](#pks)
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
# on mbedcrypto directory
$medcrypto/> ./update-dependencies.sh
```
this script automatically setups `3rdparty` directory, then tries to pull or
update dependencies from github.

### Unices
under Linux, OS X:
```bash
$medcrypto/> mkdir build
$medcrypto/> cd build

$build/> cmake ..
$build/> make
```

> the `mbedcrypto` library and the companion unit test app would be built on
> `xbin` directory.

### Windows
under Windows (MSVC) probably:
```bash
$medcrypto/> mkdir build
$medcrypto/> cd build

$build/> cmake ..
$build/> cmake --build . --config Release
```


### doxygen
under **Unices** if you have already installed `doxygen`:
```bash
# builds api documents into ./docs
$build> make docs
# removes ./docs
$build> make clean_docs
```

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
| BUILD_EC         | OFF     | enable eckey and eckey_dh public key algorithms                 |
| BUILD_ECDSA      | OFF     | enable ecdsa algorithms                                         |

please see [CMakeLists.txt](./CMakeLists.txt) for the full list.

to add or remove algorithms or features:
```bash
# cmake, ccmake or cmake-gui
$build/> cmake .. -DBUILD_CAMELLIA=ON -DBUILD_PK_EXPORT=ON -DBUILD_RSA_KEYGEN=ON

# or optionally
$build/> ccmake .

# to disable making of the test app:
$build/> cmake .. -DBUILD_TESTS=OFF
```

optionally if you use `gcc` or `clang`, you can also build `mbedcrypto` as a
shared library as:
```bash
$build/> cmake .. -DBUILD_SHARED_LIBS=ON
$build/> make
```

---

## usage

### buffer_t
`buffer_t` (synonym for `std::string`)
```cpp
namespace mbedcrypto {
  using buffer_t = std::string;
}
```
is widely used in `mbedcrypto` api as main data container for input / output
methods.

current `std::string` implementations are known to be *contiguous*, so I prefer
`std::string` over `std::vector<unsigned char>` because it helps users to
easily feed both text and binary buffers into `mbedtls` api without any cast or
conversion.

see [configs.hpp](./include/mbedcrypto/configs.hpp)


### error handling
`mbedcrypto` objects and functions throw
[`mbedcrypro::exception`](./include/mbedcrypto/exception.hpp) unless they're
tagged by `noexcept` keyword.
```cpp
try {
  //
  // mbedcrypto codes ...
  //
} catch ( mbedcrypto::exception& cerr ) {
  std::cerr << "the expanded error message is: "
      << cerr.what() << std::endl;
  int c_error_code = cerr.code(); // the underlying error code
}
```

the structure of `cerr.what()`:
```text
[message, prefix or function name][(error code in hex): [module name] error string]

ex:
mbedtls_md_starts(-0x5100): MD - Bad input parameters to function
 - function name: mbedtls_md_starts
 - error code: -0x5100
 - module name: MD (message digest)
```

the low level functions returns a non-zero `int` as an error and are tagged by
`noexcept`:
```cpp
int ret = an_object.a_low_level_method(...);
if ( ret != 0 ) {
  std::cout << "underlying error code: "
      << mbedcrypto::mbedtls_error_string(ret) << std::endl;
}
```

### available algorithms
to list all available (included in build) algorithms:
```cpp
using namespace mbedcrypto;

auto hashes = installed_hashes(); // returns std::vector<mbedcrypto::hasht_t>
std::cout << "supports " << hashes.size() << " hash algorithms: ";
for ( auto h : hashes ) { // print all installed hashes
  // convert type to string
  std::cout << to_string(h) << " , ";
}

// similarly
auto paddings = installed_paddings();
auto bmodes   = installed_block_modes();
auto ciphers  = installed_ciphers();
auto pks      = installed_pks();
auto curves   = installed_curves();

// convert from string to a type
auto htype = from_string<hash_t>("sha256");
if ( htype != hash_t::none ) {
}
```

to check for availability of a feature:
```cpp
// check by type (enum class)
if ( supports(cipher_t::aes_256_cbc)   &&   supports(pk_t::rsa) ) {
  // do stuff
}
// check by algorithm name
if ( supports_hash("sha1")    &&    supports_pk("rsa") ) {
  // sign a message ...
}
// both upper and lower case are supported
if ( supports_cipher("CAMELLIA_128_CBC") ) {
}

// to check a single feature
if ( suppurts(features::aes_ni) ) {
  std::cout << "this system supports AESNI (hardware accelerated AES)" << std::endl;
}

if ( supports(features::aead)    &&    supports(cipher_bm::gcm) ) {
  // do GCM authenticated encryption with additional data
}
```

see [types.hpp](./include/mbedcrypto/types.hpp)


### text-binary conversion
handy utility to convert binary into (or from) text:
```cpp
using namespace mbedcrypto;

std::fstream fpng = open_a_png_file(...);
std::string bin_data; // binary data
fpng >> bin_data;

auto png_hex = to_hex(bin_data);
auto png_b64 = to_base64(bin_data);

REQUIRE( from_hex(png_hex) == from_base64(png_b64) );

// to get the required base64 size
size_t encode_size = base64::encode_size(bin_data);
png_b64 = base64::encode(bin_data);

REQUIRE( base64::decode_size(png_b64) == bin_data.size() );

REQUIRE_THROWS( base64::decode("invalid base64 string @#$%#^$") );
```

see [tcodec.hpp](./include/mbedcrypto/tcodec.hpp)


### hashes
(cryptographic hashes also known as message digests)
```cpp
using namespace mbedcrypto;

// by single shot functions
auto hash_value = make_hash(hash_t::sha256, source_data);
auto hmac_value = hmac::make(hash_t::sha1, key_data, source_data);

std::cout << to_base64(hash_value) << std::endl;
```
or
```cpp
hash h0(hash_t::ripemd160);
hash h1(from_string<hash_t>("sha1"));

h1.start();
while ( ... ) {
  h1.update(read_some_data());
}
auto hash_value = h1.finish();

// re-use
h1.start();
h1.update(...); // single or multiple updates
hash_value = h1.finish();
```

see [hash.hpp](./include/mbedcrypto/hash.hpp)


### ciphers
If a cipher block mode allows, the `cipher` class automatically breaks input
data into **chunks** (`cipher::block_size()`) and frees the user from
breaking/merging of input/output data:

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

to use [authenticated encryption with associated data (aka
aead)](https://en.wikipedia.org/wiki/Authenticated_encryption):
```cpp
std::string the_additional_data = ...;

auto encr = cipher::encrypt_aead(
    cipher_t::aes_256_ccm,
    iv_data,
    key_data,
    the_additional_data,
    source_plain_data
    );  ///< returns a std::tuple< computed_tag, encrypted_data >


auto decr = cipher::decrypt_aead(
    cipher_t::aes_256_ccm,
    iv_data,
    key_data,
    the_additional_data,
    encr
    );  ///< returns a std::tuple< authentication_status, decrypted_data >


  REQUIRE( std::get<0>(decr) == true ); // authenticated?
  REQUIRE( std::get<1>(decr) == source_plain_data );
```


or by reusable object:
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
decrypted_data = cipdec.crypt(encrypted_data);
```

see [cipher.hpp](./include/mbedcrypto/cipher.hpp)


### random byte generator
to make cryptographically secure psuedo random bytes:

```cpp
rnd_generator rgen;
auto random_data1 = rgen.make(256); // in bytes
// entropy and ctr_drbg are not so cheap, reuse them:
auto random_data2 = rgen.make(32);  // in bytes

// update internal state with custom data (may helps entropy)
rgen.update(some_random_volatile_data);
auto nonce = rgen.make(64);
```

see [rnd_generator.hpp](./include/mbedcrypto/rnd_generator.hpp)


### pks
playing with `rsa` keys:

```cpp
using namespace mbedcrypto;

rsa pri_key;
// import from data buffer
pri_key.import_key(private_key_data, optional_password);
// or load from a file by file-name
pri_key.load_key("private_key.pem");

rsa pub_key;
pub_key.import_public_key(public_key_data);

// [optional] check matching public/private pair
REQUIRE( check_pair(pub_key, pri_key) == true );

// export keys
if ( supports(features::pk_export) ) {
    auto der_data = pub_key.export_public_key(pk::der_format);
    // write or share
}

// key generation
if ( supports(features::rsa_keygen) ) {
    rsa pri_key;
    pri_key.generate_key(2048); // a 2048bit key
    // do stuff
}

auto af = pub_key.what_can_do(); // what can i do with this key?
// returns pk::action_flags (key capabilities) with following data:
// af.encrypt = true
// af.decrypt = false
// af.sign    = false
// af.verify  = true
// because pub_key is a valid rsa public-key

auto kinfo = pri_key.key_info();
// kinfo.N  :  public modulus
// kinfo.E  :  public exponent
// only valid if the key is a private key
// kinfo.D  :  private exponent
// kinfo.P  :  1st prime factor
// kinfo.Q  :  2nd prime factor
// kinfo.DP  : D % (P - 1)
// kinfo.DQ  : D % (Q - 1)
// kinfo.QP  : 1 / (Q % P)
```

to sign and verify by `rsa`:
```cpp
// signature & verification
std::string message = read_message_from_somewhere();
auto signature      = pri_key.sign(message, hash_t::sha256);
REQUIRE( pub_key.verify(signature, message, hash_t::sha256);
```

to encrypt and decrypt by `rsa`:
```cpp
const auto hvalue = hash::make(hash_t::sha256, message);

auto encv = pub_key.encrypt(hvalue);
auto decv = pri_key.decrypt(encv);
REQUIRE( decv == hvalue );

// or
auto encv = pub_key.encrypt(message, hash_t::sha256);
auto decv = pri_key.decrypt(encv);
REQUIRE( decv == hash::make(hash_t::sha256, message) );

```

see [rsa.hpp](./include/mbedcrypto/rsa.hpp)


to create `ec` keys from curves:
```cpp
using namespace mbedcrypto;

if ( supports(features::pk_export)  &&  supports(pk_t::eckey) ) {
    ecp gen; // elliptic curve public key infrastructure
    gen.generate_key(curve_t::secp224k1); // or any other supported curves
    auto pri_data = gen.export_key(pk::pem_format);
    auto pub_data = gen.export_public_key(pk::pem_format);
    // do stuff

    auto kinfo = gen.key_info(); // ecurve points and secret
    std::cout
        << "\nQx (" << kinfo.Qx.bitlen() << "): " << kinfo.Qx.to_string()
        << "\nQy (" << kinfo.Qy.bitlen() << "): " << kinfo.Qy.to_string()
        << "\nQz (" << kinfo.Qz.bitlen() << "): " << kinfo.Qz.to_string()
        << "\nd  (" << kinfo.D.bitlen()  << "): " << kinfo.d.to_string()
        << std::endl;
}
```

to sign and verify by `ecdsa`:
```cpp
using namespace mbedcrypto;

if ( supports(pk_t::ecdsa)  &&  supports(features::ec_keygen) ) {
    ecdsa pri_key; // both pk_t::eckey and pk_t::ecdsa works
    pri_key.generate_key(curve_t::secp192k1);
    auto sig = pri_key.sign(message, hash_t::sha384);

    ecdsa pub_key;
    pub_key.import_public_key(
            pri_key.export_public_key(pk::pem_format)
            );

    REQUIRE( pub_key.verify(sig, message, hash_t::sha384) );
}
```

to create a shared secret by `ECDH(E)` when both ends know the curve type:
```cpp
using namespace mbedcrypto;
// const auto ctype = curve_t::secp224r1 // both know the curve type

ecdh server;
auto srv_pub = server.make_peer_key(ctype);
// send srv_pub to client

ecdh client;
client.generate_key(ctype); // alternative approach to make_peer_key()
auto cli_pub = client.peer_key();
// send cli_pub to server

auto sss = server.shared_secret(cli_pub); // on server
auto css = client.shared_secret(srv_pub); // on client

REQUIRE( (sss == css) );
```

or if the curve parameters are defined by server at runtime as defined in
[RFC 4492: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer
Security (TLS)](https://tools.ietf.org/html/rfc4492) do:
```cpp
using namespace mbedcrypto;

ecdh server;
// (only) server defines the curve type
auto skex = server.make_server_key_exchange(curve_t::secp192k1);
// send server's key exchange params to client

ecdh client;
auto cli_pub = client.make_client_peer_key(skex);
auto css     = client.shared_secret();
// send cli_pub to server

auto sss     = server.shared_secret(cli_pub); // on server

REQUIRE( (sss == css) );
```

see [ecp.hpp](./include/mbedcrypto/ecp.hpp)

---

## tests
samples and unit tests are available under [tests/tdd](./tests/tdd/) folder.

the test application has been built by
[catch](https://github.com/philsquared/Catch):
```bash
# to list all available test tags:
$xbin/> ./tests -t

# run the tests
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


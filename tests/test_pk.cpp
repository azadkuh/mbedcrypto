#include <catch2/catch.hpp>

#include "./helper.hpp"
#include "mbedcrypto/text_codec.hpp"
#include "mbedcrypto/hash.hpp"
#include "mbedcrypto/pk.hpp"

//-----------------------------------------------------------------------------
namespace {
using namespace mbedcrypto;
}
//-----------------------------------------------------------------------------

TEST_CASE("public-key capabilities", "[pk]") {
    pk::capability c;
    REQUIRE((c.encrypt == false &&
             c.decrypt == false &&
             c.sign    == false &&
             c.verify  == false));
}

TEST_CASE("api tests", "[pk]") {
    auto  ptr = pk::make_context();
    auto& ctx = *ptr;
    SECTION("empty checks") {
        REQUIRE_FALSE(pk::is_valid(ctx));
        REQUIRE(pk::type_of(ctx)                  == pk_t::unknown);
        REQUIRE(pk::key_bitlen(ctx)               == 0);
        REQUIRE(pk::key_size(ctx)                 == 0);
        REQUIRE(pk::max_crypt_size(ctx)           == 0);
        REQUIRE(pk::has_private_key(ctx)          == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(ctx, pk_t::rsassa_pss) == false);
        REQUIRE(pk::can_do(ctx, pk_t::ec)         == false);
        REQUIRE(pk::can_do(ctx, pk_t::ecdh)       == false);
        REQUIRE(pk::can_do(ctx, pk_t::ecdsa)      == false);
        REQUIRE(pk::what_can_do(ctx)              == pk::capability{});
        auto other = pk::make_context();
        REQUIRE(pk::is_pri_pub_pair(ctx, *other)  == false); // both are invalid
    }

    SECTION("setup rsa") {
        auto ec = pk::setup(ctx, pk_t::rsa); // rsa is always enabled
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(ctx) == pk_t::rsa);

        ec = pk::setup(ctx, pk_t::unknown);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::rsa_alt);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);

        ec = pk::setup(ctx, pk_t::rsassa_pss);
        REQUIRE(ec == make_error_code(error_t::not_supported));
        REQUIRE(pk::type_of(ctx) == pk_t::unknown);
    }

    SECTION("setup ec") {
        if (supports(features::pk_ec)) {
            auto ec = pk::setup(ctx, pk_t::ec);
            REQUIRE_FALSE(ec);
            REQUIRE_FALSE(pk::has_private_key(ctx));
            REQUIRE(pk::type_of(ctx) == pk_t::ec);
            REQUIRE(pk::can_do(ctx, pk_t::ec)    == true);
            REQUIRE(pk::can_do(ctx, pk_t::ecdh)  == true);
            REQUIRE(pk::can_do(ctx, pk_t::ecdsa) == true);

            ec = pk::setup(ctx, pk_t::ecdh);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx) == pk_t::ecdh);
            REQUIRE(pk::can_do(ctx, pk_t::ec)    == true);
            REQUIRE(pk::can_do(ctx, pk_t::ecdh)  == true);
            REQUIRE(pk::can_do(ctx, pk_t::ecdsa) == false);

            ec = pk::setup(ctx, pk_t::ecdsa);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::type_of(ctx) == pk_t::ecdsa);
            REQUIRE(pk::can_do(ctx, pk_t::ec)    == false);
            REQUIRE(pk::can_do(ctx, pk_t::ecdh)  == false);
            REQUIRE(pk::can_do(ctx, pk_t::ecdsa) == true);
        } else {
            auto ec = pk::setup(ctx, pk_t::ec);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);

            ec = pk::setup(ctx, pk_t::ecdh);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);

            ec = pk::setup(ctx, pk_t::ecdsa);
            REQUIRE(ec == make_error_code(error_t::not_supported));
            REQUIRE(pk::type_of(ctx) == pk_t::unknown);
        }
    }
}

TEST_CASE("rsa-key generation api", "[pk]") {
    constexpr size_t keybits = 1024;
    constexpr size_t keysize = 128;
    auto pri = pk::make_context();
    auto ec  = make_rsa_key(*pri, keybits);
    if (!pk::supports_rsa_keygen()) {
        REQUIRE(ec == make_error_code(error_t::not_supported));
        return;
    }
    // is rsa key generator is enabled
    REQUIRE_FALSE(ec);
    REQUIRE(pk::type_of(*pri)                  == pk_t::rsa);
    REQUIRE(pk::key_bitlen(*pri)               == keybits);
    REQUIRE(pk::key_size(*pri)                 == keysize);
    REQUIRE(pk::max_crypt_size(*pri)           == (keysize - 11));
    REQUIRE(pk::has_private_key(*pri)          == true);
    REQUIRE(pk::can_do(*pri, pk_t::rsa)        == true);
    REQUIRE(pk::can_do(*pri, pk_t::rsa_alt)    == false);
    REQUIRE(pk::can_do(*pri, pk_t::rsassa_pss) == true);
    REQUIRE(pk::can_do(*pri, pk_t::ec)         == false);
    REQUIRE(pk::can_do(*pri, pk_t::ecdh)       == false);
    REQUIRE(pk::can_do(*pri, pk_t::ecdsa)      == false);
    {
        auto cap = pk::what_can_do(*pri);
        REQUIRE(cap.encrypt == true); // by its public part
        REQUIRE(cap.decrypt == true);
        REQUIRE(cap.sign    == true);
        REQUIRE(cap.verify  == true); // by its public part
    }

    // export and check the public part in both pem & der formats
    auto pub = pk::make_context();
    {
        std::string pem;
        ec = pk::export_pub_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
        REQUIRE_FALSE(ec);
        REQUIRE_FALSE(pem.empty());
        ec = pk::import_pub_key(*pub, pem);
        REQUIRE_FALSE(ec);

        std::string der;
        ec = pk::export_pub_key(obuffer_t{der}, *pri, pk::key_io_t::der);
        REQUIRE_FALSE(ec);
        REQUIRE_FALSE(der.empty());
        ec = pk::import_pub_key(*pub, der);
        REQUIRE_FALSE(ec);

        REQUIRE(pk::is_valid(*pub));
        REQUIRE(is_pri_pub_pair(*pri, *pub));
        REQUIRE(pk::type_of(*pub)                  == pk_t::rsa);
        REQUIRE(pk::key_bitlen(*pub)               == keybits);
        REQUIRE(pk::key_size(*pub)                 == keysize);
        REQUIRE(pk::max_crypt_size(*pub)           == (keysize - 11));
        REQUIRE(pk::has_private_key(*pub)          == false);
        REQUIRE(pk::can_do(*pub, pk_t::rsa)        == true);
        REQUIRE(pk::can_do(*pub, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(*pub, pk_t::rsassa_pss) == true);
        REQUIRE(pk::can_do(*pub, pk_t::ec)         == false);
        REQUIRE(pk::can_do(*pub, pk_t::ecdh)       == false);
        REQUIRE(pk::can_do(*pub, pk_t::ecdsa)      == false);

        auto cap = pk::what_can_do(*pub);
        REQUIRE(cap.encrypt == true);
        REQUIRE(cap.decrypt == false);
        REQUIRE(cap.sign    == false);
        REQUIRE(cap.verify  == true);
    }

    // export and check private key
    auto other = pk::make_context();
    {
        std::string pem;
        ec = pk::export_pri_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
        REQUIRE_FALSE(ec);
        REQUIRE_FALSE(pem.empty());
        ec = pk::import_pri_key(*other, pem);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::is_pri_pub_pair(*other, *pub));

        std::string der;
        ec = pk::export_pri_key(obuffer_t{der}, *pri, pk::key_io_t::der);
        REQUIRE_FALSE(ec);
        REQUIRE_FALSE(der.empty());
        ec = pk::import_pri_key(*other, der);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::is_pri_pub_pair(*other, *pub));
    }
}

TEST_CASE("rsa key import", "[pk]") {
    auto pri = pk::make_context();
    auto ec  = pk::import_pri_key(
        *pri, test::rsa_private_key_password(), "mbedcrypto1234");
    REQUIRE_FALSE(ec);

    ec  = pk::import_pri_key(*pri, test::rsa_private_key());
    REQUIRE_FALSE(ec);
    // import and encrypted key
    auto cap = pk::what_can_do(*pri);
    REQUIRE(pk::type_of(*pri)    == pk_t::rsa);
    REQUIRE(pk::key_bitlen(*pri) == 2048);
    REQUIRE(cap.encrypt          == true);
    REQUIRE(cap.decrypt          == true);
    REQUIRE(cap.sign             == true);
    REQUIRE(cap.verify           == true);

    auto pub = pk::make_context();
    ec       = pk::import_pub_key(*pub, test::rsa_public_key());
    REQUIRE_FALSE(ec);
    REQUIRE(pk::is_pri_pub_pair(*pri, *pub));
    cap = pk::what_can_do(*pub);
    REQUIRE(pk::type_of(*pub)    == pk_t::rsa);
    REQUIRE(pk::key_bitlen(*pub) == 2048);
    REQUIRE(cap.encrypt          == true);
    REQUIRE(cap.decrypt          == false);
    REQUIRE(cap.sign             == false);
    REQUIRE(cap.verify           == true);
}

TEST_CASE("sign/verify by rsa key", "[pk]") {
    auto pri = pk::make_context();
    auto pub = pk::make_context();
    auto ec  = pk::import_pri_key(*pri, test::rsa_private_key());
    REQUIRE_FALSE(ec);
    ec = pk::import_pub_key(*pub, test::rsa_public_key());
    REQUIRE_FALSE(ec);

    // make hash
    constexpr auto hash_type = hash_t::sha1;
    std::vector<uint8_t> hashed_message;
    ec = make_hash(obuffer_t{hashed_message}, test::long_text(), hash_type);
    REQUIRE_FALSE(ec);

    // make signature by private key
    std::vector<uint8_t> signature;
    ec = pk::sign(obuffer_t{signature}, *pri, hashed_message, hash_type);
    REQUIRE_FALSE(ec);
    REQUIRE(test::long_text_signature() == signature);

    // verify signature by public key
    ec = pk::verify(*pub, hashed_message, hash_type, signature);
    REQUIRE_FALSE(ec);
    // a private key contains the public key internally, so it also can verify
    ec = pk::verify(*pri, hashed_message, hash_type, signature);
    REQUIRE_FALSE(ec);

    // test bad things
    {
        auto empty = pk::make_context();
        std::string sig1;
        ec = pk::sign(obuffer_t{sig1}, *empty, hashed_message, hash_type);
        REQUIRE(ec == make_error_code(error_t::bad_input)); // context is empty (uninitialized)
        ec = pk::verify(*empty, hashed_message, hash_type, signature);
        REQUIRE(ec == make_error_code(error_t::bad_input)); // context is empty (uninitialized)

        ec = pk::sign(obuffer_t{sig1}, *pub, hashed_message, hash_type);
        REQUIRE(ec); // can not sign with public key

        ec = pk::sign(obuffer_t{sig1}, *pri, test::long_text(), hash_type);
        REQUIRE(ec == make_error_code(error_t::bad_input)); // invalid message size

        sig1.resize(10); // small output
        bin_edit_t box{sig1};
        ec = pk::sign(box, *pri, hashed_message, hash_type);
        REQUIRE(ec == make_error_code(error_t::small_output));

        ec = pk::verify(*pub, test::long_text(), hash_type, signature);
        REQUIRE(ec == make_error_code(error_t::bad_input));
    }
}

TEST_CASE("encrypt/decrypt by rsa key", "[pk]") {
    auto pri = pk::make_context();
    auto pub = pk::make_context();
    auto ec  = pk::import_pri_key(*pri, test::rsa_private_key());
    REQUIRE_FALSE(ec);
    ec = pk::import_pub_key(*pub, test::rsa_public_key());
    REQUIRE_FALSE(ec);

    const std::string source{"Now frontiers shift like desert sands\nWhile nations wash their bloodied hands"};
    REQUIRE(source.size() < pk::max_crypt_size(*pub));

    std::vector<uint8_t> enc;
    ec = pk::encrypt(obuffer_t{enc}, *pub, source);
    REQUIRE_FALSE(ec);

    std::vector<uint8_t> dec;
    ec = pk::decrypt(obuffer_t{dec}, *pri, enc);
    REQUIRE_FALSE(ec);
    REQUIRE(bin_view_t{source} == bin_view_t{dec});

    enc.clear();
    ec = pk::encrypt(obuffer_t{enc}, *pri, source); // pri-key includes a pub key
    REQUIRE_FALSE(ec);

    // test bad things
    {
        auto empty = pk::make_context();
        std::string enc1, dec1;
        ec = pk::encrypt(obuffer_t{enc1}, *empty, source);
        REQUIRE(ec == make_error_code(error_t::bad_input));
        ec = pk::decrypt(obuffer_t{dec1}, *empty, enc);
        REQUIRE(ec == make_error_code(error_t::bad_input));

        enc1.resize(4); // small size
        bin_edit_t box{enc1};
        ec = pk::encrypt(box, *pub, source);
        REQUIRE(ec == make_error_code(error_t::small_output));

        ec = pk::encrypt(obuffer_t{enc1}, *pub, test::long_text());
        REQUIRE(ec == make_error_code(error_t::bad_input)); // input is larger than max_crypt_size()

        ec = pk::decrypt(obuffer_t{dec1}, *pub, enc);
        REQUIRE(ec == make_error_code(error_t::bad_input)); // can't decrypt by public key
    }
}

TEST_CASE("ec key generation", "[pk]") {
    if (!pk::supports_ec_keygen())
        return;
    auto pri = pk::make_context();
    // bad inputs
    {
        // rsa_alt is not an elliptic curve algorithm
        auto ec  = pk::make_ec_key(*pri, pk_t::rsa_alt, curve_t::secp192r1);
        REQUIRE(ec == make_error_code(error_t::usage));
        // curve_t::curve25519 is limited to ecdh algorithm
        ec = pk::make_ec_key(*pri, pk_t::ec, curve_t::curve25519);
        REQUIRE(ec == make_error_code(error_t::usage));
        ec = pk::make_ec_key(*pri, pk_t::ecdsa, curve_t::curve25519);
        REQUIRE(ec == make_error_code(error_t::usage));
    }

    constexpr auto hash_type = hash_t::sha256;
    std::vector<uint8_t> hashed_msg;
    make_hash(obuffer_t{hashed_msg}, test::long_text(), hash_type);

    struct test_case_t {
        curve_t curve;
        pk_t    type;
        size_t  kb; ///< key bits
    };
    const test_case_t All[] = {
        {curve_t::secp192r1, pk_t::ec, 192},
        {curve_t::secp224r1, pk_t::ec, 224},
        {curve_t::secp256r1, pk_t::ec, 256},
        {curve_t::secp384r1, pk_t::ec, 384},
        {curve_t::secp521r1, pk_t::ec, 521},
        {curve_t::secp192k1, pk_t::ec, 192},
        {curve_t::secp224k1, pk_t::ec, 224},
        {curve_t::secp256k1, pk_t::ec, 256},
        {curve_t::bp256r1,   pk_t::ec, 256},
        {curve_t::bp384r1,   pk_t::ec, 384},
        {curve_t::bp512r1,   pk_t::ec, 512},
    };

    for (const auto& t : All) {
        auto ec = pk::make_ec_key(*pri, t.type, t.curve);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(*pri)                  == t.type);
        REQUIRE(pk::key_bitlen(*pri)               == t.kb);
        REQUIRE(pk::max_crypt_size(*pri)           == 141);
        REQUIRE(pk::has_private_key(*pri)          == true);
        REQUIRE(pk::can_do(*pri, pk_t::ec)         == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdh)       == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdsa)      == true);
        REQUIRE(pk::can_do(*pri, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsassa_pss) == false);

        auto pub = pk::make_context();
        // test pem/der public-key export and import
        {
            std::string pem;
            ec = pk::export_pub_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
            REQUIRE_FALSE(ec);
            ec = pk::import_pub_key(*pub, pem);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::is_pri_pub_pair(*pri, *pub));

            std::string der;
            ec = pk::export_pub_key(obuffer_t{der}, *pri, pk::key_io_t::der);
            REQUIRE_FALSE(ec);
            ec = pk::import_pub_key(*pub, der);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::is_pri_pub_pair(*pri, *pub));
        }

        auto other = pk::make_context();
        // test pem/der private-key export and import
        {
            std::string pem;
            ec = pk::export_pri_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
            REQUIRE_FALSE(ec);
            ec = pk::import_pri_key(*other, pem);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::is_pri_pub_pair(*other, *pub));

            std::string der;
            ec = pk::export_pri_key(obuffer_t{der}, *pri, pk::key_io_t::der);
            REQUIRE_FALSE(ec);
            ec = pk::import_pri_key(*other, der);
            REQUIRE_FALSE(ec);
            REQUIRE(pk::is_pri_pub_pair(*other, *pub));
        }
        auto c = pk::what_can_do(*pri);
        REQUIRE((c.sign && c.verify)); // both sign and verifes
        REQUIRE_FALSE((c.encrypt || c.decrypt)); // can not do direct encryption/decryption
        // test sign/verify
        {
            std::vector<uint8_t> signature;
            ec = pk::sign(obuffer_t{signature}, *pri, hashed_msg, hash_type);
            REQUIRE_FALSE(ec);

            ec = pk::verify(*pub, hashed_msg, hash_type, signature);
            REQUIRE_FALSE(ec);
        }
    }

    // curve25519 is a special case which supports ecdh
    {
        const auto curve = curve_t::curve25519;
        auto ec = pk::make_ec_key(*pri, pk_t::ecdh, curve);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(*pri)                  == pk_t::ecdh);
        REQUIRE(pk::key_bitlen(*pri)               == 255);
        REQUIRE(pk::max_crypt_size(*pri)           == 0); // can not encrypt
        REQUIRE(pk::has_private_key(*pri)          == true);
        REQUIRE(pk::can_do(*pri, pk_t::ec)         == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdh)       == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdsa)      == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsassa_pss) == false);

        auto pub = pk::make_context();
        // test pem/der public-key export and import
        {
            std::string pem;
            ec = pk::export_pub_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
            REQUIRE(ec); // pem export is not supported for curve25519

            std::string der;
            ec = pk::export_pub_key(obuffer_t{der}, *pri, pk::key_io_t::der);
            REQUIRE(ec); // der export is not supported either
        }

        // only key exchange is supported
        auto c = pk::what_can_do(*pri);
        REQUIRE_FALSE((c.sign || c.verify));
        REQUIRE_FALSE((c.encrypt || c.decrypt));
    }

    // curve448 is a special case which supports ecdh
    {
        const auto curve = curve_t::curve448;
        auto ec = pk::make_ec_key(*pri, pk_t::ecdh, curve);
        REQUIRE_FALSE(ec);
        REQUIRE(pk::type_of(*pri)                  == pk_t::ecdh);
        REQUIRE(pk::key_bitlen(*pri)               == 448);
        REQUIRE(pk::max_crypt_size(*pri)           == 0); // can not encrypt
        REQUIRE(pk::has_private_key(*pri)          == true);
        REQUIRE(pk::can_do(*pri, pk_t::ec)         == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdh)       == true);
        REQUIRE(pk::can_do(*pri, pk_t::ecdsa)      == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsa)        == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsa_alt)    == false);
        REQUIRE(pk::can_do(*pri, pk_t::rsassa_pss) == false);

        auto pub = pk::make_context();
        // test pem/der public-key export and import
        {
            std::string pem;
            ec = pk::export_pub_key(obuffer_t{pem}, *pri, pk::key_io_t::pem);
            REQUIRE(ec); // pem export is not supported for curve448

            std::string der;
            ec = pk::export_pub_key(obuffer_t{der}, *pri, pk::key_io_t::der);
            REQUIRE(ec); // der export is not supported either
        }

        // only key exchange is supported
        auto c = pk::what_can_do(*pri);
        REQUIRE_FALSE((c.sign || c.verify));
        REQUIRE_FALSE((c.encrypt || c.decrypt));
    }
}

TEST_CASE("ecdh key exchange", "[pk]") {
    if (!supports(features::pk_ec))
        return;

    // using ecdh
    {
        const auto curve = curve_t::curve25519;
        const pk::ec_point_t fmt{};

        // server side
        auto srv = pk::make_context();
        std::vector<uint8_t> srv_pub;
        {
            auto ec  = pk::make_ec_key(*srv, pk_t::ecdh, curve);
            REQUIRE_FALSE(ec);
            ec = export_pub_key(obuffer_t{srv_pub}, *srv, fmt);
            REQUIRE_FALSE(ec);
        }

        // client side
        auto cli = pk::make_context();
        std::vector<uint8_t> cli_pub;
        {
            auto ec = pk::make_ec_key(*cli, pk_t::ecdh, curve);
            REQUIRE_FALSE(ec);
            ec = export_pub_key(obuffer_t{cli_pub}, *cli, fmt);
            REQUIRE_FALSE(ec);
        }

        // transfering public keys

        // server side
        std::vector<uint8_t> srv_ssk;
        {
            auto ec = pk::make_shared_secret(obuffer_t{srv_ssk}, *srv, cli_pub, fmt);
            test::dump(ec);
            REQUIRE_FALSE(ec);
        }

        // client size
        std::vector<uint8_t> cli_ssk;
        {
            auto ec = pk::make_shared_secret(obuffer_t{cli_ssk}, *cli, srv_pub, fmt);
            REQUIRE_FALSE(ec);
        }

        // both endup in same shared secret key
        REQUIRE(cli_ssk == srv_ssk);
    }

    // bad input
    {
        const auto curve = curve_t::bp256r1;
        auto pri = pk::make_context();
        pk::ec_point_t fmt{};

        // make an ecdsa to wrong-input the ecdh tools
        auto ec = pk::make_ec_key(*pri, pk_t::ecdsa, curve);
        REQUIRE_FALSE(ec);
        REQUIRE_FALSE(pk::can_do(*pri, pk_t::ecdh)); // ecdsa can not do ecdh

        std::vector<uint8_t> pub;
        ec = pk::export_pub_key(obuffer_t{pub}, *pri, fmt);
        REQUIRE(ec == make_error_code(error_t::not_supported)); // ecdsa can not do ecdh

        std::vector<uint8_t> secret;
        ec = pk::make_shared_secret(obuffer_t{secret}, *pri, pub, fmt);
        REQUIRE(ec == make_error_code(error_t::not_supported)); // ecdsa can not do ecdh
    }
}

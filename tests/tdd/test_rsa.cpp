#include <catch.hpp>

#include "mbedcrypto/hash.hpp"
#include "pk_common.hpp"

#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#include <iostream>
///////////////////////////////////////////////////////////////////////////////
namespace {
using namespace mbedcrypto;
///////////////////////////////////////////////////////////////////////////////

void
mpi_checker(const char*, const mpi& mpi) {
    REQUIRE(mpi == true);
    REQUIRE(mpi.size() > 0);
    REQUIRE(mpi.bitlen() <= (mpi.size() << 3));

    auto bin = mpi.dump();
    REQUIRE(bin.size() == mpi.size());

    auto str = mpi.to_string(16);
    REQUIRE(str.size() == (mpi.size() << 1));

    REQUIRE(from_hex(str) == bin);

    // dumper(name, mpi);
}

///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("rsa type checks", "[types][pk]") {
    using namespace mbedcrypto;

    SECTION("creation") {
        rsa my_empty;
        REQUIRE(test::icompare(my_empty.name(), "RSA"));
        REQUIRE(my_empty.can_do(pk_t::rsa));
        REQUIRE(!my_empty.can_do(pk_t::rsa_alt));
        REQUIRE(!my_empty.can_do(pk_t::ecdsa));
        REQUIRE(!my_empty.has_private_key());
        auto af = my_empty.what_can_do();
        // empty instance, all members must be false
        REQUIRE_FALSE((af.encrypt || af.decrypt || af.sign || af.verify));

        REQUIRE_THROWS(my_empty.reset_as(pk_t::none));
        REQUIRE_THROWS(my_empty.reset_as(pk_t::eckey));
        REQUIRE_THROWS(my_empty.reset_as(pk_t::eckey_dh));
        REQUIRE_THROWS(my_empty.reset_as(pk_t::ecdsa));
        REQUIRE_NOTHROW(my_empty.reset_as(pk_t::rsa));
        if (supports(pk_t::rsa_alt)) {
            REQUIRE_NOTHROW(my_empty.reset_as(pk_t::rsa_alt));
        }
        if (supports(pk_t::rsassa_pss)) {
            REQUIRE_NOTHROW(my_empty.reset_as(pk_t::rsassa_pss));
        }

        rsa my_pri;
        REQUIRE_NOTHROW(my_pri.import_key(test::rsa_private_key()));
        REQUIRE(test::icompare(my_pri.name(), "RSA"));
        REQUIRE(my_pri.has_private_key());
        REQUIRE(my_pri.can_do(pk_t::rsa));
        REQUIRE(!my_pri.can_do(pk_t::rsa_alt));
        REQUIRE(my_pri.key_bitlen() == 2048);
        af = my_pri.what_can_do();
        // private key, can do all of the tasks
        REQUIRE((af.encrypt && af.decrypt && af.sign && af.verify));

        rsa my_key;
        REQUIRE_NOTHROW(my_key.import_public_key(test::rsa_public_key()));
        REQUIRE(test::icompare(my_key.name(), "RSA"));
        REQUIRE(!my_key.has_private_key());
        REQUIRE(my_key.can_do(pk_t::rsa));
        REQUIRE(!my_key.can_do(pk_t::rsa_alt));
        REQUIRE(my_key.key_bitlen() == 2048);
        af = my_key.what_can_do();
        // public key can both encrypt or verify
        REQUIRE((af.encrypt && af.verify));
        // public key can not decrypt nor sign
        REQUIRE_FALSE((af.decrypt | af.sign));

        // check key pair
        REQUIRE(!check_pair(my_empty, my_key)); // my_empty is uninitialized
        REQUIRE(!check_pair(my_key, my_empty)); // my_empty is uninitialized
        REQUIRE(check_pair(my_key, my_pri) == true);

        // reuse of my_key
        REQUIRE_NOTHROW(my_key.import_key(
            test::rsa_private_key_password(),
            "mbedcrypto1234" // password
            ));
        REQUIRE(test::icompare(my_key.name(), "RSA"));
        REQUIRE(my_key.has_private_key());
        REQUIRE(my_key.can_do(pk_t::rsa));
        REQUIRE(my_key.key_bitlen() == 2048);

        // my_key is still the same key (with or without password)
        REQUIRE(check_pair(my_pri, my_key) == true);
    }
}

TEST_CASE("rsa cryptography", "[pk]") {
    using namespace mbedcrypto;

    SECTION("cryptography max size") {
        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        REQUIRE(my_pri.max_crypt_size() == (my_pri.key_length() - 11));

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());
        REQUIRE(my_pub.max_crypt_size() == (my_pub.key_length() - 11));
    }

    SECTION("sign and verify") {
        // message is 455 bytes long > 2048 bits
        std::string message{test::long_text()};
        constexpr auto hash_type = hash_t::sha1;

        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        // invalid hash value size
        REQUIRE_THROWS(my_pri.sign(message, hash_type));

        // sign by message
        auto sig_m = my_pri.sign_message(message, hash_type);
        REQUIRE((sig_m == test::long_text_signature()));

        // sign by hash
        auto hvalue = to_sha1(message);
        auto sig_h = my_pri.sign(hvalue, hash_type);
        REQUIRE((sig_h == sig_m));

        // verify by private key, a private key contains the public
        REQUIRE(my_pri.verify_message(sig_m, message, hash_type));
        REQUIRE(my_pri.verify(sig_m, hvalue, hash_type));

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());
        REQUIRE(my_pub.verify_message(sig_m, message, hash_type));
        REQUIRE(my_pub.verify(sig_m, hvalue, hash_type));
    }

    SECTION("encrypt and decrypt") {
        const std::string message(test::long_text());
        const auto        hvalue = hash::make(hash_t::sha256, message);

        rsa my_pub;
        my_pub.import_public_key(test::rsa_public_key());

        // message size is invalid
        REQUIRE_THROWS(my_pub.encrypt(message));
        auto encv = my_pub.encrypt(hvalue);

        rsa my_pri;
        my_pri.import_key(test::rsa_private_key());
        REQUIRE_THROWS(my_pri.decrypt(message));
        auto decv = my_pri.decrypt(encv);
        REQUIRE(decv == hvalue);
    }
}

TEST_CASE("rsa key tests", "[pk]") {
    using namespace mbedcrypto;

    if (supports(features::rsa_keygen)) {
        rsa my_pri;
        // my_pri is not defined as rsa
        REQUIRE_NOTHROW(my_pri.generate_key(1024));
        REQUIRE(my_pri.has_private_key());
        REQUIRE(my_pri.type() == pk_t::rsa);

        // reuse
        REQUIRE_NOTHROW(my_pri.generate_key(1024));
        REQUIRE(my_pri.has_private_key());
        REQUIRE_NOTHROW(my_pri.generate_key(2048, 3));
        REQUIRE(my_pri.has_private_key());
    }

    if (supports(features::pk_export)) {
        std::string message{test::long_text()};

        rsa my_gen;
        my_gen.import_key(test::rsa_private_key());
        const auto signature = my_gen.sign_message(message, hash_t::sha256);

        // test pem public
        rsa my_pub;
        my_pub.import_public_key(my_gen.export_public_key(pk::pem_format));
        REQUIRE(my_pub.verify_message(signature, message, hash_t::sha256));
        REQUIRE(check_pair(my_pub, my_gen) == true);

        // test pem private
        rsa my_pri;
        my_pri.import_key(my_gen.export_key(pk::pem_format));
        REQUIRE((signature == my_pri.sign_message(message, hash_t::sha256)));
        REQUIRE(check_pair(my_pub, my_pri) == true);

        // test der public
        my_pub.import_public_key(my_gen.export_public_key(pk::der_format));
        REQUIRE(my_pub.verify_message(signature, message, hash_t::sha256));
        REQUIRE(check_pair(my_pub, my_gen) == true);

        // test der private
        my_pri.import_key(my_gen.export_key(pk::der_format));
        REQUIRE((signature == my_pri.sign_message(message, hash_t::sha256)));
        REQUIRE(check_pair(my_pub, my_pri) == true);
    }
}

TEST_CASE("rsa key params", "[pk]") {
    using namespace mbedcrypto;

    auto dumper = [](const char* name, const mpi& mpi) {
        std::cout << name << ": (size = " << mpi.size() << " , " << mpi.bitlen()
                  << ")\n"
                  << mpi.to_string(16) << "\n"
                  << to_hex(mpi.dump()) << std::endl;
    };

    SECTION("private checks") {
        rsa pri_key;
        pri_key.import_key(test::rsa_private_key());

        auto ki = pri_key.key_info();
        mpi_checker("N",  ki.N);
        mpi_checker("E",  ki.E);
        mpi_checker("D",  ki.D);
        mpi_checker("P",  ki.P);
        mpi_checker("Q",  ki.Q);
        mpi_checker("DP", ki.DP);
        mpi_checker("DQ", ki.DQ);
        mpi_checker("QP", ki.QP);
    }

    SECTION("public checks") {
        rsa pub_key;
        pub_key.import_public_key(test::rsa_public_key());

        auto ki = pub_key.key_info();
        mpi_checker("N", ki.N);
        mpi_checker("E", ki.E);

        // private parts must be empty
        REQUIRE(ki.D  == false);
        REQUIRE(ki.P  == false);
        REQUIRE(ki.Q  == false);
        REQUIRE(ki.DP == false);
        REQUIRE(ki.DQ == false);
        REQUIRE(ki.QP == false);
    }
}

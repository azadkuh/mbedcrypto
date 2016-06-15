#include <catch.hpp>

#include "mbedcrypto/hash.hpp"
#include "mbedcrypto/mbedtls_wrapper.hxx"
#include "pk_common.hpp"

#include "../../src/pk_private.hpp"

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"

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
TEST_CASE("ec type checks", "[types][pk]") {
    using namespace mbedcrypto;

    if (supports(pk_t::eckey) || supports(pk_t::eckey_dh)) {
        ecp my_key;                         // default as eckey
        REQUIRE(!my_key.has_private_key()); // no key is provided
        REQUIRE(test::icompare(my_key.name(), "EC"));
        REQUIRE(my_key.can_do(pk_t::eckey));
        REQUIRE(my_key.can_do(pk_t::eckey_dh));
        if (supports(pk_t::ecdsa)) {
            REQUIRE(my_key.can_do(pk_t::ecdsa));
        } else {
            REQUIRE(!my_key.can_do(pk_t::ecdsa));
        }

        auto af = my_key.what_can_do();
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE((af.encrypt || af.decrypt || af.sign || af.verify));

        REQUIRE_THROWS(my_key.reset_as(pk_t::none));
        REQUIRE_THROWS(my_key.reset_as(pk_t::rsa));
        REQUIRE_THROWS(my_key.reset_as(pk_t::rsa_alt));
        REQUIRE_THROWS(my_key.reset_as(pk_t::rsassa_pss));
        REQUIRE_NOTHROW(my_key.reset_as(pk_t::eckey));
        REQUIRE_NOTHROW(my_key.reset_as(pk_t::eckey_dh));
        if (supports(pk_t::ecdsa)) {
            REQUIRE_NOTHROW(my_key.reset_as(pk_t::ecdsa));
        } else {
            REQUIRE_THROWS(my_key.reset_as(pk_t::ecdsa));
        }

        my_key.reset_as(pk_t::eckey_dh);
        REQUIRE(test::icompare(my_key.name(), "EC_DH"));
        REQUIRE(!my_key.has_private_key());
        REQUIRE(my_key.can_do(pk_t::eckey_dh));
        REQUIRE(my_key.can_do(pk_t::eckey));
        REQUIRE(!my_key.can_do(pk_t::ecdsa)); // in any circumstances
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE((af.encrypt || af.decrypt || af.sign || af.verify));

        // rsa key is not loadable into ecp
        REQUIRE_THROWS(my_key.import_key(test::rsa_private_key()));
    }

    if (supports(pk_t::ecdsa)) {
        ecp my_key(pk_t::ecdsa);
        REQUIRE(test::icompare(my_key.name(), "ECDSA"));
        REQUIRE(!my_key.has_private_key());
        REQUIRE(my_key.can_do(pk_t::ecdsa));
        REQUIRE(!my_key.can_do(pk_t::eckey));
        REQUIRE(!my_key.can_do(pk_t::eckey_dh));
        auto af = my_key.what_can_do();
        // my_key has no key. all capabilities must be false
        REQUIRE_FALSE((af.encrypt || af.decrypt || af.sign || af.verify));
    }
}

TEST_CASE("ec key tests", "[pk]") {
    using namespace mbedcrypto;

    if (supports(features::pk_export) && supports(pk_t::eckey)) {
        ecp gen;
        REQUIRE_THROWS(gen.generate_key(curve_t::none));
        // test rsa conversion
        {
            REQUIRE_NOTHROW(gen.generate_key(curve_t::secp192r1));
            auto pri_data = gen.export_key(pk::pem_format);
            auto pub_data = gen.export_public_key(pk::pem_format);

            rsa rkey;
            REQUIRE_THROWS(rkey.import_key(pri_data));
            REQUIRE_THROWS(rkey.import_public_key(pub_data));
        }

        const std::initializer_list<curve_t> Items = {
            curve_t::secp192r1,
            curve_t::secp224r1,
            curve_t::secp256r1,
            curve_t::secp384r1,
            curve_t::secp521r1,
            curve_t::secp192k1,
            curve_t::secp224k1,
            curve_t::secp256k1,
            curve_t::bp256r1,
            curve_t::bp384r1,
            curve_t::bp512r1,
            // curve_t::curve25519, // reported bug in mbedtls!
        };

        auto key_test = [&gen](curve_t ctype, const auto& afs) {
            gen.generate_key(ctype);
            auto pri_data = gen.export_key(pk::pem_format);
            auto pub_data = gen.export_public_key(pk::pem_format);

            ecp pri;
            pri.import_key(pri_data);
            REQUIRE(pri.type() == gen.type());
            REQUIRE((pub_data == pri.export_public_key(pk::pem_format)));
            auto ki = pri.key_info();
            mpi_checker("Qx: ", ki.Qx);
            mpi_checker("Qy: ", ki.Qy);
            mpi_checker("Qz: ", ki.Qz);
            mpi_checker("d: ",  ki.d);

            ecp pub;
            pub.import_public_key(pub_data);
            REQUIRE(pub.type() == gen.type());
            ki = pub.key_info();
            mpi_checker("Qx: ", ki.Qx);
            mpi_checker("Qy: ", ki.Qy);
            mpi_checker("Qz: ", ki.Qz);
            REQUIRE(ki.d == false);

            REQUIRE(check_pair(pub, pri));

            REQUIRE((pri.what_can_do() == std::get<0>(afs)));
            REQUIRE((pub.what_can_do() == std::get<1>(afs)));
        };

        auto eckey_afs = []() {
            if (supports(pk_t::ecdsa)) {
                return std::make_tuple(
                    pk::action_flags{false, false, true, true},
                    pk::action_flags{false, false, false, true});

            } else {
                return std::make_tuple(
                    pk::action_flags{false, false, false, false},
                    pk::action_flags{false, false, false, false});
            }
        };

        for (auto i : Items) {
            REQUIRE_NOTHROW(key_test(i, eckey_afs()));
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// test ecdsa
#if defined(MBEDTLS_ECDSA_C)
namespace mbedtls {
namespace details {
template <>
inline void
initializer(mbedtls_ecdsa_context* ctx) noexcept {
    mbedtls_ecdsa_init(ctx);
}

template <>
inline void
cleanup(mbedtls_ecdsa_context* ctx) noexcept {
    mbedtls_ecdsa_free(ctx);
}
} // namespace details
using ecdsa = wrapper<mbedtls_ecdsa_context>;
} // namespace mbedtls
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("ecdsa c_api tests", "[pk]") {
    mbedcrypto::ecdsa ec_;
    ec_.generate_key(mbedcrypto::curve_t::secp192r1);

    auto hash_ = mbedcrypto::make_hash(
        mbedcrypto::hash_t::sha256, mbedcrypto::test::long_text());

    auto c_sign = [&]() -> std::string {
        const auto*    ec_ctx = mbedtls_pk_ec(ec_.context().pk_);
        mbedtls::ecdsa signer;

        // private key copy
        mbedtls_c_call(mbedtls_ecp_group_copy, &signer->grp, &ec_ctx->grp);
        mbedtls_c_call(mbedtls_ecp_copy, &signer->Q, &ec_ctx->Q);
        mbedtls_c_call(mbedtls_mpi_copy, &signer->d, &ec_ctx->d);

        std::string signature((size_t)MBEDTLS_ECDSA_MAX_LEN, '\0');
        size_t      sig_len = signature.size();
        mbedtls_c_call(
            mbedtls_ecdsa_write_signature,
            signer,
            MBEDTLS_MD_SHA256,
            mbedcrypto::to_const_ptr(hash_),
            hash_.size(),
            mbedcrypto::to_ptr(signature),
            &sig_len,
            mbedcrypto::rnd_generator::maker,
            &ec_.context().rnd_);

        signature.resize(sig_len);
        return signature;
    };

    auto c_verify = [&](const std::string& signature) -> bool {
        const auto*    ec_ctx = mbedtls_pk_ec(ec_.context().pk_);
        mbedtls::ecdsa verifier;

        // public key copy
        mbedtls_c_call(mbedtls_ecp_group_copy, &verifier->grp, &ec_ctx->grp);
        mbedtls_c_call(mbedtls_ecp_copy, &verifier->Q, &ec_ctx->Q);

        int ret = mbedtls_ecdsa_read_signature(
            verifier,
            mbedcrypto::to_const_ptr(hash_),
            hash_.size(),
            mbedcrypto::to_const_ptr(signature),
            signature.size());

        if (ret == 0)
            return true;

        std::cout << mbedcrypto::mbedtls_error_string(ret) << std::endl;
        return false;
    };

    auto cpp_sign = [&]() -> std::string { return ec_.sign(hash_); };

    auto cpp_verify = [&](const std::string& signature) -> bool {
        return ec_.verify(signature, hash_);
    };

    // sign by c_api
    auto sig = c_sign();
    REQUIRE(c_verify(sig));
    REQUIRE(cpp_verify(sig));

    sig = cpp_sign();
    REQUIRE(c_verify(sig));
    REQUIRE(cpp_verify(sig));
}

TEST_CASE("ecdsa tests", "[pk]") {
    using namespace mbedcrypto;
    auto message_ = test::long_text();

    ecdsa signer;
    signer.generate_key(curve_t::secp192k1);
    auto sig = signer.sign(message_, hash_t::sha256);

    ecdsa verifier;
    verifier.import_public_key(signer.export_public_key(pk::pem_format));

    REQUIRE(verifier.verify(sig, message_, hash_t::sha256));
}

///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLS_ECDSA_C
///////////////////////////////////////////////////////////////////////////////

// test ecdh
#if defined(MBEDTLS_ECDH_C)
namespace mbedtls {
namespace details {
template <>
inline void
initializer(mbedtls_ecdh_context* ctx) noexcept {
    mbedtls_ecdh_init(ctx);
}

template <>
inline void
cleanup(mbedtls_ecdh_context* ctx) noexcept {
    mbedtls_ecdh_free(ctx);
}
} // namespace details
using ecdh = wrapper<mbedtls_ecdh_context>;

struct ecdh_base {
    enum K {
        psk_length = 150,
    };

    mbedcrypto::rnd_generator rnd_{"ecdh generator"};
    mbedtls::ecdh             ecdh_;
}; // struct ecdh_base

struct peer : public ecdh_base {

    auto make_peer_key(mbedcrypto::curve_t ctype) {
        mbedtls_c_call(
            mbedtls_ecp_group_load, &ecdh_->grp, mbedcrypto::to_native(ctype));

        mbedtls_c_call(
            mbedtls_ecdh_gen_public,
            &ecdh_->grp,
            &ecdh_->d,
            &ecdh_->Q,
            mbedcrypto::rnd_generator::maker,
            &rnd_);

        std::string mypub(psk_length, '\0');
        size_t      olen = 0;
        mbedtls_c_call(
            mbedtls_ecp_tls_write_point,
            &ecdh_->grp,
            &ecdh_->Q,
            ecdh_->point_format,
            &olen,
            mbedcrypto::to_ptr(mypub),
            psk_length);

        mypub.resize(olen);
        return mypub;
    }

    auto shared_secret(const std::string& otherpub) {
        const auto* p = mbedcrypto::to_const_ptr(otherpub);
        mbedtls_c_call(
            mbedtls_ecp_tls_read_point,
            &ecdh_->grp,
            &ecdh_->Qp,
            &p,
            otherpub.size());

        std::string secret(psk_length, '\0');
        size_t      olen = 0;
        mbedtls_c_call(
            mbedtls_ecdh_calc_secret,
            ecdh_,
            &olen,
            mbedcrypto::to_ptr(secret),
            psk_length,
            mbedcrypto::rnd_generator::maker,
            &rnd_);

        secret.resize(olen);
        return secret;
    }

}; // struct peer

} // namespace mbedtls
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("ecdh tests", "[pk]") {
    using namespace mbedcrypto;

    SECTION("calculate shared secret") {
        const auto ctype = curve_t::secp192k1;

        ecdh server;
        auto srv_pub = server.make_peer_key(ctype);

        ecdh client;
        client.generate_key(ctype); // alternative approach to make_peer_key()
        auto cli_pub = client.peer_key();

        auto sss = server.shared_secret(cli_pub); // server shared secret
        auto css = client.shared_secret(srv_pub); // client shared secret
        REQUIRE((sss == css));

        {
            mbedtls::peer c_cli;
            cli_pub = c_cli.make_peer_key(ctype);

            sss = server.shared_secret(cli_pub);
            css = c_cli.shared_secret(srv_pub);
            REQUIRE((sss == css));
        }

        if (supports(features::pk_export)) {
            auto pri_key = client.export_key(pk::pem_format);
            ecdh clone;
            clone.import_key(pri_key);
            cli_pub = clone.peer_key();

            sss = server.shared_secret(cli_pub);
            css = clone.shared_secret(srv_pub);
            REQUIRE((sss == css));
        }
    }

    SECTION("RFC 4492") {
        const auto ctype = curve_t::secp224r1;
        ecdh       server;
        auto       skex = server.make_server_key_exchange(ctype);

        ecdh client;
        auto cli_pub = client.make_client_peer_key(skex);
        auto css     = client.shared_secret();

        auto sss = server.shared_secret(cli_pub);
        REQUIRE((sss == css));
    }
}
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLS_ECDH_C
///////////////////////////////////////////////////////////////////////////////
#endif // MBEDTLS_ECP_C

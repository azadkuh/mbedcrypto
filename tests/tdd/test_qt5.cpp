#if defined(QT_CORE_LIB)
#include <catch.hpp>

#include "mbedcrypto/tcodec.hpp"
#include "mbedcrypto/hash.hpp"

#include "generator.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace {
///////////////////////////////////////////////////////////////////////////////
bool operator==(const QByteArray& ba, const std::string& ss) {
    return ba == ss.data();
}
///////////////////////////////////////////////////////////////////////////////
} // namespace anon
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("test qt5 bindings", "[qt5]") {
    using namespace mbedcrypto;

    SECTION("test pointers") {
        QByteArray sample{"mbedcrypto"};
        auto pc = to_const_ptr(sample);
        REQUIRE( *pc == 'm' );

        auto p = to_ptr(sample);
        *p = 'M';
        REQUIRE( (sample == "Mbedcrypto") );
    }

    SECTION("text codecs") {
        std::string s{"mbedcrypto library"};
        QByteArray  q = QByteArray::fromStdString(s);

        auto sr = to_hex(s);
        auto qr = to_hex(q);
        REQUIRE( (qr == sr) );

        auto ts = from_hex(sr);
        auto tq = from_hex(qr);
        REQUIRE( (tq == ts) );

        sr = to_base64(s);
        qr = to_base64(q);
        REQUIRE( (qr == sr) );

        ts = from_base64(sr);
        tq = from_base64(qr);
        REQUIRE( (tq == ts) );
    }

    SECTION("message digests") {
        std::string s{test::long_text()};
        QByteArray  q{test::long_text()};

        auto hs = to_base64(to_sha1(s));
        auto hq = to_base64(to_sha1(q));
        REQUIRE( (hq == hs) );

        hs = to_base64(to_sha256(s));
        hq = to_base64(to_sha256(q));
        REQUIRE( (hq == hs) );

        hs = to_base64(to_sha512(s));
        hq = to_base64(to_sha512(q));
        REQUIRE( (hq == hs) );

        std::string ks{test::short_text()};
        QByteArray  kq{test::short_text()};
        auto ms = to_base64(hmac::make(hash_t::sha1, ks, s));
        auto mq = to_base64(hmac::make(hash_t::sha1, kq, q));
        REQUIRE( (mq == ms) );

        ms = to_base64(make_hmac(hash_t::sha256, ks, s));
        mq = to_base64(make_hmac(hash_t::sha256, kq, q));
        REQUIRE( (mq == ms) );

        ms = to_base64(hmac::make(hash_t::sha512, ks, s));
        mq = to_base64(hmac::make(hash_t::sha512, kq, q));
        REQUIRE( (mq == ms) );
    }

}

///////////////////////////////////////////////////////////////////////////////
#endif // QT_CORE_LIB

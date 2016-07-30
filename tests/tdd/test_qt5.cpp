#if defined(QT_CORE_LIB)
#include <catch.hpp>

#include "mbedcrypto/tcodec.hpp"
#include "mbedcrypto/hash.hpp"

#include <QByteArray>
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

}

///////////////////////////////////////////////////////////////////////////////
#endif // QT_CORE_LIB

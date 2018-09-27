/** @file ecp.hpp
 *
 * @copyright (C) 2016
 * @date 2016.05.08
 * @author amir zamani <azadkuh@live.com>
 *
 */

#ifndef __MBEDCRYPTO_ECP_HPP__
#define __MBEDCRYPTO_ECP_HPP__

#include "mbedcrypto/pk.hpp"
///////////////////////////////////////////////////////////////////////////////
namespace mbedcrypto {
///////////////////////////////////////////////////////////////////////////////

/** elliptic curve (ec) for public key cryptography.
 * to use this ec you must build mbedcrypto with:
 *  - MBEDCRYPTO_EC
 *  other related options:
 *  - MBEDCRYPTO_PK_EXPORT
 * @sa cmake options
 */
class ecp : public pk::pk_base
{
public:
    /// contructs with one of pk_t::eckey, pk_t::eckey_dh or pk_t::ecdsa
    explicit ecp(pk_t ptype = pk_t::eckey);

    ~ecp();

public: // helper funtions for ec functionalities
    void generate_key(curve_t curve_type) {
        pk::generate_ec_key(context(), curve_type);
    }

public:
    /// ec key information
    struct key_info {
        mpi Qx; ///< x of public point
        mpi Qy; ///< y of public point
        mpi Qz; ///< z of public point

        // only valid if the key is a private key
        mpi d; ///< secret value
    }; // struct key_info

    /// exports info of current key
    void operator>>(key_info&) const;

    auto key_info() const {
        struct key_info ki;
        *this >> ki;
        return ki;
    }

public: // move only
    ecp(const ecp&) = delete;
    ecp(ecp&&)      = default;
    ecp& operator=(const ecp&) = delete;
    ecp& operator=(ecp&&)      = default;

    virtual pk::context&       context() override;
    virtual const pk::context& context() const override;

protected:
    struct impl;
    std::unique_ptr<impl> pimpl;
}; // ecp
///////////////////////////////////////////////////////////////////////////////
/// ECDSA specialized class
struct ecdsa : public ecp {
    explicit ecdsa() : ecp(pk_t::ecdsa) {}

    auto sign(buffer_view_t hash_value, hash_t hash_type) {
        return pk::sign(context(), hash_value, hash_type);
    }

    auto sign_message(buffer_view_t message, hash_t hash_type) {
        return pk::sign_message(context(), message, hash_type);
    }

    bool verify(
        buffer_view_t signature, buffer_view_t hash_value, hash_t hash_type) {
        return pk::verify(context(), signature, hash_value, hash_type);
    }

    bool verify_message(
        buffer_view_t signature, buffer_view_t message, hash_t hash_type) {
        return pk::verify_message(context(), signature, message, hash_type);
    }
}; // struct ecdsa
///////////////////////////////////////////////////////////////////////////////
/** ECDH(E) TLS compatible implementation.
 *
 * to calculate the shared secret when the curve type is predefined on both
 * ends:
 * @code
 * // const auto ctype = curve_t::...; // both know the curve type
 *
 * ecdh server;
 * auto srv_pub = server.make_peer_key(ctype);
 * // send srv_pub to client
 *
 * ecdh client;
 * client.generate_key(ctype); // alternative approach to make_peer_key()
 * auto cli_pub = client.peer_key();
 * // send cli_pub to server
 *
 * auto sss = server.shared_secret(cli_pub); // on server
 * auto css = client.shared_secret(srv_pub); // on client
 * REQUIRE( (sss == css) );
 * @endcode
 *
 * to calculate the shared secret by RFC 4492 (when server defines the curve
 * parameters and the client follows the server):
 * @code
 * ecdh server;
 * // (only) server defines the curve type
 * auto skex = server.make_server_key_exchange(curve_t::...);
 * // send server's key exchange params to client
 *
 * ecdh client;
 * auto cli_pub = client.make_client_peer_key(skex);
 * auto css     = client.shared_secret();
 * // send cli_pub to server
 *
 * auto sss     = server.shared_secret(cli_pub); // on server
 * REQUIRE( (sss == css) );
 * @endcode
 */
struct ecdh : public ecp {
    explicit ecdh() : ecp(pk_t::eckey_dh) {}

public:
    /** returns the public key (point) made by ecp::generate_key().
     * same as make_peer_key() but the keys are exportable/importable 'cos they
     * are made by ecp::generate_key()
     */
    auto peer_key() -> buffer_t;
    /** resets and generates a new key pair then returns peer_key().
     * returns the public key (point) to be sent to peer (other enpoint).
     *
     * @warning you can not export_xxx()/import_xxx() the pri/pub keys generated
     * by this method. if you need to export/import the keys, use the combination
     *  of ecp::generate_key() and peer_key() instead.
     */
    auto make_peer_key(curve_t) -> buffer_t;

    /// calculates the shared secret by the peer (other endpoint) public key
    auto shared_secret(buffer_view_t peer_key) -> buffer_t;

    /** calculates the shared secret if peer's public has been loaded before.
     * @sa make_client_peer_key()
     */
    auto shared_secret() -> buffer_t;

public: // RFC 4492 implementation ServerKeyExchange parameters
    /** server makes its own key pair and returns ServerKeyExchange as RFC4492.
     * both curve parameters and public key (point) are returned
     */
    auto make_server_key_exchange(curve_t) -> buffer_t;

    /** client loads curve parameters and the server's public key.
     * returns the client's public key
     */
    auto make_client_peer_key(buffer_view_t server_key_exchange) -> buffer_t;
}; // class ecdhe

///////////////////////////////////////////////////////////////////////////////
/// helper function, @sa pk::check_pair()
inline bool
check_pair(const ecp& pub, const ecp& pri) {
    return pk::check_pair(pub.context(), pri.context());
}

///////////////////////////////////////////////////////////////////////////////
} // namespace mbedcrypto
///////////////////////////////////////////////////////////////////////////////
#endif // __MBEDCRYPTO_ECP_HPP__

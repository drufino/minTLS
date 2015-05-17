#include "tls/tls_handshake.hpp"
#include "tls/tls_ecc.hpp"
#include "test_helpers.hpp"
#include "random.h"

template<typename T>
void test_serialization(T const& msg, std::vector<uint8_t> const& expected_serialized, T const& default_val = T())
{
    {
        std::vector<uint8_t> serialized; oarchive ar(serialized);

        ar << msg;
        EXPECT_EQ(serialized, expected_serialized);
    }

    {
        iarchive ar_read(&expected_serialized[0], expected_serialized.size());
        T msg_rt(default_val);
        ar_read & msg_rt;
        EXPECT_EQ(msg_rt, msg);
    }
}

template<typename T>
void test_handshake(T const& msg, std::vector<uint8_t> const& expected_serialized, T const& default_val = T())
{
    test_serialization(msg, expected_serialized, default_val);

    std::vector<uint8_t> payload(10,'b');
    msg.write_payload(payload);

    EXPECT_EQ(msg.content_type(), ContentTypes::Handshake);

    std::vector<uint8_t> header;
    TLSHandshakeMsg::write_header(header, msg.handshake_type(), expected_serialized.size());

    EXPECT_EQ(payload,std::vector<uint8_t>(10,'b') + header + expected_serialized);
}

static std::vector<uint8_t> empty;
TEST(tls_handshake_serialization_test, client_key_exchange)
{
    std::vector<uint8_t> x(10); mintls_random(&x[0],x.size());

    {
        KexMethod kex(KexMethods::DHE_RSA);
        TLSClientKeyExchange empty_kx(kex, empty);
        TLSClientKeyExchange random_kx(kex, x);

        test_handshake(empty_kx,    std::vector<uint8_t>({0x0,0x0}), TLSClientKeyExchange(kex));
        test_handshake(random_kx,   std::vector<uint8_t>({0x0,0x0a}) + x, TLSClientKeyExchange(kex));
    }

    {
        KexMethod kex(KexMethods::ECDHE_RSA);
        TLSClientKeyExchange empty_kx(kex, empty);
        TLSClientKeyExchange random_kx(kex, x);

        test_handshake(empty_kx,    std::vector<uint8_t>({0x0}), TLSClientKeyExchange(kex));
        test_handshake(random_kx,   std::vector<uint8_t>({0x0a}) + x, TLSClientKeyExchange(kex));
    }
}

TEST(tls_handshake_serialization_test, finished)
{
    std::vector<uint8_t> x(10); mintls_random(&x[0],x.size());

    TLSFinished empty_kx(empty);
    TLSFinished random_kx(x);

    test_handshake(empty_kx,    empty);
    test_handshake(random_kx,   x);
}

// Check we serialize and dserialize client hello correctly
TEST(tls_handshake_serialization_test, client_hello)
{
    std::vector<uint8_t> random(28); 
    for (int i = 0; i < 28; ++i) random[i] = i+1;

    std::vector<CipherSuite> cipher_suites;
    cipher_suites.push_back(CipherSuites::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
    cipher_suites.push_back(CipherSuites::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);

    EXPECT_ANY_THROW({TLSClientHello client_hello(TLSProtocolVersion(), random, cipher_suites);});
    random.resize(32);
    for (int i = 0; i < 32; ++i) random[i] = i+1;

    TLSClientHello client_hello(TLSProtocolVersion(), random, cipher_suites);
    client_hello.session_id = std::vector<uint8_t>({0x04,0x01,0x0a});

    ASSERT_EQ(sizeof(client_hello.random),32);

    std::vector<uint8_t> expected_serialization =
        {0x03,0x03, // 6
         1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 18,19,20,21,22,23,24,25,26,27,28,29,30,31,32, //random
         0x03,0x04,0x01,0x0a, // session id
         0x00,0x04,0x00,0x67,0x00,0x6B, // cipher suites
         0x01,0x00  // compression
     };
    test_handshake(client_hello,expected_serialization);
}

// Check we serialize and dserialize client hello correctly
TEST(tls_handshake_serialization_test, server_hello)
{
    std::vector<uint8_t> random(28); 
    for (int i = 0; i < 28; ++i) random[i] = i+1;

    std::vector<uint8_t> session(6);
    for (int i = 0; i < 6; ++i) session[i] = i+5;

     EXPECT_ANY_THROW({TLSServerHello server_hello(TLSProtocolVersion(3,1), random, session, CipherSuites::TLS_RSA_WITH_AES_128_GCM_SHA256, 0x1);});
    random.resize(32);
    for (int i = 0; i < 32; ++i) random[i] = i+1;

    TLSServerHello server_hello(TLSProtocolVersion(3,1), random, session, CipherSuites::TLS_RSA_WITH_AES_128_GCM_SHA256, 0x1);

    std::vector<uint8_t> expected_serialization =
        {0x03,0x01,  // 6
         1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17, 18,19,20,21,22,23,24,25,26,27,28,29,30,31,32, //random
         0x06,0x05,0x06,0x07,0x08,0x09,0x0a, // session id
         0x00,0x9C,  // cipher suite
         0x01
     };
    test_handshake(server_hello,expected_serialization);
}

template<typename T>
void check_extension_helper(T * pExt, std::vector<uint8_t> const& bytes)
{
    std::shared_ptr<T> ext(pExt);
    TLSExtension extension(ext);
    test_serialization(extension, bytes);
}

// Check that extensions serialize correctly
TEST(tls_handshake_serialization_test, extension_test)
{
    typedef std::vector<uint8_t> array;

    std::vector<TLSNamedCurve> curves;

    EXPECT_ANY_THROW(
        check_extension_helper(
            new TLSSupportedEllipticCurves(),
            array({'\x00','\x0a','\x00','\x02', '\x00', '\x00'})
        )
    ); 

    curves.push_back(mintls_secp224r1);
    check_extension_helper(
        new TLSSupportedEllipticCurves(curves),
        array({'\x00','\x0a','\x00','\x04', '\x00', '\x02', '\x00', '\x15'})
    );

    curves.push_back(mintls_secp256r1);
    check_extension_helper(
        new TLSSupportedEllipticCurves(curves),
        array({'\x00','\x0a','\x00','\x06', '\x00', '\x04', '\x00', '\x15', '\x00', '\x17'})
    );
}

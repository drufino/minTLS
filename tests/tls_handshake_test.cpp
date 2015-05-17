#include "tls/tls_handshake.hpp"
#include "tls/tls_extensions.hpp"
#include "test_helpers.hpp"
#include "test_helpers.cpp"

TEST(tls_handshake_test, read_header)
{
    struct test_case
    {
        TLSHandshakeMsg::Type           type;
        size_t                          length;
        const char *                    buf;
    };

    struct test_case cases[] = {
        {TLSHandshakeMsg::ServerHello, 0x000340, "\x02\x00\x03\x40"},
        {TLSHandshakeMsg::Certificate, 0xf0e212, "\x0b\xf0\xe2\x12"}
    };

    for (unsigned iCase = 0; iCase < sizeof(cases)/sizeof(struct test_case); ++iCase)
    {
        struct test_case const& case_ = cases[iCase];
        TLSHandshakeMsg::Type           type((TLSHandshakeMsg::Type)-1);
        size_t                          length(0);
        EXPECT_NO_THROW(TLSHandshakeMsg::read_header((uint8_t const*)case_.buf,type,length));
        EXPECT_EQ(type,case_.type);
        EXPECT_EQ(length,case_.length);

        std::vector<uint8_t> buf(2,0x2);
        TLSHandshakeMsg::write_header(buf,type,length);
        EXPECT_EQ(buf.size(),6);
        EXPECT_EQ(std::vector<uint8_t>(buf.begin()+2,buf.end()), std::vector<uint8_t>(case_.buf,case_.buf+4));
        EXPECT_TRUE(TLSHandshakeMsg::is_valid(type));
    }

    TLSHandshakeMsg::Type   type;
    size_t                  length;
    uint8_t invalid_buf[4] = {0xf0,0x00,0x00,0x00};
    EXPECT_THROW(TLSHandshakeMsg::read_header(invalid_buf, type, length), TLSException);
}




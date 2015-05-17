#include "../src/asn1/asn1.hpp"
#include "core/archive.hpp"
#include "../src/asn1/asn1_objects.hpp"
#include "test_helpers.hpp"
#include "test_helpers.cpp"
#include "test_main.hpp"
#include <stdint.h>

using namespace asn1;

int
int_test_helper(uint8_t const* buf, size_t sz)
{
    iarchive ar(buf,sz);
    int x;
    asn1::asn1_content<asn1::Tags::INTEGER,int>(ar,x,"",false);
    return x;
}

TEST(asn1_test,OID_test)
{
    EXPECT_EQ(asn1::OID("1.22.333.4").ids(),std::vector<uint32_t>({1,22,333,4}));
	std::vector<uint32_t> one(1, 1);
	EXPECT_EQ(asn1::OID("1").ids(), one);
    EXPECT_THROW(asn1::OID(""),std::runtime_error);
    EXPECT_THROW(asn1::OID("1."),std::runtime_error);
    EXPECT_THROW(asn1::OID(".1"),std::runtime_error);
    EXPECT_THROW(asn1::OID("1.2."),std::runtime_error);
    EXPECT_THROW(asn1::OID("1..2"),std::runtime_error);
    EXPECT_THROW(asn1::OID("A.B"),std::runtime_error);
}
TEST(asn1_test,bit_string)
{
    std::vector<uint8_t> bits;
    bits.push_back(0x0);
    for (int i = 0; i < 256; ++i)
    {
        bits.push_back(static_cast<uint8_t>(i));
    }
    std::vector<uint8_t> bits_;

    {
        iarchive ar(&bits[0], bits.size());
        asn1::asn1_content<asn1::Tags::BIT_STRING,std::vector<uint8_t> >(ar, bits_, "",false);
        EXPECT_EQ(std::vector<uint8_t>(bits.begin()+1,bits.end()),bits_);
    }
    {
        bits[0] = 0x1;
        iarchive ar(&bits[0], bits.size());
        EXPECT_THROW((asn1::asn1_content<asn1::Tags::BIT_STRING,std::vector<uint8_t> >(ar, bits_, "", false)),asn1::ber_decoding_error);
    }
}

int bit_string_to_int(std::vector<uint8_t> const& bytes, bool const bDER)
{
    iarchive ar(&bytes[0], bytes.size());
    int x(0);
    asn1::asn1_content<asn1::Tags::BIT_STRING, int>(ar, x, "", bDER);
    return x;
}

void bit_string_helper(int x, std::vector<uint8_t> const& bytes, bool const bValidDER)
{
    EXPECT_EQ(x, bit_string_to_int(bytes, false)) << "x = " << std::hex << (int)x << " padding = " << (int)bytes[0] << " bytes = " << (int)bytes[1];
    if (bValidDER)
    {
        EXPECT_EQ(x, bit_string_to_int(bytes, true)) << "x = " << std::hex << (int)x << " padding = " << (int)bytes[0] << " bytes = " << (int)bytes[1];
    }
    else
    {
        EXPECT_THROW(bit_string_to_int(bytes, true), asn1::ber_decoding_error);
    }
}

TEST(asn1_test,bit_string_integer)
{
    // Check that the bits are reversed correctly for single byte encodings
    for (unsigned i = 0; i <= 0xff; ++i)
    {
        // Check bits are reversed
        uint8_t j = ((i & 0x80) >> 7) | ((i & 0x40) >> 5) | ((i & 0x20) >> 3) | ((i & 0x10) >> 1)
                  | ((i & 0x08) << 1) | ((i & 0x04) << 3) | ((i & 0x02) << 5) | ((i & 0x01) << 7);

        bit_string_helper((int)j,{0x0,(uint8_t)i}, true);

        // Check padding field is respected by masking out the low order bits in the final byte
        uint8_t masks[] = {0x0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f};
        for (uint8_t padding = 1; padding <= 1; ++padding)
        {
            uint8_t mask = masks[padding];

            int x_unpadded = bit_string_to_int({0, (uint8_t)(i&~mask)}, false);

            // DER requires unused bits to be zero
            bit_string_helper(x_unpadded, {padding, (uint8_t)i}, (i&mask) == 0);
        }
    }

    // Check two-byte encoding works
    for (unsigned i = 0; i <= 0xffff; i += 0x107)
    {
        for (uint8_t padding = 0; padding <= 7; ++padding)
        {
            uint8_t a = i & 0xff;
            uint8_t b = (i>>8) & 0xff;
            int x = bit_string_to_int({padding, a, b}, false);
            int y = bit_string_to_int({0x0, a}, false);
            int z = bit_string_to_int({padding, b}, false);
            EXPECT_EQ(x, y|(z<<8));
        }
    }
}

TEST(asn1_test,string)
{
    std::string test1 = "abcedfghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+,-./:=?";
    std::vector<uint8_t> test1_x(test1.begin(),test1.end());
    std::string test1_;

    {
        iarchive ar(&test1_x[0],test1_x.size());
        asn1::asn1_content<asn1::Tags::PRINTABLE_STRING,std::string>(ar,test1_,"",false);
        EXPECT_EQ(test1,test1_);
    }
    {
        iarchive ar(&test1_x[0],test1_x.size());
        asn1::asn1_content<asn1::Tags::UTF8_STRING,std::string>(ar,test1_,"",false);
        EXPECT_EQ(test1,test1_);
    }
    {
        iarchive ar(&test1_x[0],test1_x.size());
        asn1::asn1_content<asn1::Tags::IA5_STRING,std::string>(ar,test1_,"",false);
        EXPECT_EQ(test1,test1_);
    }
}

TEST(asn1_test,octet_string)
{
    for (unsigned i = 0x1; i < 10; ++i)
    {
        std::vector<uint8_t> in_buf(i,0x1);
        for (unsigned j = 0; j < i; ++j)
        {
            in_buf[j] = rand()&0xff;
        }

        iarchive ar(&in_buf[0],in_buf.size());

        std::vector<uint8_t> out_buf;
        asn1::asn1_content<asn1::Tags::OCTET_STRING,std::vector<uint8_t> >(ar,out_buf,"",false);
        EXPECT_EQ(out_buf,in_buf);
    }
}

int
int_content_decoder(char const* buf, size_t sz, bool bDER)
{
    iarchive ar((uint8_t const *)buf,sz);
    int x;
    asn1::asn1_content<asn1::Tags::INTEGER,int>(ar,x,"",bDER);
    EXPECT_EQ(ar.left(), 0);
    return x;
}

BigInt
bigint_content_decoder(char const* buf, size_t sz, bool bDER)
{
    iarchive ar((uint8_t const *)buf,sz);
    BigInt x;
    asn1::asn1_content<asn1::Tags::INTEGER,BigInt>(ar,x,"",bDER);
    EXPECT_EQ(ar.left(), 0);
    return x;
}

int
int_content_decoder(char const* buf, size_t sz)
{
    int x1 = int_content_decoder(buf,sz,false);
    int x2 = int_content_decoder(buf,sz,true);
    EXPECT_EQ(x1,x2);
    return x1;
}

BigInt
bigint_content_decoder(char const* buf, size_t sz)
{
    BigInt x1 = bigint_content_decoder(buf,sz,false);
    BigInt x2 = bigint_content_decoder(buf,sz,true);
    EXPECT_EQ(x1,x2);
    return x1;
}

// [5] 8.3
TEST(asn1_test,int_content_test)
{
    using namespace asn1;

    for (uint8_t x = 0; x <= 0x7f; ++x)
    {
        EXPECT_EQ(int_content_decoder((char const *)&x,1),x);
        EXPECT_EQ(bigint_content_decoder((char const *)&x, 1), BigInt(x));
        uint8_t y = ~x;
        if (y != 0)
        {
            EXPECT_EQ(int_content_decoder((char const *)&y,1),-(int)(x+1)); 
            EXPECT_EQ(bigint_content_decoder((char const *)&y,1),-BigInt(x+1));
        }
    }
    EXPECT_EQ(int_content_decoder("\x0a\xb0",2),0x0ab0);
    EXPECT_EQ(int_content_decoder("\x00\x80",2),0x0080);
    EXPECT_EQ(int_content_decoder("\x00\x81",2),0x0081);
    // Encoding has to be minimal (8.3.2)
    EXPECT_THROW(int_content_decoder("\x00\x7f",2),asn1::ber_decoding_error);
    EXPECT_THROW(int_content_decoder("\x00\x02",2),asn1::ber_decoding_error);
    EXPECT_THROW(int_content_decoder("\xff\x80",2),asn1::ber_decoding_error);
    EXPECT_EQ(int_content_decoder("\x01\x00\x80",3),0x010080);
    EXPECT_EQ(int_content_decoder("\x01\x00\x08",3),0x010008);
    // integer overflow
    EXPECT_THROW(int_content_decoder("\x01\x01\x01\x01\x01",5),asn1::ber_decoding_error);

    // negative
    EXPECT_EQ(int_content_decoder("\x48",1),72);
    EXPECT_EQ(int_content_decoder("\x7f",1),0x7f);
    EXPECT_EQ(int_content_decoder("\x80",1),-0x80);
    EXPECT_EQ(int_content_decoder("\x00\x80",2),0x80);
}

asn1::Tag tag_decoder(uint8_t const *encoding, size_t const sz)
{
    iarchive ar(encoding, sz);
    asn1::Tag tag = asn1::decode_tag(ar, NULL);
    EXPECT_EQ(0,ar.left());
    return tag;
}

TEST(asn1_test,short_tag_test)
{
    using namespace asn1;

    for (uint8_t class_tag = 0; class_tag < 4; ++class_tag)
    {
        for (uint8_t type_tag = 0; type_tag < 0x20; ++type_tag)
        {
            for (uint8_t pc = 0; pc < 2; ++pc)
            {
                Tag total_tag = Tag(Classes::type(class_tag << 6 | pc << 5),Tags::type(type_tag));
                uint8_t total_tag_b = (class_tag << 6 | pc << 5) | type_tag;
                if (type_tag == 0x1f)
                {
                    EXPECT_THROW(tag_decoder(&total_tag_b,1),ber_decoding_error);
                }
                else
                {
                    EXPECT_EQ(total_tag, tag_decoder(&total_tag_b,1));
                }
            }
        }
    }
}

// Long-form tags [5] 8.1.2.4
TEST(asn1_test,long_tag_test)
{
    using namespace asn1;

    for (uint8_t class_tag = 0; class_tag < 4; ++class_tag)
    {
        for (uint8_t pc = 0; pc < 2; ++pc)
        {
            for (int type_tag = 0x0; type_tag <= 0xff; ++type_tag)
            {
                uint8_t encoded_tag[2];

                encoded_tag[0] = class_tag << 6 | pc << 5 | 0x1f;
                encoded_tag[1] = (uint8_t)type_tag;
                Tag total_tag = Tag(Classes::type(class_tag << 6 | pc << 5),Tags::type(type_tag));

                if (type_tag < 0x1f)
                {
                    EXPECT_THROW(tag_decoder(encoded_tag,2), ber_decoding_error) << " type tag=" << std::hex << type_tag;
                }
                else if (type_tag >= 0x80)
                {
                    EXPECT_THROW(tag_decoder(encoded_tag, 2), ber_decoding_error);
                }
                else
                {
                    EXPECT_EQ(tag_decoder(encoded_tag,2), total_tag);
                }
            }
        }
    }
}

size_t length_decoder(std::vector<uint8_t> const& x, bool const bDER=true)
{
    iarchive ar(&x[0],x.size());
    size_t len = asn1::decode_length(ar,bDER);
    EXPECT_EQ(ar.left(),0);
    return len;
}

// Length decoding [5]  8.1.3
// Only support short-form and long-form definite encoding, not indefinite encoding
TEST(asn1_test,length_test)
{
    using namespace asn1;

    std::vector<uint8_t> x;

    for (uint8_t i = 0; i <= 0x7f; ++i)
    {
        // Check short form
        x = std::vector<uint8_t>(1,i);
        EXPECT_EQ(size_t(i),length_decoder(x,true));
        EXPECT_EQ(size_t(i),length_decoder(x,false));

        // Check long form
        x = std::vector<uint8_t>({0x81,i});
        EXPECT_EQ(size_t(i),length_decoder(x,false));

        // DER disallows encoding small numbers in long form 
        EXPECT_THROW(length_decoder(x,true),ber_decoding_error);
    }

    // These are explicitly disallowed [5] 8.1.3.5
    { uint8_t x(0x80); iarchive ar(&x,1); EXPECT_THROW(decode_length(ar,true),ber_decoding_error); EXPECT_EQ(ar.left(),0); }
    { uint8_t x(0x80); iarchive ar(&x,1); EXPECT_THROW(decode_length(ar,false),ber_decoding_error); EXPECT_EQ(ar.left(),0); }
    { uint8_t x(0xff); iarchive ar(&x,1); EXPECT_THROW(decode_length(ar,true),ber_decoding_error); EXPECT_EQ(ar.left(),0); }
    { uint8_t x(0xff); iarchive ar(&x,1); EXPECT_THROW(decode_length(ar,false),ber_decoding_error); EXPECT_EQ(ar.left(),0); }

    // Check long form valid DER encodings
    for (int bDER_ = 0; bDER_ <= 1; ++bDER_)
    {
        bool const bDER = (bDER_ == 0) ? false : true;
        x = std::vector<uint8_t>({(uint8_t)(0x80+0x01)});              EXPECT_THROW(length_decoder(x,bDER),archive::error_eof);
        x = std::vector<uint8_t>({0x80+0x02,0x01});         EXPECT_THROW(length_decoder(x,bDER),archive::error_eof);

        x = std::vector<uint8_t>({0x81,0xde});              EXPECT_EQ(0xde,length_decoder(x,bDER));
        x = std::vector<uint8_t>({0x82,0xde,0x0f});         EXPECT_EQ(0xde0f,length_decoder(x,bDER));
        x = std::vector<uint8_t>({0x83,0xde,0x0f,0xea});    EXPECT_EQ(0xde0fea,length_decoder(x,bDER));
        x = std::vector<uint8_t>({0x83,0xde,0x00,0xea});    EXPECT_EQ(0xde00ea,length_decoder(x,bDER));
        x = std::vector<uint8_t>({0x83,0xde,0xea,0x00});    EXPECT_EQ(0xdeea00,length_decoder(x,bDER));
        x = std::vector<uint8_t>({0x84,0xde,0xea,0xbe,0xef});    EXPECT_EQ(0xdeeabeef,length_decoder(x,bDER));
    }

    // Check long form valid BER, but invalid DER encodings
    x = std::vector<uint8_t>({0x82,0x00,0xff}); EXPECT_EQ(0xff,length_decoder(x,false)); EXPECT_THROW(length_decoder(x,true),ber_decoding_error);
    x = std::vector<uint8_t>({0x82,0x00,0x80}); EXPECT_EQ(0x80,length_decoder(x,false)); EXPECT_THROW(length_decoder(x,true),ber_decoding_error);
    x = std::vector<uint8_t>({0x83,0x00,0x00,0x01}); EXPECT_EQ(0x01,length_decoder(x,false)); EXPECT_THROW(length_decoder(x,true),ber_decoding_error);
    x = std::vector<uint8_t>({0x83,0x00,0x02,0x00}); EXPECT_EQ(0x0200,length_decoder(x,false)); EXPECT_THROW(length_decoder(x,true),ber_decoding_error);

    x = std::vector<uint8_t>({0x85,0x00,0x00,0x00,0x00,0x00}); EXPECT_EQ(0x0,length_decoder(x,false));
    x = std::vector<uint8_t>({0x85,0x01,0x00,0x00,0x00,0x00}); EXPECT_THROW(length_decoder(x,false),ber_decoding_error);
}

bool bool_contents_decoder(uint8_t c, bool const bDER)
{
    iarchive ar(&c,1);
    bool ans;
    asn1::asn1_content<asn1::Tags::BOOLEAN, bool>(ar, ans, NULL, bDER);
    return ans;
}

TEST(asn1_test, bool_contents_test)
{
    EXPECT_EQ(false, bool_contents_decoder(0x00, true));
    EXPECT_EQ(false, bool_contents_decoder(0x00, false));
    EXPECT_EQ(true,  bool_contents_decoder(0xff, true));
    EXPECT_EQ(true,  bool_contents_decoder(0xff, false));
    EXPECT_THROW(bool_contents_decoder(0x2a, true), asn1::ber_decoding_error);
    EXPECT_EQ(true,  bool_contents_decoder(0x2a, false));
}

template<asn1::Tags::type code>
void string_test_helper(
    asn1::TagType<code> const&,
    std::vector<uint8_t> const& bytes,
    std::string comparison,
    bool bExcept
)
{
    iarchive ar(&bytes[0], bytes.size());
    std::string ans("foobar");
    if (bExcept)
    {
        EXPECT_THROW((asn1::asn1_content<code, std::string>(ar, ans, NULL, true)), asn1::ber_decoding_error);
    }
    else
    {
        asn1::asn1_content<code, std::string>(ar, ans, NULL, true);
        EXPECT_EQ(comparison, ans);
    }
}
TEST(asn1_test, string_contents_test)
{
    string_test_helper(asn1::VISIBLE_STRING, {'a','b','c','d','e','f'}, "abcdef", false);
    string_test_helper(asn1::VISIBLE_STRING, {'a','b','c','\0','e','f'}, std::string("abc\0ef",6), false);
    string_test_helper(asn1::VISIBLE_STRING, {'a','b','c',(uint8_t)0x80,'e','f'}, "abc", true);

    string_test_helper(asn1::PRINTABLE_STRING,
            {'a','A','z','Z',' ','\'', '(', ')', '+', ',','-','.','/',':','=','?'},
            "aAzZ \'()+,-./:=?", false);

    string_test_helper(asn1::PRINTABLE_STRING,{'*'},"", true);
    string_test_helper(asn1::PRINTABLE_STRING,{'%'},"", true);
}

std::ostream& operator<<(std::ostream & os, Time const& time)
{
    os << time.to_string();
    return os;
}
template<asn1::Tags::type code>
void time_test_helper(asn1::TagType<code> const&, std::string const& input, asn1::Time const& output)
{
    std::vector<uint8_t> bytes(input.begin(), input.end());
    iarchive ar(&bytes[0], bytes.size());

    asn1::Time output2;
    asn1::asn1_content<code, asn1::Time>(ar, output2, NULL, true);

    EXPECT_EQ(output, output2);
}

template<asn1::Tags::type code>
void time_test_helper2(asn1::TagType<code> const&, std::string const& input)
{
    std::vector<uint8_t> bytes(input.begin(), input.end());
    iarchive ar(&bytes[0], bytes.size());

    asn1::Time output2;
    EXPECT_THROW((asn1::asn1_content<code, asn1::Time>(ar, output2, NULL, true)), asn1::ber_decoding_error);
}

TEST(asn1_test, time_test)
{
    // RFC 2459 4.1.2.5.1 , how to deal with years before and after 2000
    time_test_helper(UTC_TIME, "950523211905Z", Time(1995,05,23,21,19,5));
    time_test_helper(UTC_TIME, "500523211922Z", Time(1950,05,23,21,19,22));
    time_test_helper(UTC_TIME, "490523211950Z", Time(2049,05,23,21,19,50));
    time_test_helper(UTC_TIME, "000523211935Z", Time(2000,05,23,21,19,35));

    // make sure we can't pass in negative numbers
    time_test_helper2(UTC_TIME, "-10523211900Z");
    time_test_helper2(UTC_TIME, "95-123211900Z");
    time_test_helper2(UTC_TIME, "9505-1211900Z");
    time_test_helper2(UTC_TIME, "950523-11900Z");
    time_test_helper2(UTC_TIME, "95052321-100Z");
    time_test_helper2(UTC_TIME, "9505232119-1Z");

    // Can omit the seconds
    time_test_helper(UTC_TIME, "5005232119Z", Time(1950,05,23,21,19,00));

    // can't omit anything else
    time_test_helper2(UTC_TIME, "50052321Z");

    // sanity chcks
    time_test_helper2(UTC_TIME, "950732211905Z");
    time_test_helper2(UTC_TIME, "950700211905Z");
    time_test_helper2(UTC_TIME, "951323211905Z");
    time_test_helper2(UTC_TIME, "950023211905Z");
    time_test_helper2(UTC_TIME, "950823241905Z");
    time_test_helper2(UTC_TIME, "950823216005Z");
    time_test_helper2(UTC_TIME, "950823212360Z");
    time_test_helper2(UTC_TIME, "950523211905");
}

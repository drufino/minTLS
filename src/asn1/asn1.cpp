/* Functionality related to ASN.1 Parsing
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#define asn1_inline
#include "asn1/asn1.hpp"
#include <cstdlib>
#include <sstream>
#include <fstream>
#include "core/tf_debug.hpp"

namespace asn1
{
    DEFINE_NEW_TAG_TYPE(BOOLEAN);
    DEFINE_NEW_TAG_TYPE(INTEGER);
    DEFINE_NEW_TAG_TYPE(PRINTABLE_STRING);
    DEFINE_NEW_TAG_TYPE(VISIBLE_STRING);
    DEFINE_NEW_TAG_TYPE(UTF8_STRING);
    DEFINE_NEW_TAG_TYPE(IA5_STRING);
    DEFINE_NEW_TAG_TYPE(BMP_STRING);
    DEFINE_NEW_TAG_TYPE(BIT_STRING);
    DEFINE_NEW_TAG_TYPE(T61_STRING);
    DEFINE_NEW_TAG_TYPE(OCTET_STRING);
    DEFINE_NEW_TAG_TYPE(SEQUENCE);
    DEFINE_NEW_TAG_TYPE(OBJECT_ID);
    DEFINE_NEW_TAG_TYPE(UTC_TIME);
    DEFINE_NEW_TAG_TYPE(GENERALIZED_TIME);

    ber_decoding_error::ber_decoding_error(const char *ctx, std::string const& error)
    {
        std::ostringstream oss;
        if (ctx != NULL)
        {
            oss << ctx << ": ";
        }
        oss << error;

        m_error = oss.str();
    }

    const char *
    ber_decoding_error::what() const throw()
    {
        return m_error.c_str();
    }

    ber_decoding_error::~ber_decoding_error() throw()
    {
    }

    const char *
    Tags::str_of_code(Tags::type code)
    {
        switch  (code)
        {
        case EOC:           return "SET";
        case BOOLEAN:       return "BOOLEAN";
        case INTEGER:       return "INTEGER";
        case BIT_STRING:    return "BITSTRING";
        case OCTET_STRING:  return "OCTET_STRING";
        case NULL_TAG:      return "NULL";
        case OBJECT_ID:     return "OID";
        case ENUMERATED:    return "ENUMERATED";
        case SEQUENCE:      return "SEQUENCE";
        case SET:           return "SET";
        case UTF8_STRING:   return "UTF8_STRING";
        case NUMERIC_STRING:    return "NUMERIC_STRING";
        case PRINTABLE_STRING:  return "PRINTABLE_STRING";
        case T61_STRING:    return "T61_STRING";
        case IA5_STRING:    return "IA5_STRING";
        case VISIBLE_STRING:return "VISIBLE_STRING";
        case BMP_STRING:    return "BMP_STRING";

        case UTC_TIME:      return "UTC_TIME";
        case GENERALIZED_TIME:  return "GENERALIZED_TIME";
        default: return "UNKNOWN";
        }
    }

    Tag decode_tag(iarchive& ar, const char *ctx)
    {
        if (ar.left() == 0)
        {
            BER_THROW(ctx, "EOF error decoding tag");
        }
        uint8_t b;
        ar & b;

        if ((b & 0x1F) != 0x1F)
        {
            return Tag(Classes::type(b&0xe0), Tags::type(b&0x1f));
        }
        else
        {
            // [5] 8.1.2.4
            TagClass class_(Classes::type(b&0xe0));
            unsigned int number(0);
            do {
                if (ar.left() == 0)
                {
                    BER_THROW(ctx, "EOF error decoding tag");
                }
                ar & b;
                // XXX check integer overflow;
                number <<= 7;
                number |= (b&0x7f);
            } while (b & 0x80);

            if (number <= 30)
            {
                BER_THROW(ctx, "Invalid DER encoding of short-form tag as long-form tag");
            }
            return Tag(class_, Tags::type(number));
        }
    }

    size_t decode_length(iarchive& ar, bool const bDER)
    {
        if (ar.left() == 0)
        {
            BER_THROW(NULL, "EOF error decoding length field");
        }
        uint8_t b;
        ar & b;

        // Short form
        if ((b & 0x80) == 0x00)
        {
            return (size_t)b;
        }
        else
        {
            uint8_t     field_sz = b & 0x7F;

            if (field_sz == 0x7f)
            {
                BER_THROW(NULL, "Invalid length field (X.690 8.1.3.5(c))");
            }
            else if (field_sz == 0x00)
            {
                BER_THROW(NULL, "Indeterminate length not supported. (X.690 8.1.3.6)");
            }

            size_t      length(0);

            for (size_t i = 0; i < field_sz; ++i)
            {
                ar & b;

                // DER encoding should be minimal
                if (bDER && b == 0 && length == 0 && (i+1 != field_sz))
                {
                    BER_THROW(NULL, "Invalid DER encoding of length field (X.690 10.1)");
                }

                if (length & 0xff000000)
                {
                    BER_THROW(NULL, "BER length field overflow");
                }

                length = (length << 8) | b;
            }

            if (bDER && length <= 0x7f)
            {
                BER_THROW(NULL, "Invalid DER encoding of length field (X.690 10.1)");
            }

            return length;
        }
    }

    template<>
    void asn1_content<Tags::BOOLEAN,bool>(iarchive& ar, bool& val, const char *ctx, bool const bDER)
    {
        uint8_t x;

        ar & x;
        if (x != 0)
        {
            // DER restrictions - [5] 11.1
            if (bDER && x != 0xff)
            {
                BER_THROW(ctx, "Invalid DER encoding for boolean (X.690 11.1).");
            }
            val = true;
        }
        else
        {
            val = false;
        }
    }

    // [5] 8.3
    template<>
    void asn1_content<Tags::INTEGER, int>(iarchive& ar, int& val, const char *ctx, bool const bDER)
    {
        uint8_t x;

        ar & x;
        bool const bNegative = (x & 0x80) != 0x0;

        if (bNegative) x = ~x;
        val = x & 0x7f;

        while (ar.left() > 0)
        {
            ar & x; if (bNegative) x = ~x;

            if (val == 0 && ((x&0x80) == 0))
            {
                BER_THROW(ctx,"Invalid integer encoding (X.690 8.3.2 b))");
            }
            if (val & 0xff000000)
            {
                BER_THROW(ctx,"Integer overflow");
            }
            val = (val << 8) | x;
        }
        if (bNegative)
        {
            val = -(val+1);
        }
    }

    template<> void asn1_content<Tags::INTEGER,BigInt>(iarchive& ar, BigInt& val, const char *ctx, bool const bDER)
    {
        uint8_t x;

        ar & x;
        bool const bNegative = (x & 0x80) != 0x0;

        if (bNegative) x = ~x;

        val = BigInt(x & 0x7F);

        while (ar.left() > 0)
        {
            ar & x;
            if (val == BigInt() && ((x&0x80) == 0))
            {
                BER_THROW(ctx,"Invalid integer encoding (X.690 8.3.2 b))");
            }
            if (bNegative)
            {
                x = ~x;
            }
            val = (val << 8) + BigInt(x);
        }

        if (bNegative)
        {
            val = val + BigInt(1);
            val = -val;
        }
    }

    template<> void asn1_content<Tags::INTEGER,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& val, const char *ctx, bool const bDER)
    {
        ar.raw(val);
    }

    // [4] 37.4
    bool
    is_printable(uint8_t c)
    {
        if (c >= 'A' && c <= 'Z') return true;
        if (c >= 'a' && c <= 'z') return true;
        if (c >= '0' && c <= '9') return true;
        switch (c)
        {
        case ' ': case '\'': case '(': case ')':
        case '+': case ',': case '-': case '.':
        case '/': case ':': case '=': case '?': return true;
        default: return false;
        }
    }

    bool
    is_printable(std::string const& s)
    {
        for (size_t i = 0; i < s.length(); ++i)
        {
            if (!is_printable(s[i])) return false;
        }
        return true;
    }

    ////////////////////////////////////////////
    //
    // Unicode string handling
    //
    // [4] http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf (Sec. 37)
    // [9] http://en.wikipedia.org/wiki/Universal_Character_Set
    // [10] http://standards.iso.org/ittf/PubliclyAvailableStandards/c056921_ISO_IEC_10646_2012.zip

    // BMP_STRING corresponds to UCS-2 encoding
    template<>
    void asn1_content<Tags::BMP_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);

        // Convert from UCS-2 to ISO 8859-1
        if (bytes.size() % 2 != 0)
        {
            BER_THROW(ctx, "UCS-2 string must have an even number of bytes");
        }

        x = "";
        for (size_t i = 0; i < bytes.size(); i += 2)
        {
            if (bytes[i] != 0)
            {
                BER_THROW(ctx, "UCS-2 string has non-LATIN1 characters");
            }

            x += static_cast<char>(bytes[i+1]);
        }
    }

    template<>
    void asn1_content<Tags::UTF8_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        UTF8String utf8_x;
        asn1_content<Tags::UTF8_STRING,UTF8String>(ar, utf8_x, ctx, bDER);
        x = utf8_x.pretty_print();
    }

    template<>
    void asn1_content<Tags::PRINTABLE_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (!is_printable(bytes[i]))
            {
                BER_THROW_LONG(ctx, "PrintableString had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x.assign(bytes.begin(), bytes.end());
    }

    template<>
    void asn1_content<Tags::VISIBLE_STRING, std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] & 0x80)
            {
                BER_THROW_LONG(ctx, "VisibleString had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x.assign(bytes.begin(), bytes.end());
    }

    template<>
    void asn1_content<Tags::IA5_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] == 0x0 || (bytes[i] & 0x80))
            {
                BER_THROW_LONG(ctx, "IA5_STRING had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x.assign(bytes.begin(), bytes.end());
    }

    template<>
    void asn1_content<Tags::T61_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] == 0x0 || (bytes[i] & 0x80))
            {
                BER_THROW_LONG(ctx, "T61_STRING had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x.assign(bytes.begin(), bytes.end());
    }

    // Convert UCS-2 to UTF-8
    void ucs2_to_utf8(uint16_t const ucs2, UTF8String& str, const char *ctx)
    {
        if (ucs2 < 0x80)
        {
            str += (uint8_t)(ucs2&0xff);
        }
        else if (ucs2 >= 0x80 && ucs2 < 0x800)
        {
            str += (ucs2 >> 6) | 0xC0;
            str += (ucs2 & 0x3F) | 0x80;
        }
        else
        {
            if (ucs2 >= 0xD800 && ucs2 <= 0xDFFF)
            {
                BER_THROW_LONG(ctx, "Invalid UCS-2 encoding");
            }
            str += ((ucs2 >> 12)) | 0xE0;
            str += ((ucs2 >> 6) & 0x3F) | 0x80;
            str += ((ucs2 >> 0) & 0x3F) | 0x80;
        }
    }

    template<> void asn1_content<Tags::BMP_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        if (bytes.size() & 0x1)
        {
            BER_THROW_LONG(ctx, "Invalid UCS-2 encoding");
        }

        // Initialize string
        x = UTF8String();
        for (unsigned i = 0; i < bytes.size(); i += 2)
        {
            uint16_t ucs2 = (uint16_t(bytes[i]) << 8) | bytes[i+1];
            ucs2_to_utf8(ucs2, x, ctx);
        }
    }

    template<> void asn1_content<Tags::UTF8_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> utf8; ar.raw(utf8);
        x = UTF8String(utf8);
    }

    template<> void asn1_content<Tags::PRINTABLE_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (!is_printable(bytes[i]))
            {
                BER_THROW_LONG(ctx, "PrintableString had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x = UTF8String(bytes);
    }

    template<> void asn1_content<Tags::VISIBLE_STRING, UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] & 0x80)
            {
                BER_THROW_LONG(ctx, "VisibleString had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x = UTF8String(bytes);
    }

    template<> void asn1_content<Tags::IA5_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] == 0x0 || (bytes[i] & 0x80))
            {
                BER_THROW_LONG(ctx, "IA5_STRING had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x = UTF8String(bytes);
    }

    template<> void asn1_content<Tags::T61_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> bytes; ar.raw(bytes);
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (bytes[i] == 0x0 || (bytes[i] & 0x80))
            {
                BER_THROW_LONG(ctx, "T61_STRING had invalid character (" << std::hex << int(bytes[i]) << ")");
            }
        }
        x = UTF8String(bytes);
    }

    template<>
    void asn1_content<Tags::BIT_STRING,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& bytes, const char *ctx, bool const bDER)
    {
        uint8_t bit_padding; ar & bit_padding;
        if (bit_padding != 0x0)
        {
            BER_THROW_LONG(ctx, "BITSTRING non-zero padding "  << std::hex << (int) bit_padding);
        }
        ar.raw(bytes);
    }

    template<>
    void asn1_content<Tags::BIT_STRING,int>(iarchive& ar, int& bits, const char *ctx, bool const bDER)
    {
        uint8_t bit_padding;        ar & bit_padding;

        if (bit_padding > 7)
        {
            BER_THROW(ctx, "BITSTRING padding too large");
        }

        std::vector<uint8_t> bytes; ar.raw(bytes);

        if (bytes.size() > 3)
        {
            BER_THROW(ctx, "BITSTRING too large to fit in an integer");
        }
        if (bytes.size() == 0)
        {
            BER_THROW(ctx, "BITSTRING unexpectedly empty");
        }

        bits = 0;
        for (unsigned i = 0; i < bytes.size(); ++i)
        {
            uint8_t octet = bytes[i];

            // Check padded with zeros
            if (i+1 == bytes.size())
            {
                uint8_t mask = (bit_padding > 0) ? (1<<bit_padding)-1 : 0;
                if (bDER && (octet & mask) != 0)
                {
                    BER_THROW(ctx, "BITSTRING non-zero padding in DER mode");
                }

                octet &= ~mask;
            }

            // Rotate the bits
            octet = (octet * 0x0202020202ULL & 0x010884422010ULL) % 1023;
            bits |= ((int)octet) << (i*8);
        }
    }

    template<>
    void asn1_content<Tags::OCTET_STRING,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& bytes, const char *ctx, bool const bDER)
    {
        ar.raw(bytes);
    }
}

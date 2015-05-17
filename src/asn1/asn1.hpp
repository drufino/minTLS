/* Functionality related to ASN.1 Parsing
 * 
 * Useful references
 *   [4] http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *   [5] http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *   [6] http://msdn.microsoft.com/en-us/library/dd408078(v=vs.85).aspx
 *   [7] http://luca.ntop.org/Teaching/Appunti/asn1.html
 *   [8] http://www.oss.com/asn1/resources/books-whitepapers-pubs/dubuisson-asn1-book.PDF
 *   [9] http://en.wikipedia.org/wiki/Basic_Encoding_Rules#BER_encoding
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#ifndef tf_asn1_hpp
#define tf_asn1_hpp
#include "core/archive.hpp"
#include "core/bigint.hpp"
#include "core/safe_enum.hpp"
#include "core/UTF8String.hpp"
#include <string>
#include <set>
#include <sstream>

#ifndef asn1_inline
#define asn1_inline __inline__
#endif

#define BER_THROW(ctx, x)                                   \
{                                                           \
    throw asn1::ber_decoding_error(ctx,x);                  \
}

#define BER_THROW_LONG(ctx, x)                              \
{                                                           \
    std::ostringstream oss;                                 \
    oss << __FILE__ << ": " << __LINE__ << ": ";            \
    oss << std::hex << x; throw asn1::ber_decoding_error(ctx, oss.str()); \
}

namespace asn1
{

struct ber_decoding_error : public std::exception
{
public:
    // Constructor
    ber_decoding_error(const char *ctx, std::string const& error);

    // Error message
    virtual const char* what() const throw();

    // Destructor
    virtual ~ber_decoding_error() throw();

private:
    std::string m_error;
};

struct Classes
{
    enum type {
        UNIVERSAL       = 0x00,
        APPLICATION     = 0x40,
        CONTEXT_SPECIFIC= 0x80,
        CONSTRUCTED     = 0x20,
        PRIVATE         = CONSTRUCTED | CONTEXT_SPECIFIC
    };
};

struct Tags
{
/**
* ASN.1 Type and Class Tags
*/
enum type {
    EOC              = 0x00,
    BOOLEAN          = 0x01,
    INTEGER          = 0x02,
    BIT_STRING       = 0x03,
    OCTET_STRING     = 0x04,
    NULL_TAG         = 0x05,
    OBJECT_ID        = 0x06,
    ENUMERATED       = 0x0A,
    SEQUENCE         = 0x10,
    SET              = 0x11,

    UTF8_STRING      = 0x0C,
    NUMERIC_STRING   = 0x12,
    PRINTABLE_STRING = 0x13,
    T61_STRING       = 0x14,
    IA5_STRING       = 0x16,
    VISIBLE_STRING   = 0x1A,
    BMP_STRING       = 0x1E,

    UTC_TIME         = 0x17,
    GENERALIZED_TIME = 0x18,
};

static const char *str_of_code(type code);

};

typedef safe_enum<Tags>     TagNumber;
typedef safe_enum<Classes>  TagClass;

struct Tag
{
    // Constructor
    Tag(TagNumber const& tag_)
    : class_(Classes::UNIVERSAL),
      number(tag_)
    {}

    // Constructor
    Tag(TagClass const& tag_class_, TagNumber const& tag_)
      : class_(tag_class_),
        number(tag_)
    {}

    // Comparison operator
    bool operator==(Tag const& rhs) const
    {
        return
            class_ == rhs.class_ &&
            number == rhs.number;
    }

    bool operator!=(Tag const& rhs) const
    {
        return !(*this == rhs);
    }

    int hex() const
    {
        if (number.underlying() <= 0x1f)
        {
            return int(class_.underlying())|int(number.underlying());
        }
        else
        {
            return int(number.underlying());
        }
    }

    TagClass    class_;
    TagNumber   number;
};

// For each tag enumeration generate a new type associated to this. This allows overloading for
// each enumeration in the public API.
template<Tags::type code> struct TagType { static const Tags::type val = code; };
#define DECLARE_NEW_TAG_TYPE(x) typedef TagType<Tags::x> x##_; extern x##_ x;
#define DEFINE_NEW_TAG_TYPE(x) x##_ x;
DECLARE_NEW_TAG_TYPE(BOOLEAN);
DECLARE_NEW_TAG_TYPE(INTEGER);
DECLARE_NEW_TAG_TYPE(PRINTABLE_STRING);
DECLARE_NEW_TAG_TYPE(UTF8_STRING);
DECLARE_NEW_TAG_TYPE(IA5_STRING);
DECLARE_NEW_TAG_TYPE(BMP_STRING);
DECLARE_NEW_TAG_TYPE(T61_STRING);
DECLARE_NEW_TAG_TYPE(BIT_STRING);
DECLARE_NEW_TAG_TYPE(OCTET_STRING);
DECLARE_NEW_TAG_TYPE(VISIBLE_STRING);
DECLARE_NEW_TAG_TYPE(SEQUENCE);
DECLARE_NEW_TAG_TYPE(OBJECT_ID);
DECLARE_NEW_TAG_TYPE(UTC_TIME);
DECLARE_NEW_TAG_TYPE(GENERALIZED_TIME);
#undef DECLARE_NEW_TAG_TYPE

// Decode an ASN.1 Identifier
//    BER [5] 8.1.2
//
Tag         decode_tag(iarchive& ar, const char *ctx);

// Decode the length value
//    BER [5] 8.1.3
//    DER [5] 10.1
//
// NB indefinite form not supported, and default to strict DER encoding
size_t      decode_length(iarchive& ar, bool const bDER=true);

///////////////////////
// Content primitives 
//
// Specialize on both the tag type and C++ type, to ensure we the content decoding
// matches up with the ASN.1 semantics.
//
template<Tags::type code,typename T>
void asn1_content(iarchive& ar, T& x, const char *ctx, bool const bDER)
{
    x.no_such_content_primitive_implemented ();
}

// Primitive decoding of BOOLEAN type
template<> void asn1_content<Tags::BOOLEAN,bool>(iarchive& ar, bool& x, const char *ctx, bool const bDER);

// Primitive decoding of INTEGER type [5] 8.3
template<> void asn1_content<Tags::INTEGER,int>(iarchive& ar, int& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::INTEGER,BigInt>(iarchive& ar, BigInt& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::INTEGER,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& val, const char *ctx, bool const bDER);

// Strings
template<> void asn1_content<Tags::BMP_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::UTF8_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::PRINTABLE_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::VISIBLE_STRING, std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::IA5_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::T61_STRING,std::string>(iarchive& ar, std::string& x, const char *ctx, bool const bDER);

template<> void asn1_content<Tags::BMP_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::UTF8_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::PRINTABLE_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::VISIBLE_STRING, UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::IA5_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::T61_STRING,UTF8String>(iarchive& ar, UTF8String& x, const char *ctx, bool const bDER);

template<> void asn1_content<Tags::BIT_STRING,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::OCTET_STRING,std::vector<uint8_t> >(iarchive& ar, std::vector<uint8_t>& x, const char *ctx, bool const bDER);
template<> void asn1_content<Tags::BIT_STRING,int>(iarchive& ar, int& bits, const char *ctx, bool const bDER);

} // namespace asn1

#undef asn1_inline

#endif

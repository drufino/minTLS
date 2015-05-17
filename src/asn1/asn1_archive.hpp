/* High-level interface for BER decoding
 *
 * Jump through some C++ hoops in order to generate a simple-ish syntax
 * for ASN.1 BER decoding, similar in spirit to boost::archive
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#ifndef tf_asn1_archive_hpp
#define tf_asn1_archive_hpp
#include "core/archive.hpp"
#include "asn1/asn1.hpp"
#include <string>
#include <set>
#include <core/tf_debug.hpp>
#include <core/utf8string.hpp>
 
#ifndef asn1_inline
#define asn1_inline __inline
#endif

namespace asn1
{
// Forward declarations
class ber_archive;

/////////////////
//
// Interface for BER-decodable objects
//

// Decodes a number of ASN.1 tag/value pairs
class ber_decodable
{
public:
    virtual void ber_decode(ber_archive & ar) = 0;

    virtual void serialize(archive& ar);
};

// Decodes a single constructed sequence, which consists of a number
// of ASN.1 tag/value pairs
class ber_decodable_sequence
{
public:
    virtual void ber_decode(ber_archive & ar) = 0;

    virtual void serialize(archive& ar);
};

// ASN.1 Tagging Mode
enum TaggingMode
{
    Implicit=0,
    Explicit=1
};

// ASN.1 Tag/Value pairs can be required, optional with default, or just optional
enum OptionalType
{
    OptionalRequired=0,     // Required
    OptionalDefault =1,     // Optional, with default supplied. NB DER encoding requires default values are omitted
    OptionalTag=2           // Optional, with no DER restriction
};

////////////////////////////////////////////////////////////////////
//
// BER decoding modifiers used to make the syntax easier
//
// Broadly speaking
//
//     ber_archive & modifier_class -> decoder_class
//     decoder_class & object       -> decodes into object according to modifier, returns 
//
//  1) UNIVERSAL PRIMITIVE tags
//
//      BIT_STRING bits;
//      STRING     string;
//
//      ar & BIT_STRING & bits & STRING & string;
//
//  2) CONSTRUCTED Sequences/Sets
//  
//      SEQUENCE {
//          BIT_STRING   bits;
//          STRING       string;
//      }
//
//      becomes
// 
//      ar & start_cons() & BIT_STRING & bits & STRING & string & end_cons();
//
//  3) Implicit Context Specific Primitives
// 
//     [0] INTEGER my_number;
//
//     ar & implicit(0,INTEGER) & my_number
// 
//  4) Implicit Context Specific Constructed
// 
//     [0] RDN myName;
// 
//      ar & implicit(0) & myName;
//  etc
//
namespace modifiers
{
    // Start a constructed sequence
    struct start_cons_
    {
        start_cons_(Tags::type tag_, const char * ctx_)
        : tag(tag_), ctx(ctx_)
        {}

        Tags::type  tag;
        const char* ctx;
    };

    // Mark the end of a constructed sequence
    struct end_cons_ {};

    // Start a single non-primitive element
    template<TaggingMode mode>
    struct tag_start_
    {
        tag_start_(
            Tag             tag_,
            OptionalType    optional_type_
        ) :
            tag(tag_),
            optional_type(optional_type_)
        {}

        Tag             tag;
        OptionalType    optional_type;
    };

    // Start a single non-primitive element
    template<typename T, TaggingMode mode>
    struct tag_start_default_ : public tag_start_<mode>
    {
        typedef tag_start_<mode> super;

        tag_start_default_(
            Tag             tag_,
            OptionalType    optional_type_,
            T const&        default_value_
        ) :
            super(tag_,optional_type_),
            default_value(default_value_)
        {}

        T               default_value;
    };

    // Start a single primitive element
    template<Tags::type code>
    struct tag_start_primitive_
    {
        tag_start_primitive_(Tag tag_, OptionalType optional_type_)
        : tag(tag_),
          optional_type(optional_type_)
        {}

        Tag             tag;
        OptionalType    optional_type;
    };

    template<typename T, Tags::type code>
    struct tag_start_primitive_default_ : public tag_start_primitive_<code>
    {
        typedef tag_start_primitive_<code> super;

        tag_start_primitive_default_(
            Tag             tag_,
            OptionalType    optional_type_,
            T const&        default_value_
        ) :
            super(tag_, optional_type_),
            default_value(default_value_)
        {}

        T const         default_value;
    };

    struct context_modifier_
    {
        context_modifier_(const char *ctx_) : ctx(ctx_) {}
        const char *ctx;
    };

    struct ignore_modifier_
    {
    };

    struct raw_modifier_
    {
        raw_modifier_(std::vector<uint8_t>& bytes_) : bytes(bytes_) {}

        std::vector<uint8_t>& bytes;
    };
}

//
// Free-standing functions used for decoding into C++ objects
// May delegate to object methods, or be defined separately
//
namespace type_traits
{
    // Primitive means INTEGER, BOOLEAN etc. Constructed otherwise.
    // This determines bit 6 of the tag number (we include it in the class tag)
    bool asn1_inline is_primitive(void *obj) { return false; }

    // Return 0x0 if no enclosing tag required for decoding this object type, otherwise
    // return the required tag
    Tag asn1_inline enclosing_tag(void* obj) { return Tag(Classes::UNIVERSAL, Tags::EOC); }

    // Delegate to object method
    void asn1_inline decode(asn1::ber_archive& ar, asn1::ber_decodable* obj)
    {
        obj->ber_decode(ar);
    }

    // This type of object is a sequence
    Tag asn1_inline enclosing_tag(asn1::ber_decodable_sequence * obj)
    {
        return Tag(Classes::CONSTRUCTED, Tags::SEQUENCE);
    }

    // Delegate to the object
    void asn1_inline decode(asn1::ber_archive& ar, asn1::ber_decodable_sequence* obj)
    {
        obj->ber_decode(ar);
    }

    // These are some primitive types which may be decoded without prefixing with tag
    bool asn1_inline is_primitive(UTF8String * obj) { return true; }
    bool asn1_inline is_primitive(std::string * obj) { return true; }
    bool asn1_inline is_primitive(int * obj) { return true; }
    bool asn1_inline is_primitive(BigInt * obj) { return true; }

    Tag asn1_inline enclosing_tag(UTF8String * obj) { return Tag(Classes::UNIVERSAL, Tags::EOC); }
    Tag asn1_inline enclosing_tag(std::string * obj) { return Tag(Classes::UNIVERSAL, Tags::EOC); }
    Tag asn1_inline enclosing_tag(int * obj) { return Tag(Classes::UNIVERSAL, Tags::INTEGER); }
    Tag asn1_inline enclosing_tag(BigInt * obj) { return Tag(Classes::UNIVERSAL, Tags::INTEGER); }

    void decode(asn1::ber_archive& ar, UTF8String * obj);
    void decode(asn1::ber_archive& ar, std::string * obj);
    void decode(asn1::ber_archive& ar, int *x);
    void decode(asn1::ber_archive& ar, BigInt *x);
}

/////
//
// Primitive modifiers
//

template<Tags::type code, typename T>
modifiers::tag_start_primitive_default_<T, code> default_(TagType<code> const&, T const& default_value)
{
    return
    modifiers::tag_start_primitive_default_<T, code>(
        Tag(Classes::UNIVERSAL, code),
        OptionalDefault,
        default_value
    );
}


template<Tags::type code>
modifiers::tag_start_primitive_<code> optional(TagType<code> const&)
{
    return
    modifiers::tag_start_primitive_<code>(
        Tag(Classes::UNIVERSAL, code),
        OptionalTag
    );
}

template<Tags::type code>
modifiers::tag_start_primitive_<code> optional_implicit(int tag, TagType<code> const&)
{
    return modifiers::tag_start_primitive_<code>(
        Tag(Classes::CONTEXT_SPECIFIC, Tags::type(tag)),
        OptionalTag
    );
}

template<Tags::type code, typename T>
modifiers::tag_start_primitive_default_<T, code> optional_implicit(int tag, TagType<code> const&, T const& default_value)
{
    return modifiers::tag_start_primitive_default_<T, code>(
        Tag(Classes::UNIVERSAL, Tags::type(tag)),
        OptionalTag,
        default_value
    );
}

template<Tags::type code>
modifiers::tag_start_primitive_<code> implicit(int tag, TagType<code> const&)
{
    return modifiers::tag_start_primitive_<code>(
        Tag(Classes::CONTEXT_SPECIFIC, Tags::type(tag)),
        OptionalRequired
    );
}

asn1_inline modifiers::raw_modifier_ raw(std::vector<uint8_t>& bytes)
{
    return modifiers::raw_modifier_(bytes);
}

/////
//
//  Non-Primitive modifiers
//

modifiers::tag_start_<Implicit> asn1_inline optional_implicit(int tag)
{
    return
    modifiers::tag_start_<Implicit>(
        Tag(Classes::CONTEXT_SPECIFIC, Tags::type(tag)),
        OptionalTag
    );
}


modifiers::tag_start_<Implicit> asn1_inline implicit(int tag)
{
    return
    modifiers::tag_start_<Implicit>(
        Tag(Classes::CONTEXT_SPECIFIC, Tags::type(tag)),
        OptionalRequired
    );
}

modifiers::tag_start_<Explicit> asn1_inline optional_explicit(int tag)
{
    return
    modifiers::tag_start_<Explicit>(
        Tag(Classes::PRIVATE, Tags::type(tag)),
        OptionalTag
    );
}

template<typename T>
modifiers::tag_start_default_<T, Explicit> optional_explicit(int tag, T const& default_value)
{
    return
    modifiers::tag_start_default_<T, Explicit>(
        Tag(Classes::PRIVATE, Tags::type(tag)),
        OptionalTag,
        default_value
    );
}



const modifiers::start_cons_  asn1_inline
start_cons(const char *ctx)
{
    return modifiers::start_cons_(Tags::SEQUENCE, ctx);
}

const modifiers::start_cons_ asn1_inline
start_cons(Tags::type tag=Tags::SEQUENCE, const char *ctx=NULL)
{
    return modifiers::start_cons_(tag, ctx);
}

const modifiers::end_cons_ asn1_inline
end_cons()
{
    return modifiers::end_cons_();
}

const modifiers::context_modifier_ asn1_inline
dbg(const char *ctx)
{
    return modifiers::context_modifier_(ctx);
}

const modifiers::ignore_modifier_ asn1_inline&
ignore_the_rest()
{
    static modifiers::ignore_modifier_ s_modifier;
    return s_modifier;
}

// Decoder for the BER encoding scheme
class ber_archive
{
public:
    ber_archive(iarchive & ar_, const char *ctx, bool bDER=true);

    ber_archive&        start_tag(Tag expected_tag, const char *ctx="");

    // Mark the end
    ber_archive&        end_tag();

    template<typename T, Tags::type code>
    static void primitive_decode(
        ber_archive&    ar,                 // (I) BER archive
        T&              rhs,                // (O) Object to decde into
        Tag             expected_tag,       // (I) The expected tag
        OptionalType    optional_type,      // (I) The behaviour if we don't see the expected tag
        T const*        default_value = 0   // (I) The possible default value
    )
    {
        if (ar.empty())
        {
            if (optional_type == OptionalRequired)
            {
                BER_THROW_LONG(ar.get_ctx(), "Expected tag " << std::hex << expected_tag.hex() << " got EOF");
            }
            else if (default_value != 0)
            {
                rhs = *default_value;
                // XXX check the DER restriction
            }
            else
            {
                rhs = T();
            }
        }
        else
        {
            Tag this_tag = ar.peek_tag();
            //tf_dbg("Got tag " << std::hex << this_tag.hex() << " expected " << expected_tag.hex());
            if (this_tag == expected_tag)
            {
                this_tag = decode_tag(ar.m_ar,ar.get_ctx());
                ar.start_contents(ar.get_ctx());
                asn1_content<code, T>(ar.m_ar, rhs, ar.get_ctx(), ar.bDER());
                ar.end_contents();
            }
            else
            {
                if (optional_type == OptionalRequired)
                {
                    BER_THROW_LONG(ar.get_ctx(), "Expected tag " << std::hex << expected_tag.hex() << " got " << this_tag.hex());
                }
                else
                {
                    if (default_value != 0)
                    {
                        rhs = *default_value;
                        if (optional_type == OptionalDefault)
                        {
                            // XXX do the DER check
                        }
                    }
                    else
                    {
                        rhs = T();
                    }
                }
            }
        }
    }

    template<Tags::type code>
    class primitive_decoder
    {
    public:
        primitive_decoder(
            ber_archive&    ar_,
            Tag const&      expected_tag_,
            OptionalType    optional_type_
        ) :
        ar(ar_),
        expected_tag(expected_tag_),
        optional_type(optional_type_)
        {}

        template<typename T>
        ber_archive& operator&(T& rhs) const
        {
            primitive_decode<T, code>(ar, rhs, expected_tag, optional_type);
            return ar;
        }

    protected:
        ber_archive&        ar;
        Tag                 expected_tag;
        OptionalType        optional_type;
    };

    template<Tags::type code, typename T>
    class primitive_decoder_default : protected primitive_decoder<code>
    {
    public:
        typedef primitive_decoder<code> super;

        primitive_decoder_default(
            ber_archive&    parent_,
            Tag const&      tag_,
            OptionalType    optional_type_,
            T const&        default_value_
        ) :
          super(parent_,tag_, optional_type_),
          default_value(default_value_)
        {}

        ber_archive& operator&(T& rhs) const
        {
            primitive_decode<T, code>(super::ar, rhs, super::expected_tag, super::optional_type, &default_value);
            return super::ar;
        }

    protected:
        T                   default_value;
    };

    // Find out what the next tag is, but don't lose it
    Tag                 peek_tag();

    // Get the remaining bytes in the sequence
    void                raw_bytes(std::vector<uint8_t>& bytes);

    // Check if there's any data left
    bool                empty() const;

    // Check if we're using DER decoding
    bool                bDER() const;

    // Find out what the current context is
    const char *        get_ctx() const;
    void                set_ctx(const char *ctx);

    iarchive&           ar() { return m_ar; }
    iarchive const&     ar() const { return m_ar; }

    // Destructor
    ~ber_archive();

    size_t  start_contents(const char *ctx);
    void    end_contents();

private:
    iarchive &                  m_ar;
    bool                        m_bDER;
    const char *                m_local_ctx;
    std::vector<const char *>   m_ctx;
    std::vector<size_t>         m_save_sz;
};

namespace type_traits 
{
    // Treat C++ arrays as a 'SEQUENCE of'
    template<typename T>
    Tag enclosing_tag(std::vector<T> * obj = 0)
    {
        return Tag(Classes::CONSTRUCTED, Tags::SEQUENCE);
    }

    // Decode the SEQUENCE
    template<typename T>
    void decode(ber_archive& ar, std::vector<T>* elts)
    {
        if (!elts) return;

        while (!ar.empty())
        {
            elts->resize(elts->size()+1);
            ar & elts->back();
        }
    }

    // PAIR
    template<typename T, typename U>
    Tag enclosing_tag(std::pair<T, U> * obj = 0)
    {
        return Tag(Classes::CONSTRUCTED, Tags::SEQUENCE);
    }

    template<typename T, typename U>
    void decode(ber_archive& ar, std::pair<T, U>* elts)
    {
        if (!elts) return;

        ar & elts->first & elts->second;
    }
}

//
// Temporary objects created from an archive which do
// the work of decoding into an object
//
namespace ber_archive_details
{
    template<TaggingMode mode> struct decoder_impl {};

    template<>
    struct decoder_impl<Implicit>
    {
        template<typename T>
        static void decode_inner(ber_archive& ar, T& rhs)
        {
            decode_tag(ar.ar(),ar.get_ctx());
            ar.start_contents(ar.get_ctx());
            type_traits::decode(ar, &rhs);
            ar.end_contents();
        }
    };

    template<>
    struct decoder_impl<Explicit>
    {
        template<typename T>
        static void decode_inner(ber_archive& ar, T& rhs)
        {
            decode_tag(ar.ar(),ar.get_ctx());
            ar.start_contents(ar.get_ctx());
            ar & rhs;
            ar.end_contents();
        }
    };

    template<TaggingMode mode>
    class decoder
    {
    public:
        decoder(
            ber_archive&    ar_,
            Tag             expected_tag_,
            OptionalType    optional_type_
        ) :
        ar(ar_),
        expected_tag(expected_tag_),
        optional_type(optional_type_)
        {}

        template<typename T>
        ber_archive& operator&(T & rhs) const
        {
            if (ar.empty())
            {
                if (optional_type == OptionalRequired)
                {
                    BER_THROW_LONG(ar.get_ctx(), "Expected tag " << std::hex << expected_tag.hex() << " got EOF");
                }
                else
                {
                    rhs = T();
                }
            }
            else
            {
                Tag this_tag = ar.peek_tag();

                // If the type we're decoding into is not primitive, then we must expected bit 6 to be set
                // namely the constructed field
                if (!type_traits::is_primitive((T *)0))
                {
                    expected_tag.class_.val =
                        Classes::type(((int)expected_tag.class_.val) | Classes::CONSTRUCTED);
                }

                //tf_dbg("Got tag " << std::hex << this_tag.hex() << " expected " << expected_tag.hex());

                if (this_tag == expected_tag)
                {
                    decoder_impl<mode>::template decode_inner<T>(ar, rhs);
                }
                else
                {
                    if (optional_type == OptionalRequired)
                    {
                        BER_THROW_LONG(ar.get_ctx(), "Expected tag " << std::hex << expected_tag.hex() << " got " << this_tag.hex());
                    }
                    else
                    {
                        rhs = T();
                    }
                }
            }

            return ar;
        }

    private:
        ber_archive&        ar;
        mutable Tag         expected_tag;
        OptionalType        optional_type;
    };
}



///////
//
// Create the decoder classes from the modifiers
//

template<Tags::type code> ber_archive::primitive_decoder<code>
operator&(ber_archive& ar, modifiers::tag_start_primitive_<code> const& rhs)
{
    return ber_archive::primitive_decoder<code>(ar, rhs.tag, rhs.optional_type);
}

template<typename T, Tags::type code> ber_archive::primitive_decoder_default<code,T>
operator&(ber_archive& ar, modifiers::tag_start_primitive_default_<T, code> const& rhs)
{
    return ber_archive::primitive_decoder_default<code,T>(ar, rhs.tag, rhs.optional_type, rhs.default_value);
}

template<TaggingMode mode> ber_archive_details::decoder<mode>
operator&(ber_archive& ar, modifiers::tag_start_<mode> const& rhs)
{
    return ber_archive_details::decoder<mode>(ar, rhs.tag, rhs.optional_type);
}

// Decode an object using the type
template<typename T>
ber_archive& operator&(ber_archive& ar, T& obj)
{
    Tag enclosing_tag = type_traits::enclosing_tag((T *)0);

    if (enclosing_tag.hex() != 0)
    {
        ar.start_tag(enclosing_tag);
    }

    type_traits::decode(ar, &obj);

    if (enclosing_tag.hex() != 0)
    {
        ar.end_tag();
    }

    return ar;
}

template<> asn1_inline
ber_archive& operator&(ber_archive& ar, modifiers::start_cons_ const& tag)
{
    return ar.start_tag(Tag(Classes::CONSTRUCTED,tag.tag),tag.ctx);
}

template<> asn1_inline
ber_archive& operator&(ber_archive& ar, modifiers::end_cons_ const &)
{
    return ar.end_tag();
}


asn1_inline ber_archive& operator&(ber_archive& ar, modifiers::ignore_modifier_ const& ctx)
{
    std::vector<uint8_t> ignored;
    ar.raw_bytes(ignored);
    return ar;
}

asn1_inline ber_archive& operator&(ber_archive& ar, modifiers::context_modifier_ const& ctx)
{
    ar.set_ctx(ctx.ctx);
    return ar;
}

asn1_inline ber_archive& operator&(ber_archive& ar, modifiers::raw_modifier_ const& raw)
{
    // Read the sequence, to figure out the size
    size_t raw_sz(0);
    {
        iarchive ar_tmp(ar.ar());
        ber_archive ar_tmp2(ar_tmp, ar.get_ctx(), ar.bDER());

        ar_tmp2 & start_cons() & ignore_the_rest() & end_cons();
        raw_sz = ar.ar().left() - ar_tmp.left();
    }

    // Read the bytes directly
    raw.bytes.resize(raw_sz);
    ar.ar().read_impl(&raw.bytes[0], raw_sz);

    return ar;
}

template<Tags::type tag>
asn1_inline ber_archive::primitive_decoder<tag> operator&(ber_archive& ar, TagType<tag>)
{
    return ber_archive::primitive_decoder<tag>(ar, Tag(Classes::UNIVERSAL, tag), OptionalRequired);
}

template<typename T>
asn1_inline void ber_decode(std::vector<uint8_t> const& bytes, T& obj, bool const bDER=true)
{
    iarchive ar(&bytes[0], bytes.size());
    ber_archive ber_ar(ar, NULL, bDER);
    ber_ar & obj;
    if (ar.left() > 0)
    {
        BER_THROW_LONG(NULL, "Unexpectedly had 0x" << std::hex << ar.left() << " bytes left over");
    }
}

}

#undef asn1_inline

#endif

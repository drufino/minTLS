/* High-level interface for BER decoding
 *
 * Jump through some C++ hoops in order to generate a simple-ish syntax
 * for ASN.1 BER decoding, similar in spirit to boost::archive
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#define asn1_inline
#include "asn1/asn1.hpp"
#include "asn1/asn1_archive.hpp"
#include <cstdlib>
#include <sstream>
#include <fstream>

namespace asn1
{
    void
    ber_decodable::serialize(archive& ar)
    {
        if (ar.is_reading())
        {
            iarchive& ar_ = dynamic_cast<iarchive&>(ar);
            uint24_t len; ar_ & len;
            iarchive opaque = ar_.opaque((size_t)len);
            std::string ctx(typeid(*this).name());
            {
                ber_archive ber(opaque, ctx.c_str());
                ber_decode(ber);
            }
        }
        else
        {
            BER_THROW(NULL,"BER writing not implemented");
        }
    }

    void
    ber_decodable_sequence::serialize(archive& ar)
    {
        if (ar.is_reading())
        {
            iarchive& ar_ = dynamic_cast<iarchive&>(ar);
            uint24_t len; ar_ & len;
            iarchive opaque = ar_.opaque((size_t)len);
            std::string ctx(typeid(*this).name());
            {
                ber_archive ber(opaque, ctx.c_str());
                ber & start_cons();
                this->ber_decode(ber);
                ber & end_cons();
            }
        }
        else
        {
            BER_THROW(NULL,"BER writing not implemented");
        }
    }

    ber_archive::ber_archive(iarchive & ar_, const char *ctx, bool bDER) :
      m_ar(ar_),
      m_bDER(bDER),
      m_local_ctx(NULL)
    {
        m_ctx.push_back(ctx);
    }

    size_t
    ber_archive::start_contents(const char *ctx)
    {
        size_t length = decode_length(m_ar);
        if (length > m_ar.left())
        {
            BER_THROW(get_ctx(),"start_cons() ran out of space")
        }

        // Temporarily reduce the size of the archive to stop overruns
        m_ctx.push_back(ctx);
        m_local_ctx = NULL;
        m_save_sz.push_back(m_ar.m_sz);
        m_ar.m_sz = m_ar.m_consumed + length;
        return length;
    }

    const char *
    ber_archive::get_ctx() const
    {
        if (m_local_ctx != NULL)
        {
            return m_local_ctx;
        }
        else if (m_ctx.size() > 0)
        {
            return m_ctx.back();
        }
        else
        {
            return "NoContext";
        }
    }

    void
    ber_archive::set_ctx(const char *ctx)
    {
        //if (ctx) tf_dbg("ctx " << ctx);
        m_local_ctx = ctx;
    }

    void
    ber_archive::end_contents()
    {
        if (m_save_sz.size() == 0)
        {
            BER_THROW(get_ctx(),"Unexpected end_cons()");
        }
        else
        {
            if (m_ar.left() > 0)
            {
                BER_THROW_LONG(get_ctx(),"Unexpected 0x" << std::hex << m_ar.left() << " bytes left in asn.1 decode ");
            }
            // Restore the size of the archive
            m_ar.m_sz = m_save_sz.back();
            m_save_sz.resize(m_save_sz.size()-1);

            // Restore Context
            if (m_ctx.size() > 0)
                m_ctx.resize(m_ctx.size()-1);
            m_local_ctx = NULL;
        }
    }

    ber_archive&
    ber_archive::start_tag(Tag expected_tag, const char *ctx)
    {
        //if (ctx) tf_dbg("" << ctx); 

        Tag this_tag      = decode_tag(m_ar, ctx);
        if (this_tag != expected_tag)
        {
            BER_THROW_LONG(ctx,"Expected tag 0x" << std::hex << expected_tag.hex() << " but got tag " << this_tag.hex());
        }

        start_contents(ctx);

        return *this;
    }

    ber_archive&
    ber_archive::end_tag()
    {
        end_contents();
        return *this;
    }

    ber_archive::~ber_archive()
    {
        // Restore some sanity
        if (m_save_sz.size() > 0)
        {
            m_ar.m_sz = m_save_sz[0];
        }
    }

    Tag
    ber_archive::peek_tag()
    {
        iarchive tmp_ar(m_ar);
        return decode_tag(tmp_ar, get_ctx());
    }

    bool
    ber_archive::empty() const
    {
        return m_ar.left() == 0;
    }

    void
    ber_archive::raw_bytes(std::vector<uint8_t>& bytes)
    {
        size_t sz = m_ar.left();
        bytes.resize(sz);
        m_ar.read_impl(&bytes[0], sz);
    }

    bool
    ber_archive::bDER() const
    {
        return m_bDER;
    }


    namespace type_traits
    {
        void decode(ber_archive& ar, int* x)
        {
            asn1_content<Tags::INTEGER,int>(ar.ar(), *x, ar.get_ctx(), ar.bDER());
        }

        void decode(ber_archive& ar, BigInt* x)
        {
            asn1_content<Tags::INTEGER,BigInt>(ar.ar(), *x, ar.get_ctx(), ar.bDER());
        }

        void decode(ber_archive& ar, UTF8String * x)
        {
            switch (ar.peek_tag().number.underlying())
            {
            case Tags::PRINTABLE_STRING:
                ar & PRINTABLE_STRING & *x;
                break;
            case Tags::UTF8_STRING:
                ar & UTF8_STRING & *x;
                break;
            case Tags::BMP_STRING:
                ar & BMP_STRING & *x;
                break;
            case Tags::IA5_STRING:
                ar & IA5_STRING & *x;
                break;
            case Tags::VISIBLE_STRING:
                ar & VISIBLE_STRING & *x;
                break;
            case Tags::T61_STRING:
                ar & T61_STRING & *x;
                break;
            default:
                BER_THROW_LONG(ar.get_ctx(),"Unsupported string type (" << std::hex << ar.peek_tag().hex() << ")");
            }
        }

        void decode(ber_archive& ar, std::string* x)
        {
            switch (ar.peek_tag().number.underlying())
            {
            case Tags::PRINTABLE_STRING:
                ar & PRINTABLE_STRING & *x;
                break;
            case Tags::UTF8_STRING:
                ar & UTF8_STRING & *x;
                break;
            case Tags::BMP_STRING:
                ar & BMP_STRING & *x;
                break;
            case Tags::IA5_STRING:
                ar & IA5_STRING & *x;
                break;
            case Tags::VISIBLE_STRING:
                ar & VISIBLE_STRING & *x;
                break;
            case Tags::T61_STRING:
                ar & T61_STRING & *x;
                break;
            default:
                BER_THROW_LONG(ar.get_ctx(),"Unsupported string type (" << std::hex << ar.peek_tag().hex() << ")");
            }
        }
    }
}

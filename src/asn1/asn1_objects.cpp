/* Some ASN.1 data types
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#define asn1_inline
#include "asn1/asn1.hpp"
#include "asn1/asn1_objects.hpp"
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <map>
#include <asn1/asn1_oid_registry.hpp>
#include <stdexcept>
#include <core/portability.h>
#include <ctime>

namespace asn1
{
    class OID_Registry
    {
    public:
        static OID_Registry& instance()
        {
            static OID_Registry s_instance;
            return s_instance;
        }

        void add_oid_str(const char *oid_str, const char *oid_name)
        {
            m_oid_registry.insert(std::make_pair(OID(oid_str), oid_name));
        }

        const char *find_oid_name(OID const& oid) const
        {
            if (m_oid_registry.find(oid) == m_oid_registry.end())
            {
                return NULL;
            }
            else
            {
                return m_oid_registry.find(oid)->second;
            }
        }

        OID const *find_oid(const char *oid_name) const
        {
            typedef std::map<OID, const char *> oid_map;
            for (oid_map::const_iterator it = m_oid_registry.begin(); it != m_oid_registry.end(); ++it)
            {
                if (!strcasecmp(oid_name, it->second))
                {
                    return &it->first;
                }
            }
            return NULL;
        }
    private:
        OID_Registry()
        {
            // Initialize the registry;
            unsigned const nOIDs = oid_registry_sz;
            for (unsigned i = 0; i < nOIDs; ++i)
            {
                add_oid_str(oid_registry[i].oid_str, oid_registry[i].oid_name);
            }
        }
        std::map<OID, const char *> m_oid_registry;
    };

    OID::OID()
    {}

    OID::OID(std::string const& s)
    {
        if (s.size() == 0)
        {
            throw std::runtime_error("Invalid OID string: empty");
        }

        uint32_t id(0);
        for (size_t i = 0; i < s.size(); ++i)
        {
            if (s[i] == '.')
            {
                if (i == 0 || i+1 == s.size() || s[i-1] == '.')
                {
                    throw std::runtime_error("Invalid OID string: " + s);
                }
                m_ids.push_back(id);
                id = 0;
            }
            else
            {
                if (!isdigit(s[i]))
                {
                    throw std::runtime_error("Invalid OID string: " + s);
                }
                else
                {
                    id *= 10;
                    id += int(s[i] - '0');
                }
            }
        }
        m_ids.push_back(id);
    }

    std::vector<uint32_t> const&
    OID::ids() const
    {
        return m_ids;
    }

    std::string
    OID::to_string() const
    {
        std::string oid_str;
        char tmp[33];

        for (size_t i = 0; i < m_ids.size(); ++i)
        {
            tmp[sizeof(tmp)-1] = '\0';
#ifdef _MSC_VER
            _itoa(m_ids[i],tmp,10);
#else
            snprintf(tmp,sizeof(tmp)-1,"%d",m_ids[i]);
#endif
            oid_str += tmp;
            if (i != m_ids.size() - 1)
            {
                oid_str += '.';
            }
        }
        return oid_str;
    }

    std::string
    OID::lookup_name() const
    {
        const char *name = OID_Registry::instance().find_oid_name(*this);
        if (name == NULL)
        {
            return to_string();
        }
        else
        {
            return std::string(name);
        }
    }

    // Lookup from name
    OID OID::lookup_from_name(const char *name)
    {
        OID const *oid = OID_Registry::instance().find_oid(name);
        if (oid)
        {
            return *oid;
        }
        else
        {
            return OID();
        }
    }

    template<>
    void asn1_content<Tags::OBJECT_ID, std::vector<uint32_t> >(iarchive& ar, std::vector<uint32_t>& m_ids, const char *ctx, bool const bDER)
    {
        std::vector<uint8_t> values(ar.left());
        ar.read_impl(&values[0], ar.left());
        if (values.size() < 2)
        {
            BER_THROW(ctx, "OID primitive expected at least two octets");
        }

        m_ids.clear();
        m_ids.push_back(values[0]/40);
        m_ids.push_back(values[0] % 40);

        // Each sub-identifier is represented as a series of (one or more) octets. Bit 8 of each octet indicates 
        // whether it is the last in the series: bit 8 of the last octet is zero; bit 8 of each preceding octet is one
        // Bits 7-1 of the octets in the series collectively encode the sub-identifier. Conceptually, these groups of bits are concatenated to form an
        // unsigned binary number whose most significant bit is bit 7 of the first octet and whose least significant bit is bit 1 of the 
        // last octet. The sub-identifier shall be encoded in the fewest possible octets, that is, the leading octet of the sub-identifier 
        // shall not have the value 0x80. 

        unsigned i = 1;
        while (i < values.size())
        {
            uint32_t component = 0;
            for (;;)
            {
                uint8_t const octet = values[i++];

                component = (component << 7) | (octet & 0x7f);

                // This was the last octet
                if ((octet & 0x80) == 0x00)
                    break;

                // Check over overflow
                if (i >= values.size())
                {
                    BER_THROW(ctx, "OID decoding overflowed");
                }
            }
            m_ids.push_back(component);
        }
    }

    // ASN.1 primitive
    void
    OID::ber_decode(ber_archive& ar)
    {
        ar & OBJECT_ID & m_ids;
    }

    // Comparison operator
    bool OID::operator<(OID const& rhs) const
    {
        // Dictionary ordering based on size then contents of the ids
        if (m_ids.size() == rhs.m_ids.size())
        {
            for (unsigned i = 0; i < m_ids.size(); ++i)
            {
                if (m_ids[i] != rhs.m_ids[i])
                {
                    return m_ids[i] < rhs.m_ids[i];
                }
            }
            return false;
        }
        else
        {
            return m_ids.size() < rhs.m_ids.size();
        }
    }

    bool OID::operator==(OID const& rhs) const
    {
        return m_ids == rhs.m_ids;
    }

    bool OID::operator!=(OID const& rhs) const
    {
        return m_ids != rhs.m_ids;
    }

    void
    AlgorithmIdentifier::ber_decode(asn1::ber_archive& ar)
    {
        ar & oid;
        ar.raw_bytes(params);
    }

    bool AlgorithmIdentifier::operator==(AlgorithmIdentifier const& rhs) const
    {
        return (oid == rhs.oid) && (params == rhs.params);
    }

    bool AlgorithmIdentifier::operator!=(AlgorithmIdentifier const& rhs) const
    {
        return !(*this == rhs);
    }

    Time::Time() :
        m_year(0), m_month(0), m_day(0),
        m_hour(0), m_min(0), m_sec(0)
    {}

    Time::Time(int year, int month, int day, int hour, int min, int sec) :
        m_year(year), m_month(month), m_day(day),
        m_hour(hour), m_min(min), m_sec(sec)
    {
        if (year < 0 || month < 1 || month > 12 || day < 1 || day > 31 ||
            m_hour < 0 || m_hour > 23 || m_min < 0 || m_min > 59 || m_sec < 0 || m_sec > 59)
        {
            throw std::runtime_error("Unexpected error constructing time object");
        }
    }

    std::string
    Time::to_string() const
    {
        std::ostringstream oss;

        struct tm time;
        time.tm_year = m_year-1900;
        time.tm_mon  = m_month-1;
        time.tm_mday = m_day;
        time.tm_hour = m_hour;
        time.tm_min  = m_min;
        time.tm_sec  = m_sec;

        char buf[1024]; buf[sizeof(buf)-1] = 0;
        strftime(buf, sizeof(buf) - 1, "%b %e %H:%M:%S %Y GMT", &time);
        return std::string(buf);
    }

    bool
    Time::operator==(Time const& rhs) const
    {
        return
        m_year == rhs.m_year &&
        m_month == rhs.m_month && 
        m_day  == rhs.m_day /*&&
        m_hour == rhs.m_hour &&
        m_min == rhs.m_min &&
        m_sec == rhs.m_sec*/;
    }

    bool
    Time::operator<=(Time const& rhs) const
    {
        if (m_year == rhs.m_year)
        {
            if (m_month == rhs.m_month)
            {
                return m_day <= rhs.m_day;
            }
            else
            {
                return m_month <= rhs.m_month;
            }
        }
        else
        {
            return m_year <= rhs.m_year;
        }
    }

    bool
    Time::operator<(Time const& rhs) const
    {
        return (*this <= rhs) && !(*this == rhs);
    }

    bool
    Time::operator>(Time const& rhs) const
    {
        return !(*this <= rhs);
    }

    Time
    Time::now()
    {
        time_t time_ = time(NULL);
        struct tm *date = localtime(&time_);
        return Time(date->tm_year + 1900, date->tm_mon + 1, date->tm_mday,0,0,0);
    }

    void
    Time::ber_decode(ber_archive& ar)
    {
        switch (ar.peek_tag().number.underlying())
        {
        case Tags::UTC_TIME:
            ar & UTC_TIME & *this;
            break;
        case Tags::GENERALIZED_TIME:
            ar & GENERALIZED_TIME & *this;
            break;
        default:
            BER_THROW_LONG(ar.get_ctx(), "Unrecognized tag 0x" << std::hex << ar.peek_tag().hex());
        }
    }

    template<>
    void asn1_content<Tags::UTC_TIME,Time>(iarchive& ar, Time& time, const char *ctx, bool const bDER)
    {
        std::string s_time;
        asn1_content<Tags::VISIBLE_STRING, std::string>(ar, s_time, ctx, bDER);

        // YYMMDDhhmm[ss]Z
        if (s_time[s_time.length() - 1] != 'Z')
        {
            BER_THROW_LONG(ctx, "Invalid UTCTime: " << s_time);
        }

        int year(0), month(0), day(0), hour(0), min(0), seconds(0);

        // NB seconds may be omitted
        if (sscanf(s_time.c_str(), "%2d%2d%2d%2d%2d%2dZ", &year, &month, &day, &hour, &min, &seconds) < 5)
        {
            BER_THROW_LONG(ctx, "Invalid UTCTime: " << s_time);
        }

        // Make sure the fields are all positive
        if (year < 0 || month <= 0 || day <= 0 || hour < 0 || min < 0 || seconds < 0 ||
            month > 12 || day > 31 || hour >= 24 || min >= 60 || seconds >= 60)
        {
            BER_THROW_LONG(ctx, "Invalid UTCTIME: " << s_time);
        }

        if (year < 50)
        {
            year += 100;
        }

        time = Time(year+1900,month,day,hour,min,seconds);
    }

    template<>
    void asn1_content<Tags::GENERALIZED_TIME,Time>(iarchive& ar, Time& x, const char *ctx, bool const bDER)
    {
        std::string s_time;
        asn1_content<Tags::VISIBLE_STRING, std::string>(ar, s_time, ctx, bDER);

        // YYMMDDhhmm[ss]Z
        if (s_time[s_time.length() - 1] != 'Z' || s_time.length() != 15)
        {
            BER_THROW_LONG(ctx, "Invalid UTCTime: " << s_time);
        }

        int year(0), month(0), day(0), hour(0), min(0), seconds(0);

        // NB seconds may be omitted
        if (sscanf(s_time.c_str(), "%4d%2d%2d%2d%2d%2dZ", &year, &month, &day, &hour, &min, &seconds) < 5)
        {
            BER_THROW_LONG(ctx, "Invalid UTCTime: " << s_time);
        }

        // Make sure the fields are all positive
        if (year < 0 || month <= 0 || day <= 0 || hour < 0 || min < 0 || seconds < 0 ||
            month > 12 || day > 31 || hour >= 24 || min >= 60 || seconds >= 60)
        {
            BER_THROW_LONG(ctx, "Invalid UTCTIME: " << s_time);
        }

        x = Time(year,month,day,hour,min,seconds);
    }

}

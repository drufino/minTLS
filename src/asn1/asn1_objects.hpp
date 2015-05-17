/* Some ASN.1 data types
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_asn1_objects_hpp
#define tf_asn1_objects_hpp
#include "asn1/asn1_archive.hpp"
#include <string>
#include <set>

namespace asn1
{

// Object Identifier ([5] 8.2)
class OID : public asn1::ber_decodable
{
public:
    // Default constructor
    OID();

    // Construct from string
    OID(std::string const& s);

    // Get the IDs
    std::vector<uint32_t> const& ids() const;

    // Represent as a string
    std::string                  to_string() const;

    // ASN.1 BER decode
    void ber_decode(ber_archive& ar);

    // Comparison operator
    bool operator<(OID const& rhs) const;

    // Lookup
    std::string lookup_name() const;

    // Lookup from name
    static OID lookup_from_name(const char *name);

    // Comparison operator
    bool operator==(OID const& rhs) const;
    bool operator!=(OID const& rhs) const;

private:
    std::vector<uint32_t>   m_ids;
};

// Template specialization for OBJECT_ID
template<> void asn1_content<Tags::OBJECT_ID, std::vector<uint32_t> >(iarchive& ar, std::vector<uint32_t>& m_ids, const char *ctx, bool const bDER);

// [3] 4.1.1.2
class AlgorithmIdentifier : public asn1::ber_decodable_sequence
{
public:
    // BER decoding
    void ber_decode(asn1::ber_archive& ar);

    // Comparison operator
    bool operator==(AlgorithmIdentifier const& rhs) const;
    bool operator!=(AlgorithmIdentifier const& rhs) const;

    asn1::OID               oid;
    std::vector<uint8_t>    params;
};

// UTCTime and GeneralizedTime [5] 11.7, 11.8
class Time : public asn1::ber_decodable
{
public:
    // Default constructor
    Time();

    // Constructor
    Time(
        int year,       // (I) Actual Year
        int month,      // (I) Month of the Year (1-12)
        int day,        // (I) Day of the Month (1-31)
        int hour,       // (I) Hour (0-23)
        int min,        // (I) Minute (0-59)
        int sec         // (I) Second (0-59)
    );

    // ASN.1 BER decode
    void ber_decode(ber_archive& ar);

    // Pretty Print
    std::string to_string() const;

    // Comparison operators
    bool operator==(Time const& rhs) const;
    bool operator<(Time const& rhs) const;
    bool operator<=(Time const& rhs) const;
    bool operator>(Time const& rhs) const;

    static Time now();

private:
    int     m_year;         // Year
    int     m_month;        // Month of the year (1-12)
    int     m_day;          // Day (1-31)
    int     m_hour;         // Hour (0-23)
    int     m_min;          // Minute (0-59)
    int     m_sec;          // Second (0-59)
};

template<>
void asn1_content<Tags::UTC_TIME,Time>(iarchive& ar, Time& time, const char *ctx, bool const bDER);

template<>
void asn1_content<Tags::GENERALIZED_TIME,Time>(iarchive& ar, Time& x, const char *ctx, bool const bDER);

} // namespace asn1

#endif

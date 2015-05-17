#include <tls/tls_ecc.hpp>
#include <tls/tls_protocol.hpp>

// Default constructor
ECParameters::ECParameters()
{
    type = ECCurveTypes::named_curve;
    named_curve = mintls_secp224r1;
}

void
ECParameters::serialize(archive& ar)
{
    ar & type;

    if (type.underlying() == ECCurveTypes::named_curve)
    {
        ar & named_curve;
    }
    else 
    {
        throw TLSException("Only ECC named curves supported", mintls_err_illegal_parameter);
    }
}

void
ECPoint::serialize(archive& ar)
{
    ar & point;

    if (point.size() == 0)
    {
        throw TLSException("Attempted to serialize empty elliptic curve point", mintls_err_illegal_parameter);
    }
}

TLSSupportedEllipticCurves::TLSSupportedEllipticCurves()
{
}

TLSSupportedEllipticCurves::TLSSupportedEllipticCurves(std::vector<TLSNamedCurve> const& curves)
  : m_curves(curves)
{
}

void
TLSSupportedEllipticCurves::serialize(archive& ar)
{
    ar & m_curves;

    if (m_curves.size() == 0)
    {
        throw TLSException("Attempted to serialize empty elliptic curve list", mintls_err_illegal_parameter);
    }
}

TLSSupportedEllipticCurves *
TLSSupportedEllipticCurves::clone() const
{
    return new TLSSupportedEllipticCurves(*this);
}

TLSExtensionType
TLSSupportedEllipticCurves::type() const
{
    return TLSExtensionTypes::elliptic_curves;
}

bool
TLSSupportedEllipticCurves::operator==(TLSSupportedEllipticCurves const& rhs) const
{
    return m_curves == rhs.m_curves;
}

bool
TLSSupportedEllipticCurves::equals(TLSExtensionBase const& rhs) const
{
    if (TLSSupportedEllipticCurves const * pRhs = dynamic_cast<TLSSupportedEllipticCurves const *>(&rhs))
    {
        // Delegate to comparison operator
        return *this == *pRhs;
    }
    else
    {
        return false;
    }
}

TLSSupportedEllipticCurves::~TLSSupportedEllipticCurves()
{
}
#include "core/bigint.hpp"
#include "random.h"
#include <sstream>
#include <stdexcept>
#include <core/portability.h>

#define CHK(f)      \
{                   \
    int ret = f;    \
    if (ret != 0)     \
    {               \
        std::ostringstream oss; \
        oss << "BigNum:" << __FUNCTION__ << ":" << __LINE__ << " retcode=" << ret; \
        throw std::runtime_error(oss.str()); \
    }               \
}

void
BigInt::dealloc()
{
    if (ref_cnt)
    {
        if (*ref_cnt == 1)
        {
            mpi_free(&num, NULL);
            delete ref_cnt;
        }
        else
        {
            (*ref_cnt)--;
        }
        ref_cnt = NULL;
    }
}

void
BigInt::alloc()
{
    dealloc();
    mpi_init(&num, NULL);
    ref_cnt = new unsigned;
    *ref_cnt = 1;
}

BigInt::BigInt() :
    ref_cnt(NULL)
{
    alloc();
    // Set to zero
    CHK(mpi_lset(&num, 0));
}

BigInt::BigInt(int x) :
    ref_cnt(NULL)
{
    alloc();
    CHK(mpi_lset(&num, x));
}

BigInt::BigInt(std::vector<uint8_t> const& data) :
    ref_cnt(NULL)
{
    alloc();
    init(&data[0],data.size());
}

BigInt::BigInt(uint8_t const *data, size_t const data_sz) :
    ref_cnt(NULL)
{
    alloc();
    init(data, data_sz);
}

void
BigInt::init(uint8_t const* data, size_t const sz)
{
    alloc();
    CHK(mpi_read_binary(&num, (unsigned char *)data,(int)sz));
}

BigInt::BigInt(BigInt const& rhs)
{
    num     = rhs.num;
    ref_cnt = rhs.ref_cnt;

    if (ref_cnt)
    {
        (*ref_cnt)++;
    }
}

BigInt::~BigInt()
{
    dealloc();
}

BigInt& BigInt::operator=(BigInt const& rhs)
{
    if (this != &rhs)
    {
        dealloc();

        num     = rhs.num;
        ref_cnt = rhs.ref_cnt;
        if (ref_cnt)
        {
            (*ref_cnt)++;
        }
    }

    return *this;
}

mpi const& BigInt::get_num() const
{
    return num;
}

size_t BigInt::size() const
{
    return mpi_size(get());
}

unsigned BigInt::nbits() const
{
    return mpi_msb(get());
}

void BigInt::write_binary(uint8_t *p,size_t const len) const
{
    CHK((len < size()) ? -1 : 0);
    memset(p,0,len - size());
    CHK(mpi_write_binary(get(), p + len - size(), size()));
    return;
}

std::vector<uint8_t> BigInt::get_binary(size_t len) const
{
    if (len == 0) len = size();

    std::vector<uint8_t> binary(len, 0);
    CHK(mpi_write_binary(get(), &binary[0], binary.size()));
    return binary;
}

bool BigInt::operator==(BigInt const& rhs) const
{
    return 0 == mpi_cmp_mpi(get(),rhs.get());
}

bool BigInt::operator!=(BigInt const& rhs) const
{
    return 0 != mpi_cmp_mpi(get(),rhs.get());
}

bool BigInt::operator<=(BigInt const& rhs) const
{
    return mpi_cmp_mpi(get(),rhs.get()) <= 0;
}

bool BigInt::operator<(BigInt const& rhs) const
{
    return mpi_cmp_mpi(get() ,rhs.get()) < 0;
}

bool BigInt::operator>(BigInt const& rhs) const
{
    return mpi_cmp_mpi(get() ,rhs.get()) > 0;
}

bool BigInt::operator>=(BigInt const& rhs) const
{
    return mpi_cmp_mpi(get(),rhs.get()) >= 0;
}

BigInt& BigInt::operator<<=(int shift)
{
    CHK(mpi_shift_l(get(), shift));
    return *this;
}

BigInt BigInt::operator<<(int shift) const
{
    BigInt x(*this);
    x <<= shift;
    return x;
}

BigInt& BigInt::operator++()
{
    *this = *this + BigInt(1);
    return *this;
}

BigInt BigInt::operator+(BigInt const& rhs) const
{
    BigInt res;
    CHK(mpi_add_mpi(res.get(),get(),rhs.get()));
    return res;
}

BigInt BigInt::operator-() const
{
    BigInt res = *this;
    res.num.s *= -1;
    return res;
}

BigInt BigInt::operator-(BigInt const& rhs) const
{
    BigInt res;
    CHK(mpi_sub_mpi(res.get(),get(),rhs.get()));
    return res;
}
BigInt BigInt::operator*(BigInt const& rhs) const
{
    BigInt res;
    CHK(mpi_mul_mpi(res.get(), get(), rhs.get()));;
    return res;
}

BigInt BigInt::operator%(BigInt const& rhs) const
{
    BigInt res;
    CHK(mpi_mod_mpi(res.get(),get(),rhs.get()));
    return res;
}

std::string BigInt::to_decimal() const
{
    VLA(char, buf, size() * 6 + 4);
    int  buf_sz(0);
    mpi_write_string(get(), 10, buf, &buf_sz);
    CHK(mpi_write_string(get(), 10, buf, &buf_sz));
    return std::string(buf);
}
std::string BigInt::to_string() const
{
    VLA(char, buf, size() * 4 + 4);
    int  buf_sz(0);
    mpi_write_string(get(),16,buf,&buf_sz);
    CHK(mpi_write_string(get(),16,buf,&buf_sz));
    return "0x" + std::string(buf);
}

void BigInt::serialize(archive& ar)
{
    if (ar.is_reading())
    {
        vararray<uint8_t>::_16 data; ar & data;
        init(&data[0],data.size());
    }
    else
    {
        vararray<uint8_t>::_16 data = get_binary();
        ar & data;
    }
}

BigInt
BigInt::rand(unsigned nbits)
{
    unsigned const nbytes = (nbits+7)/8;
    std::vector<uint8_t> bytes(nbytes,0x00);
    mintls_random(&bytes[0],nbytes);
    // ensure MSB is 1
    if (nbits & 0x7)
    {
        bytes[0] |= 0x80 >> (8-(nbits & 0x7));
    }
    else
    {
        bytes[0] |= 0x80;
    }

    return BigInt(bytes);
}

BigInt
BigInt::exp_mod(BigInt const& g, BigInt const& X, BigInt const& N)
{
    BigInt res;
    CHK(mpi_exp_mod(res.get(),g.get(),X.get(),N.get(),NULL));
    return res;
}

mpi const * BigInt::get() const
{
    return (&num);
}

mpi  * BigInt::get() 
{
    if (*ref_cnt > 1)
    {
        // Make a copy
        mpi num_new;
        mpi_init(&num_new, NULL);
        CHK(mpi_copy(&num_new,&num));

        // Dereference
        dealloc();

        // Remember the copy
        num = num_new;
        ref_cnt = new unsigned;
        *ref_cnt = 1;
    }
    return (&num);
}

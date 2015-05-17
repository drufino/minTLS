#ifndef tf_bigint_hpp
#define tf_bigint_hpp
#include "core/bignum.h"
#include "archive.hpp"
#include <vector>
#include <string>

// Wrap around the core C-based class
class BigInt
{
public:
    // Default Constructor
    BigInt();

    // Construct from int
    BigInt(int x);

    // Construct from unsigned binary data big endian
    BigInt(std::vector<uint8_t> const& data);

    BigInt(uint8_t const *data, size_t const data_sz);

    // Copy Constructor
    BigInt(BigInt const& rhs);

    // Assignment Operator
    BigInt& operator=(BigInt const& rhs);

    // Underlying implementation
    mpi const& get_num() const;

    // Size in bytes
    size_t size() const;

    // Size in bits
    unsigned nbits() const;

    // Write out |X| in big-endian format
    std::vector<uint8_t> get_binary(size_t len = 0) const;
    void write_binary(uint8_t *p, size_t const len) const;

    // Comparison operators
    bool operator==(BigInt const& rhs) const;
    bool operator!=(BigInt const& rhs) const;
    bool operator<(BigInt const& rhs) const;
    bool operator<=(BigInt const& rhs) const;
    bool operator>=(BigInt const& rhs) const;
    bool operator>(BigInt const& rhs) const;

    BigInt& operator++();

    BigInt operator-() const;
    BigInt operator+(BigInt const& rhs) const;
    BigInt operator-(BigInt const& rhs) const;
    BigInt operator*(BigInt const& rhs) const;
    BigInt operator%(BigInt const& rhs) const;

    BigInt& operator<<=(int shift);
    BigInt operator<<(int shift) const;

    std::string to_string() const;
    std::string to_decimal() const;

    // Destructor
    ~BigInt();

    void serialize(archive& ar);

    // Random Number
    static BigInt rand(unsigned bits);

    // Calculate g^X (mod N)
    static BigInt exp_mod(BigInt const& g, BigInt const& X, BigInt const& N);

private:
    void init(uint8_t const* data, size_t const sz);

    void dealloc();
    void alloc();

    mpi const * get() const;
    mpi * get();

    mpi         num;
    unsigned *  ref_cnt;
};
#endif /* tf_bigint_hpp */
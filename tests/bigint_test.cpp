#include "core/bigint.hpp"
#include "test_helpers.hpp"
#include "test_helpers.cpp"
#include "test_main.hpp"

void create_big_test_cases(std::vector<BigInt>& cases)
{
    cases.clear();
    cases.reserve(11*13+1);
    cases.push_back(BigInt());
    for (size_t sz = 1; sz <= 11; ++sz)
    {
        std::vector<uint8_t> data(sz);
        for (int i = 0; i < 10; ++i)
        {
            for (size_t j = 0; j < sz; ++j)
            {
                data[j] = rand()%0x100;
            }
            cases.push_back(BigInt(data));
        }
        // Create some edge cases to check the addition carry
        data.assign(sz,0xfe);
        cases.push_back(BigInt(data));
        data.assign(sz,0xff);
        cases.push_back(BigInt(data));
        if (sz > 1)
            data[1] = 0xfe;
        cases.push_back(BigInt(data));
    }
}

std::vector<int> create_small_test_cases()
{
    std::vector<int> cases(1,0);
    cases.reserve(4*20+1);
    for (size_t sz = 1; sz <= 4; ++sz)
    {
        for (int i = 0; i < 10; ++i)
        {
            unsigned int x(0);
            for (size_t j = 0; j < sz; ++j)
            {
                x <<= 8;
                x += ((unsigned)(rand()%0x100));

                x &= 0x7fffffff;
                if (j == (sz - 1))
                {
                    cases.push_back((int)x);
                    cases.push_back(-(int)x);
                }
            } 
        }
    }
    return cases;
}

class bigint_test_fixture : public testing::Test
{
public:
    virtual void SetUp() {small_cases = create_small_test_cases();  create_big_test_cases(big_cases); }

    std::vector<int> small_cases;
    std::vector<BigInt> big_cases;
};

std::ostream& operator<<(std::ostream & os, BigInt const& x)
{
    os << x.to_string();
    return os;
}

BigInt slow_mult(BigInt const& x, BigInt  const& y)
{
    std::vector<uint8_t> x_binary(x.get_binary());
    std::vector<uint8_t> y_binary(y.get_binary());

    // Convert to LE for simplicity
    std::reverse(x_binary.begin(),x_binary.end());
    std::reverse(y_binary.begin(),y_binary.end());

    BigInt res;
    for (unsigned i = 0; i < x_binary.size(); ++i)
    {
        for (unsigned j = 0; j < y_binary.size(); ++j)
        {
            BigInt tmp (int(x_binary[i]) * int(y_binary[j]));
            tmp <<= (i+j)*8;
            res = res + tmp;
        }
    }
    return res;
}

TEST_F(bigint_test_fixture, big_mult_test)
{
    std::vector<BigInt> const& cases = big_cases;
    for (unsigned i = 0; i < cases.size(); ++i)
    {
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            BigInt const& x = cases[i];
            BigInt const& y = cases[j];
            BigInt z = x * y;
            BigInt z2(slow_mult(x,y));
            ASSERT_EQ(z,z2) << "X=" << x << " Y=" << y;
        }
    }
}
TEST_F(bigint_test_fixture, big_cmp_test)
{
    std::vector<BigInt> const& cases = big_cases;

    // check pair-wise comparisons by doing it manually on the binary expansion
    for (unsigned i = 0; i < cases.size(); ++i)
    {
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            BigInt x(cases[i]);
            BigInt y(cases[j]);

            std::vector<uint8_t> x_ = x.get_binary();
            std::vector<uint8_t> y_ = y.get_binary();
            while (y_.size() > 0 && y_[0] == 0x0) y_ = std::vector<uint8_t>(y_.begin()+1,y_.end());
            while (x_.size() > 0 && x_[0] == 0x0) x_ = std::vector<uint8_t>(x_.begin()+1,x_.end());

            if (x_.size() < y_.size())
            {
                std::swap(x,y);
                std::swap(x_,y_);
            }
            if (x_.size() > y.size())
            {
                EXPECT_GT(x,y);
                EXPECT_GE(x,y);
                EXPECT_TRUE(!(x==y));
                EXPECT_TRUE(!(x<y));
                EXPECT_TRUE(!(x<=y));
            }
            else if (x_.size() == y_.size())
            {
                int cmp(0);
                for (int i = 0; i < x_.size(); ++i)
                {
                    if (x_[i] < y_[i])
                    {
                        cmp = -1;
                        break;
                    }
                    else if (x_[i] > y_[i])
                    {
                        cmp = 1;
                        break;
                    }
                }
                if (cmp == -1)
                {
                    std::swap(x,y);
                    cmp = 1;
                }
                if (cmp == 1)
                {
                    EXPECT_GT(x,y);
                    EXPECT_GE(x,y);
                    EXPECT_TRUE(!(x==y));
                    EXPECT_TRUE(!(x<y));
                    EXPECT_TRUE(!(x<=y));
                }
                else if (cmp == 0)
                {
                    EXPECT_EQ(x,y);
                    EXPECT_TRUE(!(x>y));
                    EXPECT_GE(x,y);
                    EXPECT_TRUE(!(x<y));
                    EXPECT_LE(x,y);
                }
            }
        }
    }
}

bool check_pred_eq(BigInt const& x_, BigInt const& y_, int x, int y)
{
    return (x_ == y_) == (x == y);
}

bool check_pred_lt(BigInt const& x_, BigInt const& y_, int x, int y)
{
    return (x_ < y_) == (x < y);
}

bool check_pred_le(BigInt const& x_, BigInt const& y_, int x, int y)
{
    return (x_ <= y_) == (x <= y);
}

bool check_pred_ge(BigInt const& x_, BigInt const& y_, int x, int y)
{
    return (x_ >= y_) == (x >= y);
}

bool check_pred_gt(BigInt const& x_, BigInt const& y_, int x, int y)
{
    return (x_ > y_) == (x > y);
}


void
small_cmp_test_helper(std::vector<int> const& cases)
{
    for (unsigned i = 0; i < cases.size(); ++i)
    {
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            int x = cases[i];
            int y = cases[j];
            BigInt x_(x);
            BigInt y_(y);

            EXPECT_PRED4(check_pred_eq, x_,y_,x,y);
            EXPECT_PRED4(check_pred_lt, x_,y_,x,y);
            EXPECT_PRED4(check_pred_le, x_,y_,x,y);
            EXPECT_PRED4(check_pred_gt, x_,y_,x,y);
            EXPECT_PRED4(check_pred_ge, x_,y_,x,y);
        }
    }
}

// check comparisons by using integer comparison
TEST_F(bigint_test_fixture,small_cmp_test)
{
    small_cmp_test_helper(small_cases);
}

TEST(bigint_test,small_constructor_test)
{
    for (int x = 1; x <= 0xff; ++x)
    {
        BigInt x_(x);
        EXPECT_EQ(x_.size(), 1);
        EXPECT_EQ(x_.get_binary(),std::vector<uint8_t>(1,(uint8_t)x));
    }

    for (int x = 0x100; x <= 0xffff; x += 0x0102)
    {
        BigInt x_(x);
        EXPECT_EQ(x_.size(), 2);
        std::vector<uint8_t> binary(2,0);
        binary[0] = (x&0xff00)>>8;
        binary[1] = (x&0x00ff);
        EXPECT_EQ(x_.get_binary(),binary);
    }

    for (int x = 0x010000; x <= 0xffff00; x += 0x010203)
    {
        BigInt x_(x);
        EXPECT_EQ(x_.size(), 3);
        std::vector<uint8_t> binary(3,0);
        binary[0] = (x&0xff0000)>>16;
        binary[1] = (x&0x00ff00)>>8;
        binary[2] = (x&0x0000ff);
        EXPECT_EQ(x_.get_binary(),binary);
    }

    for (unsigned int x = 0x01000000; x <= 0x7f000000; x += 0x01020304)
    {
        BigInt x_(x);
        EXPECT_EQ(x_.size(), 4);
        std::vector<uint8_t> binary(4,0);
        binary[0] = (x&0xff000000)>>24;
        binary[1] = (x&0x00ff0000)>>16;
        binary[2] = (x&0x0000ff00)>>8;
        binary[3] = (x&0x000000ff);
        EXPECT_EQ(x_.get_binary(),binary);
    }
}

// check left-shifts work for whole-byte shifts
TEST(bigint_test, big_byte_shift_test)
{
    std::vector<BigInt> big_test_cases; create_big_test_cases(big_test_cases);
    for (unsigned i = 0; i < big_test_cases.size(); ++i)
    {
        BigInt x = big_test_cases[i];
        std::vector<uint8_t> binary_1 = x.get_binary();
        for (int shift = 0; shift <= 128; shift += 8)
        {
            BigInt y(x);
            y <<= shift;
            EXPECT_EQ(binary_1,y.get_binary());
            if (x != BigInt())
            {
                binary_1.push_back(0x0);
            }
            EXPECT_EQ(y,x<<shift);
        }
    }
}

// check x + y where x is general and y is a single byte possibly shifted
TEST_F(bigint_test_fixture, big_add_byte_test)
{
    std::vector<BigInt> const& big_test_cases = big_cases;
    for (unsigned i = 0; i < big_test_cases.size(); ++i)
    {
        BigInt x = big_test_cases[i];
        std::vector<uint8_t> binary = x.get_binary();
        int k(0);
        bool bFailed(false);
        // Loop over all possible positions of the byte
        for (int j = binary.size()-1; !bFailed && j >= 0; --j,++k)
        {
            // Loop over all possible values
            for (int y_ = 0; y_ <= 0xff && !bFailed; ++y_)
            {
                // Create 0x000000yy00000
                BigInt y(y_); y <<= (k*8);
                BigInt z = x + y;
                EXPECT_EQ(z,y+x);
                if (x == BigInt(0))
                {
                    EXPECT_EQ(z,y);
                }
                else
                {
                    std::vector<uint8_t> z__ = binary;
                    std::vector<uint8_t> z_ = z.get_binary();
                    // Check carry
                    if (int(y_)+int(z__.at(j)) > 0xff)
                    {
                        z__[j] += uint8_t(y_);
                        // Add in the carry
                        for (int l = j-1; ; --l)
                        {
                            if (l >= 0)
                            {
                                z__[l]++;
                                if (z__[l] != 0)
                                {
                                    // No further carries so stop
                                    break;
                                }
                            }
                            else
                            {
                                // In this case have 0xffffff and need to resize the number
                                z__ = std::vector<uint8_t>(1,0x1) + z__;
                                break;
                            }
                        }

                    }
                    else
                    {
                        // No carry so just manually add
                        z__[j] += y_;
                    }
                    EXPECT_TRUE(z_==z__) << x << " + " << y << " = " << z << " (not " << BigInt(z__).to_string() << ")";

                    bFailed |= z_ != z__;
                }
            }
        }
    }
}

TEST(bigint_test, big_constructor_test)
{
    for (size_t sz = 4; sz <= 8; ++sz)
    {
        for (int i = 0; i < 10; ++i)
        {
            std::vector<uint8_t> data(sz);
            for (size_t j = 0; j < sz; ++j)
            {
                data[j] = rand()%0x100;
            }
            while (data[0] == 0) data[0] = rand()%0x100;
            BigInt x(data);
            BigInt y(x);
            EXPECT_EQ(x.get_binary(), data);
            EXPECT_EQ(x,y);
            EXPECT_EQ(y.get_binary(),data);
            EXPECT_GT(x,BigInt());
            EXPECT_LT(BigInt(),x);
        }
    }
}

// check general case 
TEST_F(bigint_test_fixture, big_add_test)
{
    std::vector<BigInt> const& cases = big_cases;

    for (unsigned i = 0; i < cases.size(); ++i)
    {
        BigInt x = cases[i];
        ASSERT_EQ(x+BigInt(),x);
        ASSERT_EQ(x+(-x),BigInt());
        ASSERT_EQ((-x)+x,BigInt());
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            BigInt y = cases[j];
            std::vector<uint8_t> y_ = y.get_binary();
            BigInt res = x;
            for (unsigned k = 0; k < y.size(); ++k)
            {
                unsigned l = y.size() - k - 1;
                res = res + (BigInt(y_[k])<<(8*l));
            }
            ASSERT_EQ(res,x+y);
            ASSERT_EQ(x+y,y+x);
            ASSERT_EQ(x+(-y),x-y);
            ASSERT_EQ((-y)+x,x-y);
        }
    }
}

TEST_F(bigint_test_fixture, big_sub_test)
{
    std::vector<BigInt> const& cases = big_cases;

    for (unsigned i = 0; i < cases.size(); ++i)
    {
        BigInt x = cases[i];
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            BigInt y = cases[j];

            if (x < y)
            {
                ASSERT_GT(y-x,BigInt());
                ASSERT_EQ((y-x)+x,y);
            }
            else
            {
                ASSERT_GE(x-y,BigInt());
                ASSERT_EQ((x-y)+y,x);
            }

            ASSERT_EQ(x-y,-(y-x));
        }
    }
}
TEST_F(bigint_test_fixture, big_negation_test)
{
    std::vector<BigInt> const& cases = big_cases;

    for (unsigned i = 0; i < cases.size(); ++i)
    {
        BigInt x = cases[i];
        BigInt y = -x;

        ASSERT_TRUE(x == BigInt() || x != y);
        ASSERT_EQ(x.get_binary(),y.get_binary());
        ASSERT_GE(x,y);
        ASSERT_LE(y,x);
        ASSERT_GE(BigInt(),y);
        ASSERT_LE(y,0);
        ASSERT_EQ(-y,x);
    }
}

TEST_F(bigint_test_fixture,cow_semantics)
{
    std::vector<BigInt> const& cases = big_cases;

    for (unsigned i = 0; i < cases.size(); ++i)
    {
        BigInt const& x = cases[i];
        std::vector<uint8_t> x_ = x.get_binary();
        BigInt y = x;
        ASSERT_EQ(y,x);
        ASSERT_EQ(y.get_num().p,x.get_num().p);
        ASSERT_EQ(x_,y.get_binary());
        y <<= 2;
        ASSERT_NE(y.get_num().p,x.get_num().p);
        ASSERT_EQ(x_,x.get_binary());
    }
}

TEST_F(bigint_test_fixture,exp_mod)
{
    std::vector<BigInt> const& cases = big_cases;

    for (unsigned i = 0; i < cases.size(); ++i)
    {
        BigInt const& x = cases[i];
        for (unsigned j = 0; j < cases.size(); ++j)
        {
            BigInt const& y = cases[j];
            if (x > BigInt() && y > BigInt() && (y % 2) != BigInt())
            {
                //ASSERT_EQ(BigInt(1), BigInt::exp_mod(x,0,y)) << "(" << x << ")^(0) mod (" << y << ")";
                ASSERT_EQ(x % y, BigInt::exp_mod(x,BigInt(1),y)) << "(" << x << ")^(1) mod (" << y << ")";
            }
        }
    }
}

TEST(bigint_test,zero_test)
{
    BigInt zero;

    EXPECT_EQ(zero.size(), 0);
    EXPECT_EQ(zero.get_binary(),std::vector<uint8_t>());

    BigInt zero_2(0);
    EXPECT_EQ(zero_2.size(), 0);
    EXPECT_EQ(zero_2.get_binary(),std::vector<uint8_t>());

    EXPECT_EQ(zero,zero_2);
}

TEST(bigint_test, string_test)
{
    EXPECT_EQ(BigInt(0x10001).to_string(),"0x10001");
    EXPECT_EQ(BigInt(0x100001).to_string(), "0x100001");
    EXPECT_EQ(BigInt(0x12345).to_string(),"0x12345");
    EXPECT_EQ(BigInt(0x123456).to_string(), "0x123456");
}

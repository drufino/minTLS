#include "core/archive.hpp"
#include "test_helpers.hpp"
#include <stdexcept>
#include "test_helpers.cpp"
#include "test_main.hpp"

class archive_test_values
{
public:
    archive_test_values() { init(); }

    // initialize the test vectors
    void init()
    {
        a = 0x1;                                    a_= {0x1};
        b = 0x0203;                                 b_= {0x02,0x03};
        c = 0x04050607;                             c_ = {0x04,0x05,0x06,0x07};
        p = 0x08090a0b0c0d0e0f;                     p_ = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

        d[0]=0xfe;d[1]=0xed;d[2]=0xfa;d[3]=0xce;    d_ = std::vector<uint8_t>(d,d+sizeof(d));
        e = {0xde,0xad,0xbe,0xef,0xfa,0xce};        e_ = {0x00,0x06,0xde,0xad,0xbe,0xef,0xfa,0xce};
        f[0] = 0xfeed;f[1] = 0xface;                f_ ={0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xcd};
        f[2] = 0xdead;f[3] = 0xbeef;
        f[4] = 0xabcd;

        g[0] = 0xdeadbeef; g[1] = 0xfeedface;       
        g[2] = 0xabcd0123; g[3] = 0x31415902;
        g[4] = 0x41424344; g[5] = 0x45464748;

        g_={0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xab,0xcd,0x01,0x23,0x31,0x41,0x59,0x02,0x41,0x42,0x43,0x44,
           0x45,0x46,0x47,0x48};

        h = {0xf423,0xb21e,0x2103,0x4582}; h_ = {0x00,0x08,0xf4,0x23,0xb2,0x1e,0x21,0x03,0x45,0x82};
        i = e;                             i_ = {0x06,0xde,0xad,0xbe,0xef,0xfa,0xce};
        j = h;                             j_ = {0x08,0xf4,0x23,0xb2,0x1e,0x21,0x03,0x45,0x82};
        k = std::vector<uint32_t>(g,g+sizeof(g)/4);
        k_ = {0x00,0x06*4,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xab,0xcd,0x01,0x23,0x31,0x41,0x59,0x02,0x41,0x42,0x43,0x44,
           0x45,0x46,0x47,0x48};

        l = std::vector<uint16_t>({0xf423,0xb21e,0x2103,0x4582});
        l_ = {0x00,0x00,0x08,0xf4,0x23,0xb2,0x1e,0x21,0x03,0x45,0x82};

        m = 0x3abc72;
        m_ = {0x3a,0xbc,0x72};
    }

    uint8_t                 a;
    uint16_t                b;
    uint32_t                c;
    uint64_t                p;
    uint8_t                 d[4];
    std::vector<uint8_t>    e;
    uint16_t                f[5];
    uint32_t                g[6];
    std::vector<uint16_t>   h;
    vararray<uint8_t>::_8   i;
    vararray<uint16_t>::_8  j;
    vararray<uint32_t>::_16 k;
    vararray<uint16_t>::_24 l;
    uint24_t                m;

    std::vector<uint8_t>    a_,b_,c_,d_,e_,f_,g_,h_,i_,j_,k_,l_,m_,p_;
};

class archive_test : public testing::Test , public archive_test_values
{
public:
    virtual void SetUp() {init();}
};


// test arrays of non-POD typs
TEST_F(archive_test,compound_types)
{
    vararray<vararray<uint16_t>::_32>::_8 x1, x2(1,std::vector<uint16_t>(1,1));

    x1.push_back(std::vector<uint16_t>({0x0102,0x0304}));
    x1.push_back(std::vector<uint16_t>({0x0506,0x0708,0x090a})); 

    std::vector<uint8_t> buf;
    oarchive ar(buf);
    ar & x1;

    std::vector<uint8_t> x1_ = {0x12,0x00,0x00,0x00,0x04,0x01,0x02,0x03,0x04,0x00,0x00,0x00,0x06,0x05,0x06,0x07,0x08,0x09,0x0a};
    EXPECT_EQ(x1_,buf);
    iarchive ar2(&buf[0],buf.size());
    EXPECT_EQ(ar2.size(),0);
    EXPECT_EQ(ar2.left(),buf.size());
    ar2 & x2;
    EXPECT_EQ(ar2.size(),buf.size());
    EXPECT_EQ(ar2.left(),0);
    EXPECT_EQ(x2,x1);
    EXPECT_THROW(ar2 & x2, archive::error_eof);
}

TEST_F(archive_test, write_primitives)
{
    #define foo(x) \
    {                             \
        std::vector<uint8_t> buf; \
        oarchive ar(buf);         \
        ar & x;                   \
        EXPECT_EQ(buf,x##_);      \
    }

    foo(a); foo(b); foo(c); foo(d); foo(e); foo(f);
    foo(g); foo(h); foo(i); foo(j); foo(k); foo(l);
    foo(m);

    #undef foo

    std::vector<uint8_t> buf;
    oarchive ar(buf);
    EXPECT_THROW(ar.left(),std::runtime_error);
    ar & a & b &c &d &e &f &g &h & i & j & k & l & m & p;
    std::vector<uint8_t> buf2 = a_ + b_ + c_ + d_ + e_ + f_ + g_ + h_ + i_ + j_ + k_ + l_ + m_ + p_;
    EXPECT_EQ(buf,buf2);
    EXPECT_THROW(ar.left(),std::runtime_error);
}
TEST_F(archive_test, write_primitives_2)
{
    std::vector<uint8_t> buf;
    oarchive ar(buf);
    std::vector<uint8_t> buf2;
    oarchive ar2(buf2);
    EXPECT_THROW(ar.left(),std::runtime_error);
    ar & a & b &c &d &e &f &g &h & i & j &k & l & m & p;
    EXPECT_THROW(ar.left(),std::runtime_error);
    ar2 << a << b << c << d << e << f << g << h << i << j << k << l << m << p;
    EXPECT_EQ(buf,buf2);
}

template<typename T>
void eof_test(T & x)
{
    std::vector<uint8_t> buf;
    oarchive ar(buf);
    ar & x;

    for (unsigned i = 1; i < buf.size() && i < 4; ++i)
    {
        iarchive ar2(&buf[0],buf.size()-i);
        EXPECT_THROW(ar2 & x, archive::error_eof);
    }
}
TEST_F(archive_test,eof_test)
{
    #define foo(x) eof_test(x)
    foo(a); foo(b); foo(c); foo(d); foo(e); foo(f);
    foo(g); foo(h); foo(i); foo(j); foo(k); foo(l); foo(m); foo(p);
    #undef foo
}

TEST_F(archive_test,raw_test)
{
    for (unsigned i = 0x1; i < 10; ++i)
    {
        std::vector<uint8_t> in_buf(i,0x1);
        for (unsigned j = 0; j < i; ++j)
        {
            in_buf[j] = rand()&0xff;
        }

        iarchive ar(&in_buf[0],in_buf.size());
        EXPECT_EQ(ar.left(), in_buf.size());

        std::vector<uint8_t> out_buf;
        ar.raw(out_buf);
        ASSERT_EQ(out_buf,in_buf);

        out_buf.clear();
        oarchive ar2(out_buf);
        ar2.raw(in_buf);
        ASSERT_EQ(in_buf, out_buf);
    }
}

TEST_F(archive_test,read_primitives)
{
    archive_test_values values;

    // Save
    std::vector<uint8_t> buf;
    oarchive ar(buf);
    ar & a & b &c &d &e &f &g &h & i & j &k & l&m  & p;

    // Munge
    a++; b++; c++; d[0]++;d[3]++;d[2]++;d[1]++;e.clear();f[0]++;g[0]++;h.clear();
    i[0]++;j[0]++;k[0]++;l[0]++;m.val++;p++;

    // Load
    iarchive ar2(&buf[0], buf.size());
    EXPECT_EQ(ar2.size(),0);
    EXPECT_EQ(ar2.left(),buf.size());
    ar2 & a & b & c & d & e;
    EXPECT_EQ(ar2.size(),a_.size()+b_.size()+c_.size()+d_.size()+e_.size());
    EXPECT_EQ(ar2.left(),f_.size()+g_.size()+h_.size()+i_.size()+j_.size()+k_.size()+l_.size()+m_.size() + p_.size());
    ar2 & f & g & h & i & j & k & l & m & p;
    EXPECT_EQ(ar2.size(),buf.size());
    EXPECT_EQ(ar2.left(),0);

    // Check it works
    #define foo(x) \
    {                             \
        EXPECT_EQ(this->x,values.x); \
    }
    #define foo2(x) \
    {                             \
        EXPECT_TRUE(0 == memcmp(this->x,values.x,sizeof(this->x))); \
    }
    foo(a); foo(b); foo(c); foo2(d); foo(e); foo2(f);
    foo2(g); foo(h); foo(i); foo(j); foo(k); foo(l); foo(m); foo(p);

    #undef foo
    EXPECT_THROW(ar2 & a, archive::error_eof);
    EXPECT_THROW(ar2 & b, archive::error_eof);
}


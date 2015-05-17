// ECC DH Testing
// http://csrc.nist.gov/groups/STM/cavp/documents/components/ecccdhvs.pdf
//

#include "ecdh.h"
#include "test_helpers.hpp"
#include <fstream>
#include <random.h>

struct ecdh_test_case
{
    ecdh_test_case() {}

    std::vector<uint8_t> pub_key_x;
    std::vector<uint8_t> pub_key_y;

    std::vector<uint8_t> priv_key;
    std::vector<uint8_t> pub_key_2_x;
    std::vector<uint8_t> pub_key_2_y;

    std::vector<uint8_t> shared_secret;

    std::string mode;
};

class ECDHVisitor
{
public:
    void visit(std::string const& lhs, std::string const& rhs)
    {
        if (lhs == "QCAVSx")
        {
            pub_key_x = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "QCAVSy")
        {
            pub_key_y = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "dIUT")
        {
            priv_key = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "QIUTx")
        {
            pub_key_2_x = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "QIUTy")
        {
            pub_key_2_y = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "ZIUT")
        {
            shared_secret = convert_from_hex(rhs.c_str());
        }

        if (shared_secret.size() > 0)
        {
            ecdh_test_case new_case;
            new_case.pub_key_x = pub_key_x;
            new_case.pub_key_y = pub_key_y;
            new_case.priv_key  = priv_key;
            new_case.pub_key_2_x = pub_key_2_x;
            new_case.pub_key_2_y = pub_key_2_y;
            new_case.shared_secret = shared_secret;
            new_case.mode = mode;
            cases.push_back(new_case);

            shared_secret.clear();
            pub_key_x.clear();
            pub_key_y.clear();
            priv_key.clear();
            pub_key_2_x.clear();
            pub_key_2_y.clear();
        }
    }

    void visit_mode(std::string const& mode_)
    {
        mode = mode_;
    }

    std::vector<ecdh_test_case> get_cases() const { return cases; }

private:
    std::string mode;

    std::vector<uint8_t> pub_key_x;
    std::vector<uint8_t> pub_key_y;

    std::vector<uint8_t> priv_key;
    std::vector<uint8_t> pub_key_2_x;
    std::vector<uint8_t> pub_key_2_y;

    std::vector<uint8_t> shared_secret;

    std::vector<ecdh_test_case> cases;
};



class ecdh_test : public testing::Test 
{
public:
    void SetUp()
    {
        test_cases = load_cases<ECDHVisitor,ecdh_test_case>("test_vectors/KAS_ECC/KAS_ECC_CDH_PrimitiveTest.txt",1000);
    }

    std::vector<struct ecdh_test_case> test_cases;
};

void run_test_case(struct ecdh_test_case const& case_, MinTLS_NamedCurve curve)
{
    size_t const key_sz = mintls_ecdh_scalar_size(curve);

    ASSERT_EQ(mintls_ecdh_point_size(curve),2*key_sz+1);
    ASSERT_EQ(case_.priv_key.size(), key_sz);

    // Calculate Public Key from Private Key
    uint8_t public_point[2*key_sz+1];
    ASSERT_EQ(
        mintls_ecdh_base_scalar_mult(
            curve,                  // (I) Curve
            &case_.priv_key[0],     // (I) Private Key
            case_.priv_key.size(),  // (I) Private Key Size
            public_point            // (O) Public Key
        ),
        0
    );

    // Check that the Public Key matches the known answer
    EXPECT_EQ(public_point[0],0x04);
    std::vector<uint8_t> pub_key_2_x(public_point+1,public_point+1+key_sz);
    std::vector<uint8_t> pub_key_2_y(public_point+1+key_sz,public_point+1+2*key_sz);
    std::ostringstream oss; oss << case_.priv_key;
    EXPECT_EQ(case_.pub_key_2_x, pub_key_2_x) << "secret_key=" << oss.str();
    EXPECT_EQ(case_.pub_key_2_y, pub_key_2_y);

    // Encode the other public key
    std::vector<uint8_t> public_point_2(2*key_sz+1);
    public_point_2[0] = 0x04;
    memcpy(&public_point_2[1],&case_.pub_key_x[0],key_sz);
    memcpy(&public_point_2[1+key_sz],&case_.pub_key_y[0],key_sz);

    // Computer the shared secret, by multiplying private and public key
    std::vector<uint8_t> shared_point(2*key_sz+1);
    ASSERT_EQ(
        mintls_ecdh_scalar_mult(
            curve,                  // (I) Curve
            &case_.priv_key[0],     // (I) Scalar (big endian using [5] 4.3.3)
            case_.priv_key.size(),  // (I) Scalar size
            &public_point_2[0],     // (I) Base point (uncompressed using [5] 4.3.6)
            public_point_2.size(),  // (I) Base point size
            &shared_point[0]        // (O) Point (uncompressed using [5] 4.3.6)
        ),
        0
    );

    // Compare shared secret with known answer
    shared_point = std::vector<uint8_t>(shared_point.begin()+1,shared_point.begin()+1+key_sz);
    EXPECT_EQ(case_.shared_secret, shared_point);
}

TEST_F(ecdh_test, ecdh_test)
{
    int iRan=0;
    for (unsigned i = 0; i < test_cases.size(); ++i)
    {
        struct ecdh_test_case const& case_ = test_cases[i];

        ASSERT_TRUE(!case_.mode.empty());

        if (case_.mode == "P-224")
        {
            iRan++;
            run_test_case(case_,mintls_secp224r1);
        }
        else if (case_.mode == "P-256")
        {
            iRan++;
            run_test_case(case_, mintls_secp256r1);
        }
    }
}

TEST_F(ecdh_test, p224_sizes)
{
    ASSERT_EQ(mintls_ecdh_scalar_size(mintls_secp224r1),224/8);
    ASSERT_EQ(mintls_ecdh_point_size(mintls_secp224r1),224/8*2+1);
}

TEST_F(ecdh_test, p256_sizes)
{
    ASSERT_EQ(mintls_ecdh_scalar_size(mintls_secp256r1),256/8);
    ASSERT_EQ(mintls_ecdh_point_size(mintls_secp256r1),256/8*2+1);
}

// Check that the base point scalar multiple routine matches the generic base point routine
void base_point_test(MinTLS_NamedCurve curve)
{
    size_t const key_sz = mintls_ecdh_scalar_size(curve);
    size_t const pt_sz  = mintls_ecdh_point_size(curve);

    // Scalar representing 1 (in big endian)
    std::vector<uint8_t> one(key_sz,0);
    one[key_sz-1] = 1;

    // Extract out the base point
    std::vector<uint8_t> base_point(pt_sz);
    ASSERT_EQ(
        mintls_ecdh_base_scalar_mult(
            curve,          // (I) Curve
            &one[0],        // (I) Private Key
            one.size(),     // (I) Private Key size
            &base_point[0]  // (O) Public Key
        ),
        0
    );

    // Computer scalar multiple in two ways
    std::vector<uint8_t> scalar(key_sz,0);
    mintls_random(&scalar[0], key_sz);

    std::vector<uint8_t> point1(pt_sz);
    std::vector<uint8_t> point2(pt_sz);
    ASSERT_EQ(
        mintls_ecdh_base_scalar_mult(
            curve,          // (I) Curve
            &scalar[0],     // (I) Private Key
            scalar.size(),  // (I) Private Key Size
            &point1[0]      // (O) Public Key
        ),
        0
    );

    ASSERT_EQ(
        mintls_ecdh_scalar_mult(
            curve,              // (I) Curve
            &scalar[0],         // (I) Scalar (big endian using [5] 4.3.3)
            scalar.size(),      // (I) Scalar size
            &base_point[0],     // (I) Base point (uncompressed using [5] 4.3.6)
            base_point.size(),  // (I) Base point size
            &point2[0]          // (O) Point (uncompressed using [5] 4.3.6)
        ),
        0
    );

    EXPECT_EQ(point1,point2);
}

TEST_F(ecdh_test, p224_base_point_test)
{
    base_point_test(mintls_secp224r1);
}

TEST_F(ecdh_test, p256_base_point_test)
{
    base_point_test(mintls_secp256r1);
}



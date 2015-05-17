#include "tls/tls_handshake.hpp"
#include "test_helpers.hpp"
#include "test_main.hpp"

struct sub_case
{
    const char *            plaintext;
    uint64_t                seq_num;
    const char *            encrypted_record;
};

struct test_case
{
    CipherSuite             cipher;
    ContentType             type;
    const char *            key;
    const char *            mac_key;
    size_t                  num_sub_cases;
    struct sub_case         sub_cases[6];
};

// Taken from gnutls-cli
struct test_case test_cases[] = 
{
    // Simple test
    {
        CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA,
        ContentTypes::ApplicationData,
        "4c3d768b7abacbdd68855c866a322294",
        "82cf58a1f8ea56cb6b7d5e893a0ee1a66e99e8fe",
        6,
        {
            {
                "a\n",
                1,
                "17030300303dea1696c47cde34911634d7199eaebea176bce4c3d44f878f1b748835bb78e16fb4ca1d991f5559f3322929726744da"
            },
            {
                "aaaaaaaaaa\n",
                2,
                "1703030030bd3bce0c74ea7acc4004f9a4127c530ae91ea94128841189c18ced88e62f7b9f0aa9ceb92b651b6676e5795fb4f8b0c9"
            },
            {
                "aaaaaaaaaaa\n",
                3,
                "1703030040ad91f6d3f1a0d6d808f2f5bae1ce6b63df994bb64206ce6617e1cda12aa3dee001a3038a653d1dabab98ee7247ad504f4869915fb43313da19acd58c4f6e28af"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                4,
                "170303004079b325f8377164c9eaefcf213c015148a7fc199b080edddf424a7d58a55920ffa1ad736faba29c2204af5947f65ebb503931dbf75b7c17cf90ad1a981f49dcc5"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                5,
                "17030300500a13f69a4bd59d36dba563bf541ee20425d97081c4db9d5fa8cd702efd1ec233535dd072058b32d6708e4c985d37eabbac9d97623ffa0b9734ebeea0c4edbb847e602f8c7f59a1626bdc47cb1a6ab259"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                6,
                "17030300903982a01e4e3b4fa898b961e20b74c8601d9780f6345a7c8fc67294a0108a8ade68f3e68f4b38c8e4cd8a140f098f74dbfd9aea18e42ab2e41d7327e1340fbcd9da3a474d25b347e01d78757ef2a885ed554a292c9f30dff08298c0c27c22316eb553e51094f00a642f99d7b8db679b38f68eea2fd5494bdf44c2d97a8a2e0b1d35f39b65cee01b711701a7b0f8aff39d"
            },
        }
    },
    {
        CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA256,
        ContentTypes::ApplicationData,
        "ff7f920f103115132ce7934c7fde083b",
        "7045d39a016dab4e3de075de16c0d33c452ca49ce0b0ea17f25653f0128c5a95",
        6,
        {
            {
                "a\n",
                1,
                "1703030040645fb6d1d96b9d27dfe59f2ade52afe2697e2861b132fde565e3c083c7888bb4d3cac73e22336554003b55eae6b06cee9f70089c419773c106bddfeb46ec694d"
            },
            {
                "aaaaaaaaaaaaaa\n",
                2,
                "1703030040f49d68beca877738032a770b48c635f8ee1e3908bf218ba0b3912b88df34dc8402b41771cafd0ccc8539aae6378fd09a0ad5db3fbb3c0759fed6abc2448351a6"
            },
            {
                "aaaaaaaaaaaaaaa\n",
                3,
                "17030300509437026f1b0710c059a5923ebde70a743bd9921cc93aebf002520cedacd1e434e13ef806cb7f26b20e56ce83964317fe8c95370a092b53b066ec48b324ab19bdc556ad79ca7f84e5e31a8b4eb91bdc49"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                4,
                "17030300508623e6f2c2810fc9d0c8dca7556a273863fffbf8f288c074b961a9f819888895441da17d68ec4a74a5c98412db59581f4a027fe1fe6649ac6e3ec82c1e0356258ee0b2efff7df587f88c90914b5e54b8"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                5,
                "1703030060a7e99cad8f32ea6af7bc01d9f43e901c5137b17f3d658ca0b71d0ef1b871c01925065c0b260c57b43fee0734a1b9eb45d63f167790f33b3f3ac509c64b3038c97f2beab03327d7b0fac3ffc9eaf9bf431f5b5eca49ab439030cf45639c5bcdd0"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                6,
                "17030300a03d6308a0cb7fcf706e8e59216182ed942ae20ffa5c07ccf504159e7b7ea3e0161fd4195103f766660517765b61578bf7e4c2a50468e65a3f2ba1ff6eb4745a786091a9c6203f480e02b67ec6cae46f59a10777031d91e510d58e33069d2932d067c503f1f9c3cfd06496b62f6acff7a5573b4c4052ede1fa430eaebc10e3f5322a39f9c12979d1a2b1d869edf88dc214b986bb2d4b4eccef452898c71e9159eb"
            },
        }
    },
    {
        CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA,
        ContentTypes::ApplicationData,
        "5a64da23e1c12e7d0aecaf934b483497cd3d82ce9af070068f9f82d751689e2a",
        "e70079401522bbe974b1787cc3c5209603c8b9d6",
        6,
        {
            {
                "a\n",
                1,
                "1703030030f5b7929cc20449fd3da1a341ea9b72c9079691cd6410ff14e6f3fc6808e2867e3274d72c699dd300f91e9d9f367428f9"
            },
            {
                "aaaaaaaaaa\n",
                2,
                "1703030030af7aff508e69fed74d19785496d6741e18819cfc36e254ff57eef5db92ccf0dce13c4a77a8e6ffdaafe8b9c8bf0ba048"
            },
            {
                "aaaaaaaaaaa\n",
                3,
                "17030300401b62967afc9a85953cc0293f09361360be0ce979bf3ef88a1bd1cde9a1772a81de856255c9c59816e4e95a8c34c5ed22a28a8e57a5f0761783ea2aafe52a3fbd"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                4,
                "1703030040b6c351c432711ebc076bc42336307a1828b5550a1b66037d07131db960ea085708898c5a2ce6909c51a184dba4bde15b32a6f547c07393d5c1acdae2dee9fa39"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                5,
                "17030300504d2c7902446da0131b1b4645f3c5cef1b46b5babdf0429a61b86e2fdc3f23cd51c547464f02ab5ac406af5586089278dbf62ebd0b97a2c83c1f588ceb5cd12d5ebc19c9ccf77a1c2a3947885f9fa4ed0"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                6,
                "17030300902a6f99abf5e96ad550a1ebc26fcabad7c3acfe7fb2a6331955484ad345418dfff6a12ce9eb9239fa2ea44f189bd7a12b5d6032ecb7bbd69e65abb39293ce08d29897b28f45ffb19aa81ec530bf5cc19fbe36677a10a7e60d7152c9c6a2113815fd32f01591c9253fd60190d5c06b07edefb6416e0c8d7d98105ea7c9302b5a07ce98efc495776b8197443d9cbf3eea33"
            },
        }
    },
    {
        CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA256,
        ContentTypes::ApplicationData,
        "3e571006fe86991859960df5758225caacaf425626dd8e76729728d5cc137b08",
        "35832954f9c76a6e96d46d4865d507af62587c7405add57c908fe3eae29643c5",
        6,
        {
            {
                "a\n",
                1,
                "170303004019685e2949e8620ffe86fe9190d69fee4dc67d8c161490b85ba09048396a1b34298d49973d1b24306e35f550068767d1d96e6bc0bf25b15bd99a30dd2dd869e8"
            },
            {
                "aaaaaaaaaaaaaa\n",
                2,
                "1703030040ed8b7cb973066a3288f2207bf24c89cb2afc1335fe84099bcceb3b640d554cc204eeb9284d384224ccf0f88e70d61e61aee1856e7884dace4d2d8c6502e5bef2"
            },
            {
                "aaaaaaaaaaaaaaa\n",
                3,
                "17030300509b2ab47b8be3389c3b0a4ed9961c84e16df90b1e43fc4ff2dbf0a190a3a3daf77d5483ded7755c1214e23d7559d4f57eaecef16fa6b6798ad1d3e1c4ac62195ca8aba96df7f837ee6d18108bdf1d0c21"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                4,
                "17030300507b3c5e60e3b7d118ed1e736fde54452a0de556162255562d502d27b1b42c6803c67dbacb753c480fe7b97a9c00a9319624df795b325981d41b3e7b90ae54e28fd7c96b4a0b9eb24065503aa1b686be0c"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                5,
                "1703030060de00f1dca20f334c5f89a8cbfb989e5f6bc4c119e7486db20fa308a83091bf51cb1d50dff47f45d50c9fc825a04e97eb7f506b07ede379646f0abd6ac3a8219a95d743de0c8e9f1af117cd982426167144514f8ea5d5deb15a3403b29a2b5913"
            },
            {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                6,
                "17030300a01ab2fdaccacbc5f9d3e144fa3e275a6d18cc936abacd51f71ff9edf6e62fae77c8762c17c100c0d12070f3082aa2eb0a0060a648ae123af749b72752634ee6a34b428481394198bc942e3f419bba1f50f92e7a2f8684a52e23b370d599c1db9a921fbed463fc881e15a395f64e4a2539762a6831dcf1479bb66905e245c4fba7479cf966d7ef35713fb988a0d7c75eeec9d9838c5a5cfbd6f6887aadc28cfc32"
            },
        }
    },
};

std::vector<struct test_case> expand_test_cases(struct test_case *begin, struct test_case *end)
{
    std::vector<struct test_case> cases;

    struct test_case *it;
    for (it = begin; it != end; ++it)
    {
        struct test_case const& case_ = *it;
        for (unsigned i = 0; i < case_.num_sub_cases; ++i)
        {
            struct test_case this_case = case_;
            this_case.num_sub_cases = 1;
            this_case.sub_cases[0] = case_.sub_cases[i];
            cases.push_back(this_case);
        }
    }
    return cases;
}

std::vector<struct test_case> const& expanded_test_cases()
{
    static std::vector<struct test_case> s_cases;
    if (s_cases.empty())
    {
        s_cases = expand_test_cases(test_cases,test_cases+sizeof(test_cases)/sizeof(struct test_case));
    }
    return s_cases;
}


void encryption_test_tls12(struct test_case const& case_)
{
    TLSProtocolVersion version(3,3);

    for (unsigned iSubCase = 0; iSubCase < case_.num_sub_cases; ++iSubCase)
    {
        struct sub_case const& sub_case = case_.sub_cases[iSubCase];
        std::vector<uint8_t> pt(sub_case.plaintext,sub_case.plaintext+strlen(sub_case.plaintext));
        std::vector<uint8_t> key= convert_from_hex(case_.key);
        std::vector<uint8_t> mac_key= convert_from_hex(case_.mac_key);
        std::vector<uint8_t> rec = convert_from_hex(sub_case.encrypted_record);
        std::vector<uint8_t> IV(rec.begin()+5,rec.begin()+5+16);

        std::vector<uint8_t> rec2;
        mintls_error err =
        TLSRecord::write_encrypted_record(
            rec2,           // (O) Buffer to append to
            sub_case.seq_num,  // (I) Sequence number
            case_.type,     // (I) Content Type
            version,        // (I) Version
            case_.cipher,   // (I) Cipher
            IV,             // (I) IV
            key,            // (I) Key
            mac_key,        // (I) MAC key
            pt              // (I/O) plaintext
        );
        EXPECT_EQ(err, mintls_success);
        EXPECT_EQ(rec2,rec);
    }
}

void decryption_test_tls12(struct test_case const& case_)
{
    TLSProtocolVersion version(3,3);

    for (unsigned iSubCase = 0; iSubCase < case_.num_sub_cases; ++iSubCase)
    {
        struct sub_case const& sub_case = case_.sub_cases[iSubCase];
        std::vector<uint8_t> pt2(sub_case.plaintext,sub_case.plaintext+strlen(sub_case.plaintext));
        std::vector<uint8_t> key= convert_from_hex(case_.key);
        std::vector<uint8_t> mac_key= convert_from_hex(case_.mac_key);
        std::vector<uint8_t> ct = convert_from_hex(sub_case.encrypted_record);
        std::vector<uint8_t> IV(ct.begin()+5,ct.begin()+5+16);

        std::vector<uint8_t> pt;
        ContentType type;
        mintls_error err =
        TLSRecord::decrypt_record(
            pt,                 // (O) Plaintext
            sub_case.seq_num,   // (I) Sequence Number
            type,               // (O) Content type
            version,            // (I) Version
            case_.cipher,       // (I) Cipher
            key,                // (I) Key
            mac_key,            // (I) MAC key
            ct                  // (I) Ciphertext
        );
        EXPECT_EQ(type,case_.type);
        EXPECT_EQ(err, mintls_success);
        EXPECT_EQ(pt,pt2);
    }
}

TEST(tls_record_test,encryption_test_tls12_aes128_cbc_sha160)
{
    encryption_test_tls12(test_cases[0]);
}

TEST(tls_record_test,encryption_test_tls12_aes128_cbc_sha256)
{
    encryption_test_tls12(test_cases[1]);
}

TEST(tls_record_test,encryption_test_tls12_aes256_cbc_sha160)
{
    encryption_test_tls12(test_cases[2]);
}

TEST(tls_record_test,encryption_test_tls12_aes256_cbc_sha256)
{
    encryption_test_tls12(test_cases[3]);
}

TEST(tls_record_test,decryption_test_tls12_aes128_cbc_sha160)
{
    decryption_test_tls12(test_cases[0]);
}

TEST(tls_record_test,decryption_test_tls12_aes128_cbc_sha256)
{
    decryption_test_tls12(test_cases[1]);
}

TEST(tls_record_test,decryption_test_tls12_aes256_cbc_sha160)
{
    decryption_test_tls12(test_cases[2]);
}

TEST(tls_record_test,decryption_test_tls12_aes256_cbc_sha256)
{
    decryption_test_tls12(test_cases[3]);
}


//////
//
// Tests for decryption validation
//
class decryption_validation_test : public ::testing::Test
{
public:
    void SetUp()
    {
        test_cases = expanded_test_cases();
    }

    std::vector<struct test_case> test_cases;

    void SetUpCase(struct test_case const& case_)
    {
        version = TLSProtocolVersion(3,3);
        struct sub_case const& sub_case = case_.sub_cases[0];
        seq_num = sub_case.seq_num;
        pt.assign(sub_case.plaintext,sub_case.plaintext+strlen(sub_case.plaintext));
        key= convert_from_hex(case_.key);
        mac_key= convert_from_hex(case_.mac_key);
        ct = convert_from_hex(sub_case.encrypted_record);
        IV.assign(ct.begin()+5,ct.begin()+5+16);
        cipher_suite      = case_.cipher;
        cipher = CipherSuites::cipher(case_.cipher);
        mode        = MinTLS_CBC;
        block_sz    = mintls_cipher_block_length(cipher,mode);
        mac_algo = CipherSuites::mac_algorithm(case_.cipher);
        hmac_version = MACAlgorithms::hmac_version(mac_algo);
        mac_sz = mintls_hash_tag_length(hmac_version);
        type = case_.type;
    }

    TLSProtocolVersion version;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> key;
    std::vector<uint8_t> mac_key;
    std::vector<uint8_t> ct;
    std::vector<uint8_t> IV;
    CipherSuite cipher_suite;
    MinTLS_Cipher cipher;
    MinTLS_CipherMode mode;
    uint8_t block_sz;
    uint64_t seq_num;
    MACAlgorithm mac_algo;
    MinTLS_Hash hmac_version;
    size_t mac_sz;
    ContentType type;
};

// Some input validtaion
TEST_F(decryption_validation_test, record_too_small)
{
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        SetUpCase(test_cases[iCase]);
        for (unsigned i = 0; i < TLSRecord::header_sz + 16*2 - 1; ++i)
        {
            std::vector<uint8_t> ct2(i);
            TLSRecord::write_header(&ct2[0],ContentTypes::ApplicationData,TLSProtocolVersion(3,3),i-TLSRecord::header_sz);
            std::vector<uint8_t> pt2;
            ContentType type;
            mintls_error err =
            TLSRecord::decrypt_record(
                pt2,                // (O) Plaintext
                seq_num,            // (I) Sequence Number
                type,               // (O) Content type
                version,            // (I) Version
                cipher_suite,       // (I) Cipher Suite
                key,                // (I) Key
                mac_key,            // (I) MAC key
                ct2                 // (I) Ciphertext
            );
            EXPECT_EQ(err,mintls_err_decode_error);
            EXPECT_EQ(pt2.size(),0);
        }
    }
}

// Some more input validation
TEST_F(decryption_validation_test, invalid_key_size)
{
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        SetUpCase(test_cases[iCase]);
        // Invalid key size
        for (unsigned i = 0; i < 35; ++i)
        {
            std::vector<uint8_t> key(i);
            if (i == mintls_cipher_key_length(CipherSuite::cipher(cipher_suite)))
                continue;
            std::vector<uint8_t> pt2;
            ContentType type;
            mintls_error err =
            TLSRecord::decrypt_record(
                pt2,                // (O) Plaintext
                seq_num,            // (I) Sequence Numbers
                type,               // (O) Content type
                version,            // (I) Version
                cipher_suite,       // (I) Cipher Suite
                key,                // (I) Key
                mac_key,            // (I) MAC key
                ct                  // (I) Ciphertext
            );
            EXPECT_EQ(err,mintls_err_internal_error);
            EXPECT_EQ(pt2.size(),0);
        }
    }
}

// Check we return error when the MAC is invalid
TEST_F(decryption_validation_test, invalid_mac)
{
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        SetUpCase(test_cases[iCase]);
        for (unsigned i = 0; i < mac_key.size(); ++i)
        {
            std::vector<uint8_t> pt2 = pt;
            std::vector<uint8_t> mac_key_2(mac_key);
            mac_key_2[i] ^= 0x3f;
            std::vector<uint8_t> ct2;
            mintls_error err =
            TLSRecord::write_encrypted_record(
                ct2,            // (O) Buffer to append to
                seq_num,        // (I) Sequence number
                type,           // (I) Content Type
                version,        // (I) Version
                cipher_suite,       // (I) Cipher Suite
                IV,             // (I) IV
                key,            // (I) Key
                mac_key_2,      // (I) MAC key
                pt2             // (I/O) plaintext
            );
            EXPECT_EQ(mintls_success, err);

            std::vector<uint8_t> pt3;
            ContentType type;
            err =
            TLSRecord::decrypt_record(
                pt3,                // (O) Plaintext
                seq_num,            // (I) Sequence Number
                type,               // (O) Content type
                version,            // (I) Version
                cipher_suite,       // (I) Cipher Suite
                key,                // (I) Key
                mac_key,            // (I) MAC key
                ct2                 // (I) Ciphertext
            );
            EXPECT_EQ(err,mintls_err_bad_record_mac);
            EXPECT_EQ(pt3.size(),0);
        }
    }
}

// Check we return error when the padding is invalid
TEST_F(decryption_validation_test, invalid_padding)
{
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        SetUpCase(test_cases[iCase]);
        // Work out the padding for this test
        uint8_t padding_sz = block_sz - ((mac_sz + pt.size()) % block_sz);
        // Try with invalid padding
        for (unsigned i = 0; i < padding_sz+1; ++i)
        {
            std::vector<uint8_t> padding; padding.resize(padding_sz, padding_sz-1);
            if (i > 0)
              padding[i-1] = 0x1f;

            std::vector<uint8_t> ct2,pt2(pt);
            mintls_error err =
            TLSRecord::write_encrypted_record(
                ct2,            // (O) Buffer to append to
                seq_num,        // (I) Sequence number
                type,           // (I) Content Type
                version,        // (I) Version
                cipher_suite,   // (I) Cipher Suite
                IV,             // (I) IV
                key,            // (I) Key
                mac_key,        // (I) MAC key
                pt2,            // (I/O) plaintext
                &padding        // (I) Padding
            );
            ASSERT_EQ(mintls_success, err);

            std::vector<uint8_t> pt3;
            ContentType type;
            err =
            TLSRecord::decrypt_record(
                pt3,                // (O) Plaintext
                seq_num,            // (I) Sequence Number
                type,               // (O) Content type
                version,            // (I) Version
                cipher_suite,       // (I) Cipher Suite
                key,                // (I) Key
                mac_key,            // (I) MAC key
                ct2                 // (I) Ciphertext
            );
            if (i == 0)
            {
                EXPECT_EQ(mintls_success, err);
            }
            else
            {
                EXPECT_EQ(mintls_err_bad_record_mac, err);
                EXPECT_EQ(0,pt3.size()) << " i=" << i;
            }
        }
    }
}

TEST(tls_record_test,encryption_validation)
{
    TLSProtocolVersion version(3,3);
    struct test_case const& case_ = test_cases[0];
    struct sub_case const& sub_case = case_.sub_cases[0];
    std::vector<uint8_t> pt(sub_case.plaintext,sub_case.plaintext+strlen(sub_case.plaintext));
    std::vector<uint8_t> key= convert_from_hex(case_.key);
    std::vector<uint8_t> mac_key= convert_from_hex(case_.mac_key);
    std::vector<uint8_t> rec = convert_from_hex(sub_case.encrypted_record);
    std::vector<uint8_t> IV(15);

    std::vector<uint8_t> rec2;
    mintls_error err =
    TLSRecord::write_encrypted_record(
        rec2,           // (O) Buffer to append to
        sub_case.seq_num,  // (I) Sequence number
        case_.type,     // (I) Content Type
        version,        // (I) Version
        case_.cipher,   // (I) Cipher
        IV,             // (I) IV
        key,            // (I) Key
        mac_key,        // (I) MAC key
        pt              // (I/O) plaintext
    );
    EXPECT_EQ(err, mintls_err_internal_error);
    EXPECT_EQ(rec2.size(),0);

    IV.resize(16);
    key.resize(key.size()-1);
    err =
    TLSRecord::write_encrypted_record(
        rec2,           // (O) Buffer to append to
        sub_case.seq_num,  // (I) Sequence number
        case_.type,     // (I) Content Type
        version,        // (I) Version
        case_.cipher,   // (I) Cipher
        IV,             // (I) IV
        key,            // (I) Key
        mac_key,        // (I) MAC key
        pt              // (I/O) plaintext
    );
    EXPECT_EQ(err, mintls_err_internal_error);
    EXPECT_EQ(rec2.size(),0);
}

TEST(tls_record_test,plaintext_test)
{
    struct dummy : public TLSPlaintext
    {
        dummy(std::vector<uint8_t> my_buf_) : my_buf(my_buf_) {}

        virtual void
        write_payload(
                std::vector<uint8_t>&   buf          // (O) Buffer to append to
        ) const
        {
            buf.insert(buf.end(),my_buf.begin(),my_buf.end());
        }

        virtual ContentType
        content_type() const
        {
            return (ContentType)0x42;
        }

        std::vector<uint8_t> my_buf;
    };

    dummy a1(std::vector<uint8_t>(5,'a'));
    std::vector<uint8_t> send_buf(6,'b');
    TLSRecord::write_plaintext_record(send_buf, TLSProtocolVersion(), a1);

    EXPECT_EQ(send_buf.size(), 6 + TLSRecord::header_sz + a1.my_buf.size());
    std::vector<uint8_t> header;
    TLSRecord::write_header(header, (ContentType)0x42, TLSProtocolVersion(), a1.my_buf.size());
    EXPECT_EQ(send_buf, std::vector<uint8_t>(6,'b') + header + a1.my_buf);
};

TEST(tls_record_test,read_write_header)
{
    struct test_case
    {
        const char *            buf;
        size_t                  buf_sz;
        mintls_error            err;
        ContentType             type;
        TLSProtocolVersion      version;
        size_t                  msg_sz;
    };

    struct test_case cases[] = {
        {"\x01", 1, mintls_err_decode_error, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x01\x02", 2, mintls_err_decode_error, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x01\x02\x03", 3, mintls_err_decode_error, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x01\x02\x03\x04", 4, mintls_err_decode_error, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x01\x02\x03\x04\x05", 5, mintls_err_unexpected_message, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x14\x02\x03\x04\x05", 5, mintls_err_unexpected_message, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x14\x03\x02\x40\x01", 5, mintls_err_record_overflow, ContentTypes::UnknownRecord, TLSProtocolVersion(), 0},
        {"\x15\x03\x03\x40\x00", 5, mintls_success, ContentTypes::Alert, TLSProtocolVersion(3,3), 0x4000},
        {"\x16\x03\x01\x02\x41", 5, mintls_success, ContentTypes::Handshake, TLSProtocolVersion(3,1), 0x241},
    };

    for (int iCase = 0; iCase < sizeof(cases)/sizeof(struct test_case); ++iCase)
    {
        struct test_case const& case_ = cases[iCase];

        std::vector<uint8_t> buf((uint8_t const *)case_.buf,(uint8_t const*)case_.buf+case_.buf_sz);

        ContentType         type(ContentTypes::UnknownRecord);
        TLSProtocolVersion  version(3,3);
        size_t              msg_sz(1024);
        mintls_error        err(mintls_success);

        err = TLSRecord::read_header(
            buf,
            type,
            version,
            msg_sz
        );

        #define compare_member(x) \
        {                             \
            EXPECT_EQ(case_.x,x); \
        }
        compare_member(err);
        compare_member(type);
        compare_member(version);
        compare_member(msg_sz);
        #undef compare_member

        if (case_.err == mintls_success)
        {
            std::vector<uint8_t> buf2;
            mintls_error err =
            TLSRecord::write_header(buf2, case_.type, case_.version, case_.msg_sz);
            EXPECT_EQ(err,mintls_success) << " case " << iCase;
            EXPECT_EQ(buf,buf2);
        }
        if (case_.err == mintls_success)
        {
            std::vector<uint8_t> buf2(5,0);
            mintls_error err =
            TLSRecord::write_header(buf2, case_.type, case_.version, case_.msg_sz);
            EXPECT_EQ(err,mintls_success) << " case " << iCase;
            EXPECT_EQ(buf,std::vector<uint8_t>(buf2.begin()+5,buf2.end()));
            EXPECT_EQ(std::vector<uint8_t>(buf2.begin(),buf2.begin()+5),std::vector<uint8_t>(5,0));
        }
    }

    std::vector<uint8_t> buf;
    EXPECT_EQ(TLSRecord::write_header(buf,ContentTypes::Handshake,TLSProtocolVersion(3,3),0x4001),mintls_err_record_overflow);
    EXPECT_EQ(buf.size(),0);
}


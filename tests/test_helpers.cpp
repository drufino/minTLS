#include "test_helpers.hpp"

bool is_hex(char p)
{
    if (p >= 'a' && p <= 'f')
        return true;
    if (p >= 'A' && p <= 'F')
        return true;
    if (p >= '0' && p <= '9')
        return true;
    return false;
}

std::ostream& operator<<(std::ostream & os, std::vector<uint8_t> const& x)
{
    for (unsigned i = 0; i < x.size(); ++i)
    {
        os << std::hex;
        if (x[i] <= 0x0f)
        {
            os << '0';
        }
        os << (int)x[i];
    }
    return os;
}

std::vector<uint8_t> convert_from_hex(char const *in)
{
    unsigned numdigits = 0;
    {
        char const *p = in;
        while (*p != '\x00' && is_hex(*p))
        {
            ++p;
            ++numdigits;
        }
    }

    unsigned n = numdigits/2;
    char hex_byte[8];
    std::vector<uint8_t> out(n);
    for (unsigned i = 0; i < n; ++i)
    {
        hex_byte[2] = '\0';
        hex_byte[0] = *in++;
        hex_byte[1] = *in++;
        out[i] = (unsigned char)(strtoul(hex_byte,NULL,16)&0xff);

    }
    return out;
}

// Called before a test starts.
void MinimalistPrinter::OnTestStart(const ::testing::TestInfo& test_info)
{
    printf("    Test %s.%s...\t\t", test_info.test_case_name(), test_info.name());
}

// Called after a failed assertion or a SUCCEED() invocation.
void MinimalistPrinter::OnTestPartResult(const ::testing::TestPartResult& test_part_result)
{
    printf("\n%s in %s:%d\n%s",
         test_part_result.failed() ? "*** Failure" : "Success",
         test_part_result.file_name(),
         test_part_result.line_number(),
         test_part_result.summary());
}

// Called after a test ends.
void MinimalistPrinter::OnTestEnd(const ::testing::TestInfo& test_info)
{
    printf("\n");
}

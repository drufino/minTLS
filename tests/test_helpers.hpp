#ifndef test_helpers_hpp
#define test_helpers_hpp
#include <iostream>
#include <iomanip>
#include <cstring>
#ifndef _MSC_VER
#include <cxxabi.h>
#endif
#include <gtest/gtest.h>
#include <fstream>
#include <algorithm>
#include <stdint.h>

bool is_hex(char p);
std::ostream& operator<<(std::ostream & os, std::vector<uint8_t> const& x);
std::vector<uint8_t> convert_from_hex(char const *in);

#ifndef tf_tls_primitives_hpp
template<typename T>
std::vector<T> operator+(std::vector<T> const& lhs, std::vector<T> const& rhs)
{
    std::vector<T> ret = lhs;
    ret.reserve(ret.size() + rhs.size());
    std::copy(rhs.begin(),rhs.end(),std::back_inserter(ret));
    return ret;
}

template<typename T>
std::vector<T>& operator+=(std::vector<T> & lhs, std::vector<T> const& rhs)
{
    lhs.insert(lhs.end(),rhs.begin(),rhs.end());
    return lhs;
}
#endif

template<typename Visitor, typename T>
std::vector<T> load_cases(std::string const& fn, int max)
{
    Visitor visitor;

    std::ifstream in_file(fn.c_str());
    char buf[1024];

    for (;;)
    {
        buf[0] = buf[sizeof(buf)-1] = '\0';
		if (!in_file.getline(buf, sizeof(buf) - 1, '\n'))
			break;
        if (strlen(buf) == 0) continue;
        if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
            continue;

        if (buf[0] == '[')
        {
            std::string mode(buf+1);
            if (mode[mode.length()-1] == '\r' || mode[mode.length()-1] == '\n')
            {
                mode.resize(mode.length()-1);
            }
            if (mode[mode.length()-1] == ']')
            {
                mode.resize(mode.length()-1);
            }
            visitor.visit_mode(mode);
            continue;
        }
        char *c_equals = strchr(buf,'=');
        if (c_equals > buf)
        {
            *(c_equals - 1) = '\0';
            std::string lhs(buf);
            std::string rhs(c_equals+2);
            if (rhs[rhs.length()-1] == '\r' || rhs[rhs.length() -1] == '\n')
            {
                rhs.resize(rhs.length()-1);
            }
            visitor.visit(lhs,rhs);
        }
    }

    std::vector<T> cases = visitor.get_cases();
    size_t cnt = max < cases.size() ? max : cases.size();
    return std::vector<T>(cases.begin(),cases.begin()+cnt);
}

class MinimalistPrinter : public ::testing::EmptyTestEventListener
{
    // Called before a test starts.
    virtual void OnTestStart(const ::testing::TestInfo& test_info);

    // Called after a failed assertion or a SUCCEED() invocation.
    virtual void OnTestPartResult(const ::testing::TestPartResult& test_part_result);

    // Called after a test ends.
    virtual void OnTestEnd(const ::testing::TestInfo& test_info);
};

    template<typename T, size_t size>
    ::testing::AssertionResult ArraysMatch(const T (&expected)[size],
                                           const T (&actual)[size]){
        for (size_t i(0); i < size; ++i){
            if (expected[i] != actual[i]){
                return ::testing::AssertionFailure() << "array[" << i
                    << "] (" << actual[i] << ") != expected[" << i
                    << "] (" << expected[i] << ")";
            }
        }

        return ::testing::AssertionSuccess();
    }

#endif

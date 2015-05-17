#ifndef test_main_hpp
#define test_main_hpp
#include <iostream>
#include <cstring>
#include <gtest/gtest.h>

int
main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc,argv);
    if (argc > 1 && !strcmp(argv[1],"--quiet"))
    {
        ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
        delete listeners.Release(listeners.default_result_printer());
        listeners.Append(new MinimalistPrinter);
    }
    return RUN_ALL_TESTS();
}
#endif

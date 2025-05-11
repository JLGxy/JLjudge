
#include "gtest/gtest.h"
#include "judge_local.h"

TEST(compareFilename, int) {
    EXPECT_EQ(jlgxy::compare_strint("0", "0"), 0);
    EXPECT_EQ(jlgxy::compare_strint("0", "0"), 0);
    EXPECT_EQ(jlgxy::compare_strint("01", "01"), 0);
    EXPECT_EQ(jlgxy::compare_strint("00", "00"), 0);
    EXPECT_LT(jlgxy::compare_strint("01", "002"), 0);
    EXPECT_LT(jlgxy::compare_strint("001", "02"), 0);
    EXPECT_LT(jlgxy::compare_strint("00", "02"), 0);
    EXPECT_LT(jlgxy::compare_strint("00", "000"), 0);
}
TEST(compareFilename, str) {
    EXPECT_EQ(jlgxy::compare_filename("abc", "abc"), 0);
    EXPECT_LT(jlgxy::compare_filename("abc", "abd"), 0);
    EXPECT_GT(jlgxy::compare_filename("abd", "abc"), 0);
}
TEST(compareFilename, strint) {
    EXPECT_EQ(jlgxy::compare_filename("abc1", "abc1"), 0);
    EXPECT_LT(jlgxy::compare_filename("abc1", "abc2"), 0);
    EXPECT_GT(jlgxy::compare_filename("abc2", "abc1"), 0);
    EXPECT_LT(jlgxy::compare_filename("abc1", "abc10"), 0);
    EXPECT_GT(jlgxy::compare_filename("abc01", "abc0"), 0);
    EXPECT_GT(jlgxy::compare_filename("abc01", "abc00"), 0);
    EXPECT_GT(jlgxy::compare_filename("abc01", "abc000"), 0);
    EXPECT_GT(jlgxy::compare_filename("abc1", "abc01"), 0);
    EXPECT_LT(jlgxy::compare_filename("abc1", "abc02"), 0);
}
TEST(compareFilename, intstr) {
    EXPECT_EQ(jlgxy::compare_filename("1abc", "1abc"), 0);
    EXPECT_LT(jlgxy::compare_filename("01abc", "1abc"), 0);
    EXPECT_GT(jlgxy::compare_filename("02abc", "1abc"), 0);
    EXPECT_GT(jlgxy::compare_filename("10abc", "1abc"), 0);
    EXPECT_GT(jlgxy::compare_filename("10abc", "01abc"), 0);
    EXPECT_LT(jlgxy::compare_filename("01abc", "01abd"), 0);
    EXPECT_GT(jlgxy::compare_filename("01abd", "01abc"), 0);
}
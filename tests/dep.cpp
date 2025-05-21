
#include <vector>

#include "gtest/gtest.h"
#include "judge_core.h"

using dep_t = jlgxy::SubtaskDependencies;

TEST(subDep, chain1) {
    dep_t dep(4);
    dep.dag_[0].emplace_back(1);
    dep.dag_[1].emplace_back(2);
    dep.dag_[2].emplace_back(3);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({0, 1, 2, 3}));
}
TEST(subDep, chain2) {
    dep_t dep(4);
    dep.dag_[3].emplace_back(2);
    dep.dag_[2].emplace_back(1);
    dep.dag_[1].emplace_back(0);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({3, 2, 1, 0}));
}

TEST(subDep, star1) {
    dep_t dep(5);
    dep.dag_[2].emplace_back(0);
    dep.dag_[2].emplace_back(1);
    dep.dag_[2].emplace_back(3);
    dep.dag_[2].emplace_back(4);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({2, 0, 1, 3, 4}));
}
TEST(subDep, star2) {
    dep_t dep(5);
    dep.dag_[0].emplace_back(2);
    dep.dag_[1].emplace_back(2);
    dep.dag_[3].emplace_back(2);
    dep.dag_[4].emplace_back(2);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({0, 1, 3, 4, 2}));
}

TEST(subDep, graph1) {
    dep_t dep(5);
    dep.dag_[2].emplace_back(0);
    dep.dag_[2].emplace_back(3);
    dep.dag_[2].emplace_back(4);
    dep.dag_[0].emplace_back(1);
    dep.dag_[3].emplace_back(1);
    dep.dag_[4].emplace_back(1);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({2, 0, 3, 4, 1}));
}

TEST(subDep, scc1) {
    dep_t dep(5);
    auto add = [&](int u, int v) { dep.dag_[u].emplace_back(v); };
    add(0, 1);
    add(1, 2);
    add(2, 0);
    add(2, 3);
    add(3, 4);
    add(4, 2);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({0, 1, 2, 3, 4}));
}
TEST(subDep, scc2) {
    dep_t dep(6);
    auto add = [&](int u, int v) { dep.dag_[u].emplace_back(v); };
    add(0, 1);
    add(1, 2);
    add(2, 0);
    add(3, 2);
    add(3, 4);
    add(4, 5);
    add(5, 3);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({3, 4, 5, 0, 1, 2}));
}
TEST(subDep, scc3) {
    dep_t dep(5);
    auto add = [&](int u, int v) { dep.dag_[u].emplace_back(v); };
    add(2, 1);
    add(1, 3);
    add(3, 4);
    add(4, 1);
    add(1, 0);
    dep.init();
    EXPECT_EQ(dep.order_, std::vector<int>({2, 1, 3, 4, 0}));
}

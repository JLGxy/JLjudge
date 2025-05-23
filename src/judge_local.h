//
// Copyright (c) 2024-2025 JLGxy, a1co0av5ce5az1cz0ap_
//

#pragma once

#include <sys/wait.h>

#include <chrono>
#include <cstddef>
#include <ctime>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "prog_option.h"

#define FMT_ENFORCE_COMPILE_STRING 1

#include "fmt/core.h"
#include "judge_core.h"
#include "judge_logs.h"

namespace jlgxy {

using namespace std::literals;
namespace chrono = std::chrono;

using judge_time_duration = chrono::milliseconds;

using po::_size_inf;

class TestdirWrapper {
  public:
    explicit TestdirWrapper(fs::path t);
    fs::path getpath() const;
    ~TestdirWrapper();

  private:
    fs::path pth_;
};

inline std::string operator+(std::string &&a, const std::string_view b) {
    a.append(b);
    return std::move(a);
}

class JudgeError : public std::exception {
  public:
    explicit JudgeError(const std::string_view what_arg)
            : what_str_(std::string("\033[31m\033[1merror:\033[0m ") + what_arg) {}
    const char *what() const noexcept override { return what_str_.c_str(); }

  protected:
    std::string what_str_;
};

class ProblemConfigError : public JudgeError {
  public:
    ProblemConfigError(const std::string_view name, const std::string_view what_arg)
            : JudgeError(std::string("in problem ") + name + ":\n  " + what_arg) {}
    const char *what() const noexcept override { return what_str_.c_str(); }
};

inline std::string get_name(const std::string_view username, const std::string_view probname,
                            const std::string_view suf, const std::string_view rstr) {
    return std::string(username) + "_jlgxy_" +
           std::to_string(std::hash<std::string>{}(std::string(username) + probname + rstr + suf)) +
           "_compiled_" + probname + "_" + suf;
}

class JudgeOne {
  public:
    fs::path data_dir_, temp_dir_;
    const std::string rstr_;
    JudgeOne(fs::path dd, fs::path td, std::string ss);

    list_result_t run(const fs::path &code_file, const conf_t &config) const;
};

struct contest_conf_t {
    contest_conf_t() = default;
    contest_conf_t(const contest_conf_t &) = delete;
    contest_conf_t(contest_conf_t &&) noexcept = default;
    contest_conf_t &operator=(const contest_conf_t &) = delete;
    contest_conf_t &operator=(contest_conf_t &&) noexcept = default;
    std::vector<std::string> problems;
    std::map<std::string, int, std::less<>> prob_id;
};

inline void read_contest_config(const fs::path &file, contest_conf_t &contest_conf);

constexpr auto _max_threads = 5;

struct sub_res_t {
    sub_res_t() : list_res{} {}
    sub_res_t(const sub_res_t &) = delete;
    sub_res_t(sub_res_t &&) noexcept = default;
    sub_res_t &operator=(const sub_res_t &) = delete;
    sub_res_t &operator=(sub_res_t &&) noexcept = default;
    list_result_t list_res;
    scores_t sco;
    sub_res_t(list_result_t &&l, scores_t &&s) : list_res(std::move(l)), sco(std::move(s)) {}
};

struct sub_info_t {
    std::string prob_name, user_name;
    std::size_t code_len;
    chrono::time_point<chrono::system_clock> judge_time;
    sub_res_t result;
    const Compiler *compiler;

    sub_info_t() = default;
    sub_info_t(const sub_info_t &) = delete;
    sub_info_t(sub_info_t &&) noexcept = default;
    sub_info_t &operator=(const sub_info_t &) = delete;
    sub_info_t &operator=(sub_info_t &&) noexcept = default;

    struct comp_max_tm_usage {
        bool operator()(const sub_info_t &a, const sub_info_t &b) const {
            return a.result.list_res.get_max_tm_mem().first <
                   b.result.list_res.get_max_tm_mem().first;
        }
    };
    struct comp_max_mem_usage {
        bool operator()(const sub_info_t &a, const sub_info_t &b) const {
            return a.result.list_res.get_max_tm_mem().second <
                   b.result.list_res.get_max_tm_mem().second;
        }
    };
    struct comp_total_tm_usage {
        bool operator()(const sub_info_t &a, const sub_info_t &b) const {
            return a.result.list_res.get_total_tm() < b.result.list_res.get_total_tm();
        }
    };
    struct comp_code_length {
        bool operator()(const sub_info_t &a, const sub_info_t &b) const {
            return a.code_len < b.code_len;
        }
    };
};

template <typename Comp>
struct iter_comp_iter {
    using is_transparent = void;
    using compare = Comp;

    template <typename T, typename U>
    bool operator()(T a, U b) {
        return compare{}(*a, *b);
    }
};

struct user_res_t {
    user_res_t() = default;
    user_res_t(const user_res_t &) = delete;
    user_res_t(user_res_t &&) noexcept = default;
    user_res_t &operator=(const user_res_t &) = delete;
    user_res_t &operator=(user_res_t &&) noexcept = default;
    std::vector<sub_info_t> subs;
    std::string to_str() const {
        if (subs.empty()) return "{}";
        std::string res = "{";
        for (const auto &sub : subs) {
            res += "'" + sub.prob_name + "': " + sub.result.list_res.to_str() + ",";
        }
        res.back() = '}';
        return res;
    }
};

struct all_res_t {
    all_res_t() = default;
    all_res_t(const all_res_t &) = delete;
    all_res_t(all_res_t &&) noexcept = default;
    all_res_t &operator=(const all_res_t &) = delete;
    all_res_t &operator=(all_res_t &&) noexcept = default;
    std::vector<std::pair<std::string, user_res_t>> r;
    std::string to_str() const {
        if (r.empty()) return "{}";
        std::string res = "{";
        for (const auto &[probname, lr] : r) {
            res += "'" + probname + "': " + lr.to_str() + ",";
        }
        res.back() = '}';
        return res;
    }
};

struct table_t {
    std::vector<std::string> rows, cols;
    std::vector<std::vector<double>> tab;
    table_t(std::size_t rown, std::size_t coln) : tab(rown, std::vector<double>(coln)) {
        rows.resize(rown);
        cols.resize(coln);
    }
};

inline table_t to_table(const all_res_t &res,
                        const std::vector<std::pair<std::string, conf_t>> &probs);

namespace sb_base64 {

inline const char _alphabet_map[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64_encode(std::string_view text);

}  // namespace sb_base64

namespace save {

template <int Len, typename It, typename Num>
void num_to_bytes(It &&it, Num x);

template <typename It>
void double_to_bytes(It &&it, double x);

template <typename It>
void bool_to_bytes(It &&it, bool x);

template <typename It>
void string_to_bytes(It &&it, std::string_view s);

template <typename Int, int Len, typename It>
Int read_num(It &&it);

template <typename It>
double read_double(It &&it);

template <typename It>
bool read_bool(It &&it);

template <typename It>
std::string read_string(It &&it);

template <typename It>
verdict_t read_verdict(It &&it);

template <typename It>
void result_to_binary(It &&it, const result_t &r);
template <typename It>
result_t result_from_binary(It &&it);

template <typename It>
void scores_to_binary(It &&it, const scores_t &s);
template <typename It>
scores_t scores_from_binary(It &&it);

template <typename It>
void list_result_to_binary(It &&it, const list_result_t &r);
template <typename It>
list_result_t list_result_from_binary(It &&it);

template <typename It>
void user_res_to_binary(It &&it, const user_res_t &r);
template <typename It>
user_res_t user_res_from_binary(It &&it, std::string_view user_name,
                                const std::vector<const Compiler *> &comps);

template <typename It>
void all_res_to_binary(It &&it, const all_res_t &r);
template <typename It>
all_res_t all_res_from_binary(It &&it, const std::vector<const Compiler *> &comps);

void print_binary(const std::vector<std::byte> &v);

void save_file(const fs::path &file, const all_res_t &r);
all_res_t load_file(const fs::path &file, const std::vector<const Compiler *> &comps);

}  // namespace save

inline std::string to_string_n(double x, int n) { return fmt::format(JLGXY_FMT("{:.{}f}"), x, n); }

struct row {
    const user_res_t *res;
    const std::string *name;
    double score;
};

inline std::string rand_by(const std::string_view s, const std::string_view t) {
    return sb_base64::base64_encode(s) + "-qwq-" + sb_base64::base64_encode(t);
}

inline std::string localstr(std::time_t c, const std::string_view s) {
    std::stringstream ss;
    ss << std::put_time(std::localtime(&c), std::string(s).c_str());
    return ss.str();
}

template <typename T>
inline T square(T x) {
    return x * x;
}

inline std::string mu_to_str(mem_usage_t kib) {
    return to_string_n(static_cast<double>(kib) / 1024.0, 3) + "MiB";
}

inline std::string tu_to_str(tm_usage_t ms) {
    if (ms == _tm_usage_inf) return "N/A";
    return to_string_n(static_cast<double>(ms) / 1000.0, 3) + "s";
}

void generateexcel(const table_t &table, time_t st, time_t run, time_t ed);

struct pair_cmp {
    using is_transparent = void;
    template <typename T1, typename T2, typename T3, typename T4>
    constexpr bool operator()(const std::pair<T1, T2> &_x, const std::pair<T3, T4> &_y) const {
        return _x.first < _y.first || (!(_y.first < _x.first) && _x.second < _y.second);
    }
};

struct submission_set {
    std::set<std::pair<std::string, std::string>, pair_cmp> mp;
    std::set<std::string, std::less<>> users, probs;
    void init();
    bool contains_prob(std::string_view prob) const;
    bool contains(std::string_view user, std::string_view prob) const;
    void loads_from_args(int argc, char **argv);
    void loads_from_args(const std::vector<std::string> &args);
};

inline bool path_contains(fs::path a, fs::path b) {
    a = fs::canonical(a);
    b = fs::canonical(b);
    for (; b.has_relative_path(); b = b.parent_path()) {
        if (a == b) return true;
    }
    return false;
}

inline std::string trans(const std::string_view s) {
    std::string res;
    for (auto c : s) {
        if (c == '"')
            res += "\\\"";
        else if (c == '\'')
            res += "\\\'";
        else if (c == '\\')
            res += "\\\\";
        else if (c == '\n')
            res += "\\n";
        else if (c == '\r')
            res += "\\r";
        else
            res += c;
    }
    return res;
}

void print_problem_config_warning(std::string_view name, std::string_view what_arg);

tm_usage_t get_tot_judge_time(const conf_t &config);

using prob_sub_vec = std::vector<std::vector<const sub_info_t *>>;

inline bool is_ac_sub(const sub_info_t &s) { return s.result.sco.final_verdict == verdict_t::_ac; }

int compare_strint(std::string_view a, std::string_view b);

int compare_filename(std::string_view a, std::string_view b);

class JudgeAll {
  public:
    fs::path data_dir, source_dir, temp_dir;
    contest_conf_t contest_config;
    std::vector<std::pair<std::string, conf_t>> probs;
    submission_set subs;
    all_res_t all_res;
    std::vector<std::unique_ptr<Compiler>> compilers;
    std::vector<const Compiler *> compilers_p;

    static constexpr std::string_view _projectfile = ".jljudge/.jlproject";

    JudgeAll(fs::path dd, fs::path sd, fs::path td);
    ~JudgeAll();

    void add_range(const std::vector<std::pair<std::string, std::string>> &s);

    void load_compilers();
    void judge_main();

    void merge_user();
    void remove_range();

    void load_project();
    void load_probs();

    // TODO(JLGxy): export statistics
    void export_results();

    static std::pair<double, double> calc_sd(const std::vector<double> &s);

    void export_bests(std::size_t best_cnt) const;
    void export_stats(std::size_t best_cnt) const;

  private:
    const std::string rstr_;
    struct judge_task {
        fs::path user_path;
        std::string user_name;
        std::string prob_name;
        const conf_t &config;
        const Compiler *compc;
        fs::path code;
    };
    struct compile_prog {
        fs::path src, exe;
        const Compiler *compiler;
    };

    std::vector<judge_task> tasks_;
    std::queue<compile_prog> compile_list_;
    std::mutex compile_list_lock_;
    int tot_compile_task_ = 0;
    int tot_compiled_ = 0;
    double base_prop_ = 0;
    double cur_prop_ = 0;
    double prop_ = 0;

    void save_file() const;
    static std::tuple<bool, const Compiler *, fs::path> find_code_at(const fs::path &dir,
                                                                     const conf_t &config);
    void read_config(const fs::path &conf_file, conf_t &conf) const;
    void check_valid() const;

    void get_problem_compile_list();
    void check_problem_compile_files();
    void get_user_compile_list();

    void inc_compile_progress();
    static void compiles(JudgeAll &ja, const fs::path &temp_dir);
    void compile_all();

    void calc_all_score();
    bool exist_prob(std::string_view x) const;

    std::vector<std::vector<const sub_info_t *>> get_all_subs() const;
    static prob_sub_vec filter_sub(prob_sub_vec &&subs,
                                   const std::function<bool(const sub_info_t &s)> &pred);
    std::string generate_bests(std::size_t best_cnt) const;
    std::string generate_ranklist() const;
    static std::string generate_submission_info(const sub_info_t &sub, const conf_t &conf,
                                                std::string_view user_name);
    std::string generate_html() const;
};

// class CliRunner {
//   public:
//     static void err_usage();
//     static void err_newprob_usage();
//     static void newprob(int argc, char **argv);
//     static int try_run(int argc, char **argv);
//     static int run(int argc, char **argv);
// };

namespace cli {

class CliHandler {
  public:
    int run(int argc, char **argv);

  private:
    po::CommandHandler handler_;

    int run_throw(int argc, char **argv);
};

}  // namespace cli

}  // namespace jlgxy

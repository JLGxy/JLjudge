//
// Copyright (c) 2024-2025 JLGxy
//

#pragma once

#ifndef __linux__
#error "only linux is supported"
#endif

#ifndef __GNUC__
#error "unsupported compiler"
#endif

static_assert(sizeof(void *) == 8, "can only compile and run on 64-bit machines");

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "config.h"  // IWYU pragma: export

// #define JLGXY_SHOWSYSCALLS

#define JLGXY_ENABLE_SECCOMP

struct rusage;

namespace jlgxy {

namespace fs = std::filesystem;

enum class verdict_t : std::int8_t {
    _canceled = -2,
    _failed = -1,
    _ac = 0,
    _ce = 1,
    _wa = 2,
    _re = 3,
    _tle = 4,
    _mle = 5,
    _pe = 6,
    _ole = 7,
    _wt = 100,
    _jg = 101,
    _wr = 102
};

std::string verdict_to_str(verdict_t ver);
std::string verdict_to_str_sjlac(verdict_t ver);
std::string verdict_to_str_short(verdict_t ver);

using tm_usage_t = long;
using mem_usage_t = long;

constexpr tm_usage_t _tm_usage_inf = std::numeric_limits<tm_usage_t>::max();

inline bool startswith(const std::string_view a, const std::string_view b) {
    return a.length() >= b.length() && a.substr(0, b.length()) == b;
}
inline bool endswith(const std::string_view a, const std::string_view b) {
    return a.length() >= b.length() && a.substr(a.length() - b.length(), b.length()) == b;
}

constexpr int _int_nan = -0x7fffffff - 1;
constexpr double _double_inf = 1e18;

struct result_t {
    verdict_t res;
    tm_usage_t tm_used;
    mem_usage_t mem_used;
    double score;
    int returnval;
    std::string info;

    result_t(verdict_t v, tm_usage_t tm, mem_usage_t mem, double sc, int rv, std::string f);
    std::string to_str() const;
};

inline bool is_valid_token(const std::string_view t) {
    for (auto c : t) {
        if ((c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_' &&
            c != '.' && c != '-')
            return false;
    }
    return t.find("..") == std::string::npos;
}

// Config of a testcase
struct testcase_conf_t {
    tm_usage_t time_lim;
    mem_usage_t mem_lim;
    std::string input_file, answer_file;

    testcase_conf_t() = default;
    testcase_conf_t(testcase_conf_t &&) noexcept = default;
    testcase_conf_t(const testcase_conf_t &) = delete;
    testcase_conf_t &operator=(testcase_conf_t &&) noexcept = default;
    testcase_conf_t &operator=(const testcase_conf_t &) = delete;

    bool is_valid() const;
};

enum class scoring_t : std::int8_t { _c_sum, _c_min, _c_max };

inline scoring_t to_scoring_t(const std::string_view s) {
    if (s == "avg") return scoring_t::_c_sum;
    if (s == "min") return scoring_t::_c_min;
    if (s == "max") return scoring_t::_c_max;
    throw std::runtime_error("invalid scoring method");
}

struct subtask_conf_t {
    double tot_score;
    std::vector<int> testcases;
    scoring_t scoring;

    subtask_conf_t() = default;
    subtask_conf_t(subtask_conf_t &&) noexcept = default;
    subtask_conf_t(const subtask_conf_t &) = delete;
    subtask_conf_t &operator=(subtask_conf_t &&) noexcept = default;
    subtask_conf_t &operator=(const subtask_conf_t &) = delete;
};

class Compiler;

// Config of the problem
struct conf_t {
    std::vector<testcase_conf_t> testcase_conf;
    std::vector<subtask_conf_t> subtask_conf;
    std::string name;
    std::vector<const Compiler *> compiler;
    std::string input_file, output_file;
    std::string checker;
    const Compiler *checker_compiler;
    bool is_interactive;
    std::string interactor;
    const Compiler *interactor_compiler;
    bool has_subtasks;

    conf_t() = default;
    conf_t(conf_t &&) noexcept = default;
    conf_t(const conf_t &) = delete;
    conf_t &operator=(conf_t &&) noexcept = default;
    conf_t &operator=(const conf_t &) = delete;

    bool is_valid() const;
};

struct scores_t {
    std::vector<double> scores;
    double score;
    verdict_t final_verdict;

    scores_t() = default;
    scores_t(scores_t &&) noexcept = default;
    scores_t(const scores_t &) = delete;
    scores_t &operator=(scores_t &&) noexcept = default;
    scores_t &operator=(const scores_t &) = delete;

    std::string to_str() const;
};

struct list_result_t {
    bool has_started = false;
    std::vector<result_t> results;

    list_result_t(const list_result_t &) = delete;
    list_result_t(list_result_t &&) noexcept = default;
    list_result_t &operator=(const list_result_t &) = delete;
    list_result_t &operator=(list_result_t &&) noexcept = default;
    list_result_t(std::initializer_list<result_t> lst) : results(lst) {}

    std::string to_str() const;
    scores_t calc_score(const conf_t &conf) const;

    std::pair<tm_usage_t, mem_usage_t> get_max_tm_mem() const;
    tm_usage_t get_total_tm() const;
};

const result_t _failed_r = result_t(verdict_t::_failed, 0, 0, 0, _int_nan, "");
const result_t _ce_r = result_t(verdict_t::_ce, 0, 0, 0, _int_nan, "");

inline void copy_file(const fs::path &src, const fs::path &dst) {
    if (!fs::is_regular_file(src)) return;
    // if (access(src.c_str(), F_OK)) return;
    std::ofstream(dst) << std::ifstream(src).rdbuf();
}
inline std::string read_file(const fs::path &src) {
    std::stringstream ss;
    ss << std::ifstream(src).rdbuf();
    return ss.str();
}
inline void write_file(const fs::path &dst, const std::string_view s) { std::ofstream(dst) << s; }

class MyPipe {
  public:
    int fd_[2]{};
    bool closed_[2]{false, false};
    MyPipe();
    void close(int p);
    void close();
    ~MyPipe();

    // Returns the number written, or -1
    ::ssize_t write(std::string_view s);
    // Returns the number read, or -1
    ::ssize_t read(std::string &s);
};

// Create C subprocesses
template <int C>
int myfork(int pid[C]);

constexpr auto _randstr_default_length = 8;

inline std::string randstr(int len = _randstr_default_length) {
    const std::string set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static std::mt19937 rng(std::random_device{}());
    std::string ret;
    for (int i = 0; i < len; i++) {
        ret += set[rng() % set.length()];
    }
    return ret;
}
inline std::vector<std::string> mysplit(const std::string_view s) {
    std::size_t lst = 0;
    std::vector<std::string> ret;
    for (std::size_t i = 0; i <= s.length(); i++) {
        if (i == s.length() || s[i] == ' ') {
            if (lst < i) ret.emplace_back(s.substr(lst, i - lst));
            lst = i + 1;
        }
    }
    return ret;
}

void exec_vec(const std::string &name, const std::vector<std::string> &args)
        __attribute__((noreturn));

std::tuple<int, std::string, std::string> run_get_output(const std::string &name,
                                                         const std::vector<std::string> &args);

// TODO(JLGxy): test
class Compiler {
  public:
    std::string name;
    std::string compiler;
    std::vector<std::string> argvec;
    std::vector<std::string> suffix;
    std::vector<std::string> disallow_pragmas;

    Compiler() = default;
    Compiler(const Compiler &) = delete;
    Compiler(Compiler &&) noexcept = default;
    Compiler &operator=(const Compiler &) = delete;
    Compiler &operator=(Compiler &&) noexcept = default;

    bool is_gcc_or_clang() const;
    bool are_pragmas_valid() const;

    void compile(const fs::path &source, const fs::path &dest,
                 const std::vector<std::string> &additional_args) const
            __attribute__((__noreturn__));

    bool validfile(const fs::path &pth) const;
};

class ProgramWrapper {
  public:
    static constexpr int _max_compile_time = 10000;
    std::string source_, executable_;
    static inline int compiler_pid_;
    static void signal_handler(int);
    static void settimer(int pid);
    static void clrtimer();

    verdict_t check_pramgas(const Compiler &compc, const fs::path &tempdir) const;
    verdict_t compile(const Compiler &compc, const fs::path &tempdir,
                      const std::vector<std::string> &additional_args = {}) const;
    static void configure_seccomp();

    void startexe(int in, int out, int err, tm_usage_t /* time_lim */, mem_usage_t mem_lim,
                  const std::vector<std::string> &args) const __attribute__((__noreturn__));
};

class TracerOld {
  public:
    bool iscalling_ = false;
    const std::vector<std::string> *validinputs_p_, *validoutputs_p_;
    TracerOld(const std::vector<std::string> &validinputs,
              const std::vector<std::string> &validoutputs)
            : validinputs_p_(&validinputs), validoutputs_p_(&validoutputs) {}
    static std::string getdata(pid_t child, unsigned long long addr);
    static constexpr std::array<bool, 500> get_valid_calls();
    bool is_dangerous_syscall(long id, pid_t pid);
    static inline int child_pid_;
    static void signal_handler(int);
    int tracerwork(int pid, tm_usage_t time_lim, mem_usage_t mem_lim, rusage &usage);
};

class Tracer {
  public:
    bool iscalling_ = false;
    bool started_ = false;
    const std::vector<std::string> *validinputs_p_, *validoutputs_p_;
    Tracer(const std::vector<std::string> &validinputs,
           const std::vector<std::string> &validoutputs)
            : validinputs_p_(&validinputs), validoutputs_p_(&validoutputs) {}
    static std::string getdata(pid_t child, unsigned long long addr);
    bool is_dangerous_syscall(long id, pid_t pid);
    static inline int child_pid_;
    static inline bool timeout_killed_;
    timer_t tmid_;

    static void signal_handler(int);
    void configure_timer(tm_usage_t time_lim);
    void clear_timer() const;

    int tracerwork(int pid, tm_usage_t time_lim, mem_usage_t /* mem_lim */, rusage &usage);
};

// Run unsafe program
class UnsafeCodeRunner {
  public:
    ProgramWrapper prog_, inter_prog_;
    std::vector<std::string> validinputs_, validoutputs_;
    std::ostream &logs;
#ifdef JLGXY_ENABLE_SECCOMP
    Tracer
#else
    TracerOld
#endif
            tracer;
    explicit UnsafeCodeRunner(std::ostream &os) : logs(os), tracer(validinputs_, validoutputs_) {}

    result_t run(int /* id */, const std::string &in_data, std::string &out_data,
                 tm_usage_t time_lim, mem_usage_t mem_lim, const std::vector<std::string> &args);
    result_t run_interactive(int /* id */, tm_usage_t time_lim, mem_usage_t mem_lim);
};

verdict_t compile_to(const fs::path &src, const fs::path &exe, const Compiler &compc,
                     const fs::path &tempdir);

std::pair<bool, const Compiler *> find_compiler_by_file(const std::vector<const Compiler *> &comps,
                                                        const fs::path &file);

std::pair<bool, const Compiler *> find_compiler_by_name(const std::vector<const Compiler *> &comps,
                                                        std::string_view name);

class Judger {
  public:
    const conf_t &config_;
    std::stringstream logs;
    UnsafeCodeRunner runner_, chkrunner_;
    std::string out_data, in_data;
    fs::path tempdir;

    explicit Judger(fs::path td, const conf_t &conf)
            : config_(conf), runner_(logs), chkrunner_(logs), tempdir(std::move(td)) {}

    int get_input(int id);
    void clear_output();
    int get_output(int /* id */) const;

    result_t run(int id);
    list_result_t run_all(int /* tot_pt */, const fs::path &source, bool compiled = false);
};

}  // namespace jlgxy

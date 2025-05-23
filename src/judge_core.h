//
// Copyright (c) 2024-2025 JLGxy
//

#pragma once

#include <asm/unistd_64.h>
#include <fcntl.h>
#include <unistd.h>

#include <boost/dynamic_bitset.hpp>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "config.h"  // IWYU pragma: export
#include "multiprocess.h"

#ifndef __linux__
#error "only linux is supported"
#endif

#ifndef __GNUC__
#error "unsupported compiler"
#endif

static_assert(sizeof(void *) == 8, "can only compile and run on 64-bit machines");

// #define JLGXY_SHOWSYSCALLS

struct rusage;

namespace jlgxy {

namespace mpc = multiproc;
namespace fs = std::filesystem;

enum class verdict_t : std::int8_t {
    _skp = -3,
    _can = -2,
    _fail = -1,
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
    std::vector<int> pre;
    double punish{};

    subtask_conf_t() = default;
    subtask_conf_t(subtask_conf_t &&) noexcept = default;
    subtask_conf_t(const subtask_conf_t &) = delete;
    subtask_conf_t &operator=(subtask_conf_t &&) noexcept = default;
    subtask_conf_t &operator=(const subtask_conf_t &) = delete;
};

class Compiler;

class SubtaskDependencies {
  public:
    using vvi = std::vector<std::vector<int>>;
    using vb = std::vector<boost::dynamic_bitset<>>;

    vvi dag_;
    std::vector<int> order_;
    vb dep_;

    explicit SubtaskDependencies(int n) : dag_(n), dep_(n, boost::dynamic_bitset<>(n)) {}

    void init() {
        get_order();
        get_prevs();
    }

  private:
    class Tarjan {
      public:
        vvi scc_;
        void tarjan(int p);
        void run();
        explicit Tarjan(const vvi &graph)
                : dag_(graph),
                  dfn_(graph.size()),
                  low_(graph.size()),
                  col_(graph.size()),
                  ins_(graph.size()) {}

        std::size_t cols() const { return scnt_; }
        int col(std::size_t idx) const { return col_[idx]; }

      private:
        const vvi &dag_;
        std::vector<int> dfn_, low_, st_, col_;
        std::vector<bool> ins_;
        int dcnt_{}, scnt_{};
    };

    void get_order();
    void get_prevs();
};

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

    std::unique_ptr<SubtaskDependencies> dep;

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

const result_t _failed_r = result_t(verdict_t::_fail, 0, 0, 0, _int_nan, "");
const result_t _ce_r = result_t(verdict_t::_ce, 0, 0, 0, _int_nan, "");
const result_t _wt_r = result_t(verdict_t::_wt, 0, 0, 0, _int_nan, "");
const result_t _skp_r = result_t(verdict_t::_skp, 0, 0, 0, _int_nan, "");

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
    MyPipe() {
        if (pipe(fd_) == -1) closed_[0] = closed_[1] = true;
    }
    void close_read() {
        if (!closed_[0]) ::close(fd_[0]), closed_[0] = true;
    }
    void close_write() {
        if (!closed_[1]) ::close(fd_[1]), closed_[1] = true;
    }
    void close() {
        close_read();
        close_write();
    }
    ~MyPipe() { close(); }

    // Returns the number written, or -1
    ::ssize_t write(std::string_view s) const;
    // Returns the number read, or -1
    ::ssize_t read(std::string &s) const;

    int read_fd() const { return fd_[0]; }
    int write_fd() const { return fd_[1]; }

    bool is_read_closed() const { return closed_[0]; }
    bool is_write_closed() const { return closed_[1]; }

    inline friend MyPipe null_pipe();

  private:
    MyPipe(int read_fd, int write_fd) : fd_{read_fd, write_fd}, closed_{false, false} {}
    int fd_[2]{};
    bool closed_[2]{false, false};
};

inline MyPipe null_pipe() {
    int read_fd = open("/dev/null", O_RDONLY);
    int write_fd = open("/dev/null", O_WRONLY);
    if (read_fd == -1 || write_fd == -1) {
        close(read_fd);
        close(write_fd);
        MyPipe p(-1, -1);
        p.closed_[0] = p.closed_[1] = true;
        return p;
    }
    MyPipe p(read_fd, write_fd);
    return p;
}

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
    static void realtimer(tm_usage_t);
    static void settimer(int pid);
    static void clrtimer();

    verdict_t check_pramgas(const Compiler &compc, const fs::path &tempdir) const;
    verdict_t compile(const Compiler &compc, const fs::path &tempdir,
                      const std::vector<std::string> &additional_args = {}) const;
    static void configure_seccomp();

    void startexe(MyPipe &&in, MyPipe &&out, MyPipe &&err, tm_usage_t /* time_lim */,
                  mem_usage_t mem_lim, const std::vector<std::string> &args) const
            __attribute__((__noreturn__));
};

constexpr int _syscalls_allowed[] = {
        __NR_read,
        __NR_write,
        __NR_close,
        __NR_fstat,
        __NR_poll,
        __NR_lseek,
        __NR_mmap,
        __NR_mprotect,
        __NR_munmap,
        __NR_brk,
        __NR_ioctl,
        __NR_pread64,
        __NR_pwrite64,
        __NR_dup,
        __NR_dup2,
        __NR_nanosleep,
        __NR_getitimer,
        __NR_getpid,
        __NR_exit,
        __NR_uname,
        __NR_flock,
        __NR_readlink,
        __NR_gettimeofday,
        __NR_getrlimit,
        __NR_getrusage,
        __NR_getppid,
        __NR_arch_prctl,
        __NR_time,
        __NR_futex,
        __NR_set_tid_address,
        __NR_timer_gettime,
        __NR_clock_gettime,
        __NR_clock_getres,
        __NR_clock_nanosleep,
        __NR_exit_group,
        __NR_newfstatat,
        __NR_readlinkat,
        __NR_set_robust_list,
        __NR_get_robust_list,
        __NR_dup3,
        __NR_prlimit64,
        __NR_getrandom,
        __NR_rseq,
};
constexpr int _syscalls_traced[] = {
        __NR_openat,  // trace openat syscall
        __NR_execve,  // trace execve, only the first execve syscall is valid
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
    Tracer tracer;
    explicit UnsafeCodeRunner() : tracer(validinputs_, validoutputs_) {}
    static std::pair<tm_usage_t, mem_usage_t> get_time_mem(rusage &usage);
    static std::optional<result_t> check_usage(tm_usage_t tm, mem_usage_t mem, tm_usage_t time_lim,
                                               mem_usage_t mem_lim);
    static std::optional<result_t> check_status(int status, tm_usage_t tm, mem_usage_t mem);
    static result_t get_run_result(rusage &usage, int status, tm_usage_t time_lim,
                                   mem_usage_t mem_lim, mpc::Process &proc);
    pid_t start_tracee(MyPipe &inp, MyPipe &outp, tm_usage_t time_lim, mem_usage_t mem_lim,
                       const std::vector<std::string> &args) const;
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
    UnsafeCodeRunner runner_, chkrunner_;
    std::string out_data, in_data;
    fs::path tempdir;

    explicit Judger(fs::path td, const conf_t &conf) : config_(conf), tempdir(std::move(td)) {}

    int get_input(int id);
    void clear_output();
    int get_output(int /* id */) const;

    result_t run(int id);
    std::optional<list_result_t> prepare_run(int /* tot_pt */, const fs::path &source,
                                             bool compiled = false);
    list_result_t run_all(int /* tot_pt */, const fs::path &source, bool compiled = false);
    list_result_t run_all_ordered(int /* tot_pt */, const fs::path &source, bool compiled = false);
};

}  // namespace jlgxy

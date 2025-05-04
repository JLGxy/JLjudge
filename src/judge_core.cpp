//
// Copyright (c) 2024-2025 JLGxy
//

#include "judge_core.h"

#include <asm/unistd_64.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "judge_logs.h"
#include "multiprocess.h"

namespace jlgxy {

std::string verdict_to_str(verdict_t ver) {
    switch (ver) {
        case verdict_t::_canceled: return "_canceled";
        case verdict_t::_failed: return "_failed";
        case verdict_t::_ac: return "_ac";
        case verdict_t::_ce: return "_ce";
        case verdict_t::_wa: return "_wa";
        case verdict_t::_re: return "_re";
        case verdict_t::_tle: return "_tle";
        case verdict_t::_mle: return "_mle";
        case verdict_t::_pe: return "_pe";
        case verdict_t::_ole: return "_ole";
        case verdict_t::_wt: return "_wt";
        case verdict_t::_jg: return "_jg";
        case verdict_t::_wr: return "_wr";
        default: return "_undefined";
    }
}
std::string verdict_to_str_sjlac(verdict_t ver) {
    switch (ver) {
        case verdict_t::_canceled: return "Canceled";
        case verdict_t::_failed: return "Failed";
        case verdict_t::_ac: return "Accepted";
        case verdict_t::_ce: return "Compile Error";
        case verdict_t::_wa: return "Wrong Answer";
        case verdict_t::_re: return "Runtime Error";
        case verdict_t::_tle: return "Time Limit Exceeded";
        case verdict_t::_mle: return "Memory Limit Exceeded";
        case verdict_t::_pe: return "Presentation Error";
        case verdict_t::_ole: return "Output Limit Exceeded";
        case verdict_t::_wt: return "Waiting";
        case verdict_t::_jg: return "Judging";
        case verdict_t::_wr: return "Waiting for Rejudge";
        default: return "Undefined";
    }
}
std::string verdict_to_str_short(verdict_t ver) {
    switch (ver) {
        case verdict_t::_canceled: return "CANCL";
        case verdict_t::_failed: return "FAIL";
        case verdict_t::_ac: return "AC";
        case verdict_t::_ce: return "CE";
        case verdict_t::_wa: return "WA";
        case verdict_t::_re: return "RE";
        case verdict_t::_tle: return "TLE";
        case verdict_t::_mle: return "MLE";
        case verdict_t::_pe: return "PE";
        case verdict_t::_ole: return "OLE";
        case verdict_t::_wt: return "WAIT";
        case verdict_t::_jg: return "JUDGE";
        case verdict_t::_wr: return "REJUD";
        default: return "UNDEF";
    }
}

using tm_usage_t = long;
using mem_usage_t = long;

result_t::result_t(verdict_t v, tm_usage_t tm, mem_usage_t mem, double sc, int rv, std::string f)
        : res(v), tm_used(tm), mem_used(mem), score(sc), returnval(rv), info(std::move(f)) {}

std::string result_t::to_str() const {
    return "(" + verdict_to_str(res) + "," + std::to_string(tm_used) + "," +
           std::to_string(mem_used) + "," + std::to_string(score) + "," +
           std::to_string(returnval) + ")";
}

bool testcase_conf_t::is_valid() const {
    if (!is_valid_token(input_file)) return false;
    if (!is_valid_token(answer_file)) return false;
    return true;
}

bool conf_t::is_valid() const {
    if (!is_valid_token(input_file)) return false;
    if (!is_valid_token(output_file)) return false;
    if (!is_valid_token(checker)) return false;
    return std::all_of(testcase_conf.begin(), testcase_conf.end(),
                       [](const auto &c) { return c.is_valid(); });
}

std::string scores_t::to_str() const {
    std::string ret = "(" + verdict_to_str(final_verdict) + "," + std::to_string(score) + "):{";
    if (scores.empty()) {
        ret += "}";
    } else {
        for (auto sc : scores) {
            ret += std::to_string(sc);
            ret += ",";
        }
        ret.back() = '}';
    }
    return ret;
}

std::string list_result_t::to_str() const {
    if (results.empty()) {
        return "[]";
    }
    std::string res = "[";
    for (const auto &r : results) {
        res += r.to_str() + ",";
    }
    res.back() = ']';
    return res;
}
scores_t list_result_t::calc_score(const conf_t &conf) const {
    scores_t ret;
    if (!has_started) {
        ret.scores = {0};
        ret.score = 0;
        ret.final_verdict = results.empty() ? verdict_t::_failed : results[0].res;
        return ret;
    }
    for (const auto &sub : conf.subtask_conf) {
        double cur = 0;
        if (sub.scoring == scoring_t::_c_sum) {
            cur = 0;
            for (auto pt : sub.testcases) cur += results[pt].score;
            cur /= static_cast<double>(sub.testcases.size());
        } else if (sub.scoring == scoring_t::_c_min) {
            cur = _double_inf;
            for (auto pt : sub.testcases) cur = std::min(cur, results[pt].score);
        } else if (sub.scoring == scoring_t::_c_max) {
            cur = -_double_inf;
            for (auto pt : sub.testcases) cur = std::max(cur, results[pt].score);
        } else {
            throw std::runtime_error("unknown scoring method");
        }
        cur *= sub.tot_score;
        ret.scores.emplace_back(cur);
    }
    ret.score = 0;
    for (auto sc : ret.scores) ret.score += sc;
    ret.final_verdict = verdict_t::_ac;
    for (const auto &v : results) {
        if (v.res != verdict_t::_ac) {
            ret.final_verdict = v.res;
            break;
        }
    }
    return ret;
}

std::pair<tm_usage_t, mem_usage_t> list_result_t::get_max_tm_mem() const {
    tm_usage_t tm = 0;
    mem_usage_t mem = 0;
    for (const auto &r : results) {
        if (r.res == verdict_t::_tle) {
            tm = std::numeric_limits<tm_usage_t>::max();
        } else {
            tm = std::max(tm, r.tm_used);
        }
        mem = std::max(mem, r.mem_used);
    }
    return {tm, mem};
}

tm_usage_t list_result_t::get_total_tm() const {
    tm_usage_t tot_tm = 0;
    for (const auto &r : results) {
        if (r.res == verdict_t::_tle) {
            return std::numeric_limits<tm_usage_t>::max();
        }
        tot_tm += r.tm_used;
    }
    return tot_tm;
}

// Returns the number written, or -1
::ssize_t MyPipe::write(const std::string_view s) const {
    return ::write(write_fd(), s.data(), s.size());
}
// Returns the number read, or -1
::ssize_t MyPipe::read(std::string &s) const {
    std::stringstream fout;
    std::vector<char> out_buf(1 << 26);
    ::ssize_t tot = 0;
    while (true) {
        ::ssize_t t = ::read(read_fd(), out_buf.data(), out_buf.size());
        if (t == -1) return -1;
        if (t == 0) break;
        fout.write(out_buf.data(), t);
        tot += t;
    }
    s = fout.str();
    return tot;
}

namespace {

void open_and_dup_log_file(const fs::path &log_file, int fd) {
    int newfd = openat(AT_FDCWD, log_file.c_str(), O_CREAT | O_WRONLY, S_IRWXU | S_IRGRP | S_IROTH);
    if (dup2(newfd, fd) == -1) {
        jl::prog.println(JLGXY_FMT("Failed to redirect log"));
        exit(10);
    }
}

void set_mem_lim(mem_usage_t mem_lim) {
    rlimit rlim;
    rlim.rlim_cur = static_cast<rlim_t>(mem_lim);
    rlim.rlim_max = static_cast<rlim_t>(mem_lim);
    setrlimit(RLIMIT_DATA, &rlim);
    setrlimit(RLIMIT_STACK, &rlim);
}

void exit_with(std::string_view s, int exit_status) {
    jl::prog.println(JLGXY_FMT("{}"), s);
    exit(exit_status);
}

void redirect_or_exit(int in, int out, int err, int fail_status = 4) {
    if (dup2(in, STDIN_FILENO) == -1) exit_with("Failed to redirect", fail_status);
    if (dup2(out, STDOUT_FILENO) == -1) exit_with("Failed to redirect", fail_status);
    if (dup2(err, STDERR_FILENO) == -1) exit_with("Failed to redirect", fail_status);
}

void use_pipe_or_exit(MyPipe &in, MyPipe &out, MyPipe &err) {
    in.close_write();
    out.close_read();
    err.close_read();
    redirect_or_exit(in.read_fd(), out.write_fd(), err.write_fd());
}

}  // namespace

template <int C>
int myfork(int pid[C]) {
    int sid;
    for (sid = 0; sid < C; sid++) {
        pid[sid] = fork();
        if (pid[sid] < 0) {
            return -1;
        }
        if (pid[sid] == 0) {
            break;
        }
    }
    return sid;
}

void exec_vec(const std::string &name, const std::vector<std::string> &args) {
    std::vector<char *> argv;
    argv.reserve(args.size() + 2);
    argv.emplace_back(const_cast<char *>(name.c_str()));
    for (const auto &arg : args) argv.emplace_back(const_cast<char *>(arg.c_str()));
    argv.emplace_back(nullptr);

    execvp(name.c_str(), argv.data());
    exit(-1);
}

std::tuple<int, std::string, std::string> run_get_output(const std::string &name,
                                                         const std::vector<std::string> &args) {
    MyPipe out, err;
    mpc::Process proc([&] {
        out.close_read();
        err.close_read();
        int nfd = open("/dev/null", O_RDONLY);
        redirect_or_exit(nfd, out.write_fd(), err.write_fd());
        exec_vec(name, args);
    });
    out.close_write();
    err.close_write();
    auto read_to = [](MyPipe &p, std::string &s) { p.read(s); };
    std::string out_data, err_data;
    std::thread read_out(read_to, std::ref(out), std::ref(out_data));
    std::thread read_err(read_to, std::ref(err), std::ref(err_data));
    read_out.join();
    read_err.join();
    proc.join();
    return {proc.if_exited() ? proc.exit_status() : -1, out_data, err_data};
}

bool Compiler::is_gcc_or_clang() const {
    auto [ret, out, err] = run_get_output(compiler, {"-v"});
    if (ret != 0) return false;
    if (err.find("gcc version") != std::string::npos) return true;
    if (err.find("clang version") != std::string::npos) return true;
    return false;
}

void Compiler::compile(const fs::path &source, const fs::path &dest,
                       const std::vector<std::string> &additional_args) const {
    auto rarg = argvec;
    std::replace(rarg.begin(), rarg.end(), std::string("${source}"), source.string());
    std::replace(rarg.begin(), rarg.end(), std::string("${executable}"), dest.string());

    std::copy(additional_args.begin(), additional_args.end(), std::back_inserter(rarg));

    exec_vec(compiler, rarg);
}

bool Compiler::validfile(const fs::path &pth) const {
    std::string filename = pth.filename();
    return std::any_of(suffix.begin(), suffix.end(),
                       [&](const std::string &suf) { return endswith(filename, suf); });
}

void ProgramWrapper::signal_handler(int) {
    jl::prog.println(JLGXY_FMT("compiler timeout"));
    kill(compiler_pid_, SIGKILL);
}
void ProgramWrapper::realtimer(tm_usage_t time_ms) {
    itimerval tm;
    tm.it_value.tv_sec = time_ms / 1000;
    tm.it_value.tv_usec = time_ms % 1000 * 1000;
    tm.it_interval.tv_sec = 0;
    tm.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &tm, nullptr);
}
void ProgramWrapper::settimer(int pid) {
    compiler_pid_ = pid;
    signal(SIGALRM, signal_handler);
    realtimer(_max_compile_time);
}
void ProgramWrapper::clrtimer() { realtimer(0); }

// TODO(JLGxy): implementation
verdict_t ProgramWrapper::check_pramgas(const Compiler &compc, const fs::path &tempdir) const {
    if (!compc.is_gcc_or_clang()) return verdict_t::_ac;
    compile(compc, tempdir, {"-E"});
    std::ifstream fin(executable_);

    // TODO(JLGxy): impl

    fin.close();
    fs::remove(executable_);
    return verdict_t::_ac;
}

verdict_t ProgramWrapper::compile(const Compiler &compc, const fs::path &tempdir,
                                  const std::vector<std::string> &additional_args) const {
    int pid = fork();
    if (pid < 0) {
        jl::prog.println(JLGXY_FMT("Error while forking"));
        return verdict_t::_failed;
    }
    fs::path outfn = tempdir / ("compile_" + randstr() +
                                ".out");  // random should be in the main process, otherwise it
                                          // will results in same random seed
    fs::path errfn = tempdir / ("compile_" + randstr() + ".err");
    if (pid == 0) {
        if (!access(outfn.c_str(), F_OK)) {
            unlinkat(AT_FDCWD, outfn.c_str(), 0);
        }
        if (!access(errfn.c_str(), F_OK)) {
            unlinkat(AT_FDCWD, errfn.c_str(), 0);
        }
        int ppid = fork();
        if (ppid < 0) {
            jl::prog.println(JLGXY_FMT("Error while forking"));
            return verdict_t::_failed;
        }
        if (ppid == 0) {
            jl::prog.println(JLGXY_FMT("compiling: {}"), source_);
            open_and_dup_log_file(outfn, STDOUT_FILENO);
            open_and_dup_log_file(errfn, STDERR_FILENO);
            set_mem_lim(2L << 30);

            compc.compile(source_, executable_, additional_args);
        } else {
            settimer(ppid);
            int status = 0;
            do {
                waitpid(ppid, &status, 0);
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            clrtimer();
            std::string compilelog;
            compilelog.resize(400);
            auto len = std::ifstream(errfn).read(compilelog.data(), 400).gcount();
            compilelog.resize(len);
            jl::prog.println(JLGXY_FMT("compiler: "));
            jl::prog.println(JLGXY_FMT("---------------"));
            jl::prog.println(JLGXY_FMT("{}"), compilelog);
            jl::prog.println(JLGXY_FMT("---------------"));
            if (WIFSIGNALED(status)) {
                jl::prog.println(JLGXY_FMT("compiler killed"));
                jl::prog.println(JLGXY_FMT("signal: {}"), WTERMSIG(status));
                exit(static_cast<int>(verdict_t::_ce));
            }
            jl::prog.println(JLGXY_FMT("Compiler returned {}"), WEXITSTATUS(status));
            if (WEXITSTATUS(status)) {
                exit(static_cast<int>(verdict_t::_ce));
            }
            exit(static_cast<int>(verdict_t::_ac));
        }
    } else {
        int status = 0;
        do {
            waitpid(pid, &status, 0);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        if (WIFEXITED(status)) return static_cast<verdict_t>(WEXITSTATUS(status));
        return verdict_t::_failed;
    }
    return verdict_t::_ac;
}
void ProgramWrapper::configure_seccomp() {
    std::vector<sock_filter> filt{
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    };

    auto add_rule = [&](unsigned nr, unsigned act) {
        filt.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        filt.push_back(BPF_STMT(BPF_RET | BPF_K, act));
    };
    for (auto nr : _syscalls_traced) add_rule(nr, SECCOMP_RET_TRACE);
    for (auto nr : _syscalls_allowed) add_rule(nr, SECCOMP_RET_ALLOW);
    filt.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));

    jl::prog.println("size: {}", filt.size());

    struct sock_fprog prog = {
            static_cast<unsigned short>(filt.size()),
            filt.data(),
    };

    jl::prog.println(JLGXY_FMT("configuring seccomp"));
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) exit(2);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) exit(2);
    jl::prog.println(JLGXY_FMT("seccomp configured"));
}

void ProgramWrapper::startexe(MyPipe &&in, MyPipe &&out, MyPipe &&err, tm_usage_t /* time_lim */,
                              mem_usage_t mem_lim, const std::vector<std::string> &args) const {
    signal(SIGPIPE, SIG_IGN);
    use_pipe_or_exit(in, out, err);

    std::vector<char *> argv;
    argv.emplace_back(const_cast<char *>(executable_.c_str()));
    for (const auto &arg : args) {
        argv.emplace_back(const_cast<char *>(arg.c_str()));
    }
    argv.emplace_back(nullptr);

    set_mem_lim((mem_lim << 9) * 3);
    // rlim.rlim_cur = time_lim/1000+1;
    // rlim.rlim_max = time_lim/1000+2;
    // setrlimit(RLIMIT_CPU, &rlim);
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    kill(getpid(), SIGSTOP);
    configure_seccomp();
    execvp(executable_.c_str(), argv.data());
    // execl(executable_.c_str(), "", nullptr);
    exit(3);
}

std::string Tracer::getdata(pid_t child, unsigned long long addr) {
    std::string ans;
    while (true) {
        union {
            unsigned long long val;
            char chars[8];
        } data;
        data.val = ptrace(PTRACE_PEEKDATA, child, addr, nullptr);
        int end = 0;
        for (char ch : data.chars) {
            if (!static_cast<int>(ch)) {
                end = 1;
                break;
            }
            ans += ch;
        }
        if (end) break;
        addr += 8;
    }
    return ans;
}
bool Tracer::is_dangerous_syscall(long id, pid_t pid) {
    if (id == __NR_openat) {
        if (!iscalling_) {  // syscall-entry-stop
            iscalling_ = true;
            user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
            if (static_cast<int>(regs.rdi) != AT_FDCWD) return true;
            std::string filename = getdata(pid, regs.rsi);
            while (filename.length() > 2 && startswith(filename, "./")) {
                filename.erase(filename.begin(), filename.begin() + 2);
            }
            // jl::p.println(JLGXY_FMT(<< filename));
            if ((regs.rdx & 3) == O_RDONLY) {
                if (find(validinputs_p_->begin(), validinputs_p_->end(), filename) ==
                            validinputs_p_->end() &&
                    startswith(filename, "/etc/") && startswith(filename, "/lib/"))
                    return true;
            } else if ((regs.rdx & 3) == O_WRONLY) {
                if (find(validoutputs_p_->begin(), validoutputs_p_->end(), filename) ==
                    validoutputs_p_->end())
                    return true;
            } else {
                return true;
            }
        } else {  // syscall-exit-stop
            iscalling_ = false;
        }
        return false;
    }
    if (id == __NR_execve) {
        if (started_) return true;
        started_ = true;
        return false;
    }
    return true;  // disallow others
}
void Tracer::signal_handler(int) {
    jl::prog.println(JLGXY_FMT("timeout"));
    kill(child_pid_, SIGKILL);
    timeout_killed_ = true;
}
void Tracer::configure_timer(tm_usage_t time_lim) {
    signal(SIGALRM, signal_handler);

    sigevent sevp;
    sevp.sigev_notify = SIGEV_SIGNAL;
    sevp.sigev_signo = SIGALRM;
    sevp.sigev_value.sival_int = 8123;
    if (timer_create(CLOCK_REALTIME, &sevp, &tmid_) == -1) {
        kill(child_pid_, SIGKILL);
    }

    struct itimerspec its;
    its.it_value.tv_sec = (time_lim * 3 / 2) / 1000;
    its.it_value.tv_nsec = (time_lim * 3 / 2) % 1000 * 1000000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    if (timer_settime(tmid_, 0, &its, nullptr) == -1) {
        jl::prog.println(JLGXY_FMT("failed to set timer"));
        kill(child_pid_, SIGKILL);
    }
}
void Tracer::clear_timer() const { timer_delete(tmid_); }

int Tracer::tracerwork(int pid, tm_usage_t time_lim, mem_usage_t /* mem_lim */, rusage &usage) {
    iscalling_ = false;
    started_ = false;
    timeout_killed_ = false;
    int status = 0;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    child_pid_ = pid;
    configure_timer(time_lim);

    while (true) {
        int oid = wait4(pid, &status, 0, &usage);
        if (!oid) {
            jl::prog.println(JLGXY_FMT("err: {}"), oid);
            break;
        }
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            long orig_rax = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, nullptr);
#ifdef JLGXY_SHOWSYSCALLS
            jl::prog.println(JLGXY_FMT("seccomp stop"));
            jl::prog.println(JLGXY_FMT("{} called: {}"), pid, orig_rax);
#endif
            if (is_dangerous_syscall(orig_rax, pid)) {
                jl::prog.println(JLGXY_FMT("Dangerous syscall: {}"), orig_rax);
                // exit(1);  // debug
                kill(pid, SIGKILL);
                wait4(pid, &status, 0, &usage);
                break;
            }
        } else if (status >> 8 == SIGTRAP) {
        } else {
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
            jl::prog.println(JLGXY_FMT("{} got signal {}"), pid, WSTOPSIG(status));
            kill(pid, SIGKILL);
            wait4(pid, &status, 0, &usage);
            break;
        }
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        // kill
    }
    clear_timer();
    kill(pid, SIGKILL);
    if (timeout_killed_) {
        usage.ru_utime.tv_sec = -1;
        usage.ru_utime.tv_usec = -1;
    }
    return status;
}
std::pair<tm_usage_t, mem_usage_t> UnsafeCodeRunner::get_time_mem(rusage &usage) {
    tm_usage_t tm = (usage.ru_utime.tv_sec == -1)
                            ? _tm_usage_inf
                            : (usage.ru_utime.tv_usec / 1000) + (usage.ru_utime.tv_sec * 1000);
    mem_usage_t mem = usage.ru_maxrss;

    return {tm, mem};
}
std::optional<result_t> UnsafeCodeRunner::check_usage(tm_usage_t tm, mem_usage_t mem,
                                                      tm_usage_t time_lim, mem_usage_t mem_lim) {
    if (tm > time_lim) {
        return result_t{verdict_t::_tle, _tm_usage_inf, mem, 0, _int_nan, ""};
    }
    if (mem > mem_lim) {
        return result_t{verdict_t::_mle, tm, mem, 0, _int_nan, ""};
    }
    return std::nullopt;
}

std::optional<result_t> UnsafeCodeRunner::check_status(int status, tm_usage_t tm, mem_usage_t mem) {
    jl::prog.println(JLGXY_FMT("status: {}"), status);
    // if killed
    if (WIFSIGNALED(status)) {
        jl::prog.println(JLGXY_FMT("Killed"));
        jl::prog.println(JLGXY_FMT("Signal: {}"), WTERMSIG(status));
        if (WTERMSIG(status) == 31) {
            return result_t{verdict_t::_re, tm, mem, 0, _int_nan, "bad system call"};
        }
        return result_t{verdict_t::_re, tm, mem, 0, _int_nan, "killed"};
    }
    jl::prog.println(JLGXY_FMT("Program returned {}"), WEXITSTATUS(status));
    // return value is not zero
    if (WEXITSTATUS(status)) {
        return result_t{verdict_t::_re,
                        tm,
                        mem,
                        0,
                        WEXITSTATUS(status),
                        "exit code: " + std::to_string(WEXITSTATUS(status))};
    }
    return std::nullopt;
}

result_t UnsafeCodeRunner::get_run_result(rusage &usage, int status, tm_usage_t time_lim,
                                          mem_usage_t mem_lim, mpc::Process &proc) {
    auto [tm, mem] = get_time_mem(usage);
    auto ret = check_usage(tm, mem, time_lim, mem_lim);
    if (ret.has_value()) return *ret;
    ret = check_status(status, tm, mem);
    if (ret.has_value()) return *ret;

    if (proc.if_signaled()) {
        jl::prog.println(JLGXY_FMT("monitor process signaled {}"), proc.term_sig());
        return _failed_r;
    }
    if (proc.exit_status() != 0) {
        jl::prog.println(JLGXY_FMT("monitor process exited {}"), proc.exit_status());
        return _failed_r;
    }

    return {verdict_t::_ac, tm, mem, 1.0, 0, ""};
}

pid_t UnsafeCodeRunner::start_tracee(MyPipe &inp, MyPipe &outp, tm_usage_t time_lim,
                                     mem_usage_t mem_lim,
                                     const std::vector<std::string> &args) const {
    if (inp.is_read_closed() || outp.is_read_closed()) {
        jl::prog.println(JLGXY_FMT("Error creating pipe"));
        return -1;
    }
    auto tracee_pid = mpc::start_process([&] {
        prog_.startexe(std::move(inp), std::move(outp), null_pipe(), time_lim, mem_lim, args);
    });
    if (tracee_pid == -1) {
        jl::prog.println(JLGXY_FMT("Error while forking"));
        return -1;
    }
    return tracee_pid;
}
result_t UnsafeCodeRunner::run(int /* id */, const std::string &in_data, std::string &out_data,
                               tm_usage_t time_lim, mem_usage_t mem_lim,
                               const std::vector<std::string> &args) {
    MyPipe inp, outp;
    auto tracee_pid = start_tracee(inp, outp, time_lim, mem_lim, args);
    if (tracee_pid == -1) return _failed_r;

    MyPipe resp;
    if (resp.is_read_closed()) {
        jl::prog.println(JLGXY_FMT("Error creating pipe"));
        return _failed_r;
    }

    mpc::Process io_handler([&] {
        // redirects the tracee's stdin/stdout
        // read the data from tracee's stdout from `outp`, and send to the tracer through `resp`
        signal(SIGPIPE, SIG_IGN);
        outp.close_write();
        inp.close_read();
        resp.close_read();
        std::atomic<bool> success = true;
        std::thread write_thread([&] {
            if (inp.write(in_data) == -1) success = false;
            inp.close_write();
        });
        std::thread read_thread([&] {
            if (outp.read(out_data) == -1) success = false;
            outp.close_read();
        });
        write_thread.join();
        read_thread.join();
        if (success && resp.write(out_data) == -1) success = false;
        resp.close_write();
        if (!success) {
            jl::prog.println(JLGXY_FMT("Error transfering output data"));
            exit(1);
        }
        exit(0);
    });
    if (io_handler.failed()) {
        jl::prog.println(JLGXY_FMT("Error while forking"));
        return _failed_r;
    }

    inp.close();
    outp.close();
    resp.close_write();

    rusage usage;
    int status = tracer.tracerwork(tracee_pid, time_lim, mem_lim, usage);

    if (resp.read(out_data) == -1) {
        jl::prog.println(JLGXY_FMT("Error while reading output"));
        return _failed_r;
    }
    resp.close_read();

    io_handler.join();

    return get_run_result(usage, status, time_lim, mem_lim, io_handler);
}

result_t UnsafeCodeRunner::run_interactive(int /* id */, tm_usage_t time_lim, mem_usage_t mem_lim) {
    MyPipe inp, outp;
    auto tracee_pid = start_tracee(inp, outp, time_lim, mem_lim, {});
    if (tracee_pid == -1) return _failed_r;

    auto inter_proc = mpc::Process([&] {
        auto prog_pid = mpc::start_process([&] {
            inter_prog_.startexe(std::move(outp), std::move(inp), null_pipe(), time_lim, mem_lim,
                                 {});
        });

        inp.close();
        outp.close();
        rusage usage;
        int status = tracer.tracerwork(prog_pid, time_lim, mem_lim, usage);
        exit(WEXITSTATUS(status));
    });

    inp.close();
    outp.close();

    rusage usage;
    int status = tracer.tracerwork(tracee_pid, time_lim, mem_lim, usage);

    inter_proc.join();

    return get_run_result(usage, status, time_lim, mem_lim, inter_proc);
}

verdict_t compile_to(const fs::path &src, const fs::path &exe, const Compiler &compc,
                     const fs::path &tempdir) {
    ProgramWrapper prog;
    prog.source_ = src;
    prog.executable_ = exe;
    verdict_t comp = prog.compile(compc, tempdir);
    if (comp == verdict_t::_failed) return verdict_t::_failed;
    if (comp == verdict_t::_ce) return verdict_t::_ce;
    if (!fs::is_regular_file(exe)) return verdict_t::_ce;
    // if (access(exe.c_str(), F_OK)) return _ce;
    return verdict_t::_ac;
}

std::pair<bool, const Compiler *> find_compiler_by_file(const std::vector<const Compiler *> &comps,
                                                        const fs::path &file) {
    auto it = std::find_if(comps.begin(), comps.end(),
                           [&](const Compiler *compc) { return compc->validfile(file); });
    if (it == comps.end()) return {false, nullptr};
    return std::make_pair(true, *it);
}

std::pair<bool, const Compiler *> find_compiler_by_name(const std::vector<const Compiler *> &comps,
                                                        const std::string_view name) {
    auto it = std::find_if(comps.begin(), comps.end(),
                           [&](const Compiler *compc) { return compc->name == name; });
    if (it == comps.end()) return {false, nullptr};
    return std::make_pair(true, *it);
}

int Judger::get_input(int id) {
    if (config_.input_file.empty()) {
        in_data = read_file(config_.testcase_conf[id].input_file);
    } else {
        copy_file(config_.testcase_conf[id].input_file, config_.input_file);
    }
    return 0;
}
void Judger::clear_output() {
    out_data.clear();
    unlinkat(AT_FDCWD, "user.out", 0);
    if (config_.output_file.empty()) {
    } else {
        unlinkat(AT_FDCWD, config_.output_file.c_str(), 0);
    }
}
int Judger::get_output(int /* id */) const {
    if (config_.output_file.empty()) {
        write_file("user.out", out_data);
    } else {
        copy_file(config_.output_file, "user.out");
    }
    return 0;
}

result_t Judger::run(int id) {
    jl::prog.println(JLGXY_FMT("running on {}"), id);
    clear_output();
    in_data.clear();
    if (get_input(id) == -1) return _failed_r;
    result_t res = _failed_r;
    if (config_.is_interactive) {
        res = runner_.run_interactive(id, config_.testcase_conf[id].time_lim,
                                      config_.testcase_conf[id].mem_lim);
    } else {
        res = runner_.run(id, in_data, out_data, config_.testcase_conf[id].time_lim,
                          config_.testcase_conf[id].mem_lim, {});
    }
    get_output(id);
    if (res.res == verdict_t::_ac) {
        std::string chkout;
        chkrunner_.validinputs_.clear();
        chkrunner_.validinputs_.emplace_back("user.out");
        chkrunner_.validinputs_.emplace_back(config_.testcase_conf[id].input_file);
        chkrunner_.validinputs_.emplace_back(config_.testcase_conf[id].answer_file);
        chkrunner_.validoutputs_.clear();
        chkrunner_.validoutputs_.emplace_back("result.txt");
        result_t chkres = chkrunner_.run(0, "", chkout, 10000, 1 << 20,
                                         {config_.testcase_conf[id].input_file, "user.out",
                                          config_.testcase_conf[id].answer_file, "result.txt"});
        jl::prog.println(JLGXY_FMT("spj ret: {}"), chkres.returnval);
        std::string resstr = read_file("result.txt");
        if (chkres.returnval == 0)
            return {verdict_t::_ac, res.tm_used, res.mem_used, 1.0, res.returnval, resstr};
        if (chkres.returnval == 1)
            return {verdict_t::_wa, res.tm_used, res.mem_used, 0.0, res.returnval, resstr};
        if (chkres.returnval == 2)
            return {verdict_t::_pe, res.tm_used, res.mem_used, 0.0, res.returnval, resstr};
        if (chkres.returnval == 3)
            return {verdict_t::_failed, res.tm_used, res.mem_used, 0.0, res.returnval, resstr};
        if (chkres.returnval == 7) {
            std::string tempstr = resstr;
            std::size_t pos = tempstr.find(' ');
            if (pos != std::string::npos) {
                tempstr.erase(pos);
            }
            double score = std::stod(tempstr);
            return {score >= 1.0 ? verdict_t::_ac : verdict_t::_wa,
                    res.tm_used,
                    res.mem_used,
                    score,
                    res.returnval,
                    resstr};
        }
        return {verdict_t::_failed, res.tm_used, res.mem_used, 0.0, res.returnval, "spj error"};
    }
    return res;
}
list_result_t Judger::run_all(int /* tot_pt */, const fs::path &source, bool compiled) {
    int tot_pt = static_cast<int>(config_.testcase_conf.size());
    assert(tot_pt > 0);
    assert(config_.is_valid());
    runner_.prog_.source_ = source;
    runner_.prog_.executable_ = "./jljudge_main";
    runner_.validinputs_ = {config_.input_file};
    runner_.validoutputs_ = {config_.output_file};
    if (!compiled) {
        auto [found, compc] = find_compiler_by_file(config_.compiler, source);
        if (!found) return {_ce_r};
        verdict_t comp = runner_.prog_.compile(*compc, tempdir);
        if (comp == verdict_t::_failed) return {_failed_r};
        if (comp == verdict_t::_ce) return {_ce_r};
    }
    if (access("./jljudge_main", F_OK)) {
        return {_ce_r};
    }
    chkrunner_.prog_.source_ = config_.checker + ".cpp";
    chkrunner_.prog_.executable_ = "./jljudge_checker";
    if (!compiled) {
        verdict_t compchk = chkrunner_.prog_.compile(*config_.checker_compiler, tempdir);
        if (compchk == verdict_t::_failed) return {_failed_r};
        if (compchk == verdict_t::_ce) return {_ce_r};
    }
    if (access("./jljudge_checker", F_OK)) {
        return {_failed_r};
    }
    if (config_.is_interactive) {
        runner_.inter_prog_.source_ = config_.interactor + ".cpp";
        runner_.inter_prog_.executable_ = "./jljudge_interactor";
        if (!compiled) {
            verdict_t compinter =
                    runner_.inter_prog_.compile(*config_.interactor_compiler, tempdir);
            if (compinter == verdict_t::_failed) return {_failed_r};
            if (compinter == verdict_t::_ce) return {_ce_r};
        }
        if (access("./jljudge_interactor", F_OK)) {
            return {_failed_r};
        }
    }
    list_result_t ans{};
    ans.has_started = true;
    for (int id = 0; id < tot_pt; id++) {
        result_t ver = run(id);
        ans.results.emplace_back(ver);
    }
    return ans;
}

}  // namespace jlgxy

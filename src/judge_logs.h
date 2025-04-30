#pragma once

#include <fcntl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cmath>
#include <cstring>
#include <ios>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

#include "fmt/core.h"

#define JLGXY_FMT_COMPILE 0

#if JLGXY_FMT_COMPILE
#include "fmt/compile.h"
#define JLGXY_FMT FMT_COMPILE
#else
#define JLGXY_FMT FMT_STRING
#endif

namespace jlgxy::jl {

class FileLock {
  public:
    template <typename... Args>
    explicit FileLock(int fd) : fd_(fd) {
        if (flock(fd_, LOCK_EX) == -1) {
            throw std::runtime_error(std::string{"failed to get lock "} + strerror(errno));
        }
    }
    ~FileLock() { flock(fd_, LOCK_UN); }
    auto get_fd() const -> int { return fd_; }

  private:
    const int fd_;
};

inline std::string data;

class ProgressBar {
  public:
    ProgressBar() : main_pid_(getpid()) {
        log_file_fd_ = openat(AT_FDCWD, "log.txt", O_WRONLY | O_APPEND | O_CREAT);
        if (log_file_fd_ == -1) {
            throw std::runtime_error(std::string{"failed to open file "} + strerror(errno));
        }
    }
    ~ProgressBar() {
        finish();
        if (log_file_fd_ != -1) close(log_file_fd_);
    }

    void init() {
        const std::lock_guard guard(lock_);
        if (!isatty(STDOUT_FILENO)) {
            return;
        }
        if (!init_) {
            init_ = true;
            std::cout << "\033[?25l";
            std::cout << std::nounitbuf;
            printbar();
        }
    }
    void finish() {
        const std::lock_guard guard(lock_);
        if (!isatty(STDOUT_FILENO)) {
            return;
        }
        if (init_) {
            clearbar();
            std::cout << "\033[?25h" << std::flush;
            init_ = false;
        }
    }

    auto write_log_to_err(std::string_view s) -> void {
        std::lock_guard guard(file_lock_);
        FileLock f_lock(log_file_fd_);
        ::write(log_file_fd_, s.data(), s.size());
    }

    template <typename... Args>
    auto println(Args... args) -> void {
        if (getpid() != main_pid_) {
            write_log_to_err(fmt::format(std::forward<Args>(args)...) + '\n');
            return;
        }
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << fmt::format(std::forward<Args>(args)...) << '\n';
        printbar();
    }

    template <typename T>
    [[deprecated("use println instead")]]
    auto operator<<(T &&x) -> ProgressBar & {
        if (getpid() != main_pid_) {
            write_log_to_err(x);
            return *this;
        }
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << std::forward<T>(x);
        printbar();
        return *this;
    }

    [[deprecated("use println instead")]]
    auto operator<<(std::ostream &(*pf)(std::ostream &)) -> ProgressBar & {
        if (getpid() != main_pid_) {
            return *this;
        }
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << pf;
        printbar();
        return *this;
    }

    auto setprogress(double prog) -> void {
        if (getpid() != main_pid_) {
            throw std::runtime_error("can't set progress in sub process");
            return;
        }
        const std::lock_guard guard(lock_);
        progress_ = prog;
        clearbar();
        printbar();
    }

  private:
    double progress_ = 0;
    bool init_ = false;
    std::mutex lock_, file_lock_;
    pid_t main_pid_;
    int log_file_fd_{-1};

    auto printbar() const -> void {
        if (!init_ || getpid() != main_pid_) return;

        winsize sz;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &sz) == -1) {
            throw;
        }
        std::cout << "\033[0m";

        int perc = static_cast<int>(std::round(progress_ * 100));
        if (sz.ws_col <= 16) {
            std::cout << perc << "%";
            std::cout << std::flush;
            return;
        }
        int tot = sz.ws_col - 11;
        int fill = static_cast<int>(std::round(tot * progress_));
        int blank = tot - fill;

        std::cout << "[";
        for (int i = 0; i < fill; i++) std::cout << '#';
        for (int i = 0; i < blank; i++) std::cout << '.';
        std::cout << "] ";
        std::cout << "\033[42m";
        std::cout << fmt::format(JLGXY_FMT("[{: >3}%]"), perc);
        std::cout << "\033[0m";
        std::cout << std::flush;
    }
    auto clearbar() const -> void {
        if (!init_ || getpid() != main_pid_) return;
        std::cout << "\033[2K\r" << std::flush;
    }
};

inline jl::ProgressBar prog;

class ProgressBarWrapper {
  public:
    ProgressBarWrapper() { prog.init(); }
    ~ProgressBarWrapper() { prog.finish(); }
};

}  // namespace jlgxy::jl

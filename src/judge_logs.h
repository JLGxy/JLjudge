#pragma once

#include <sys/ioctl.h>
#include <unistd.h>

#include <cmath>
#include <ios>
#include <iostream>
#include <mutex>
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

inline std::string data;

class ProgressBar {
  public:
    ProgressBar() = default;
    ~ProgressBar() { finish(); }

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

    template <typename... Args>
    auto print(Args... args) -> void {
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << fmt::format(std::forward<Args>(args)...);
        printbar();
    }
    template <typename... Args>
    auto println(Args... args) -> void {
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << fmt::format(std::forward<Args>(args)...) << '\n';
        printbar();
    }

    template <typename T>
    [[deprecated("use println instead")]]
    auto operator<<(T &&x) -> ProgressBar & {
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << std::forward<T>(x);
        printbar();
        return *this;
    }

    [[deprecated("use println instead")]]
    auto operator<<(std::ostream &(*pf)(std::ostream &)) -> ProgressBar & {
        const std::lock_guard guard(lock_);
        clearbar();
        std::cout << pf;
        printbar();
        return *this;
    }

    auto setprogress(double prog) -> void {
        const std::lock_guard guard(lock_);
        progress_ = prog;
        clearbar();
        printbar();
    }

  private:
    double progress_ = 0;
    bool init_ = false;
    std::mutex lock_;

    auto printbar() const -> void {
        if (!init_) return;

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
        if (!init_) return;
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

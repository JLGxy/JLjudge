#pragma once

#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <concepts>
#include <csignal>
#include <cstdlib>
#include <functional>
#include <type_traits>
#include <utility>

namespace jlgxy::multiproc {

class Process {
  public:
    Process() = default;
    Process(Process &&o) noexcept
            : pid_(std::exchange(o.pid_, 0)),
              status_(std::exchange(o.status_, 0)),
              alive_(std::exchange(o.alive_, false)),
              fail_(std::exchange(o.fail_, false)) {}
    template <typename T, typename... Args>
        requires(!std::same_as<Process, std::remove_cvref_t<T>>) && std::invocable<T, Args...>
    explicit Process(T &&f, Args &&...args) {
        int pid = fork();
        if (pid == -1) {
            fail_ = true;
            return;
        }
        if (pid == 0) {
            std::invoke(std::forward<T>(f), std::forward<Args...>(args)...);
            exit(0);
        } else {
            pid_ = pid;
            alive_ = true;
        }
    }
    Process(const Process &) = delete;
    ~Process() { join(); }

    void join() {
        if (!alive_) return;
        while (true) {
            int status;
            int wid = waitpid(pid_, &status, 0);
            if (wid == pid_)
                status_ = status;
            else
                break;
        }
        alive_ = false;
    }
    bool is_alive() {
        check_alive();
        return alive_;
    }
    bool failed() const { return fail_; }
    bool if_exited() {
        check_alive();
        return !alive_ && WIFEXITED(status_);
    }
    bool if_signaled() {
        check_alive();
        return !alive_ && WIFSIGNALED(status_);
    }
    int exit_status() {
        check_alive();
        assert(WIFEXITED(status_));
        return WEXITSTATUS(status_);
    }
    int term_sig() {
        check_alive();
        assert(WIFSIGNALED(status_));
        return WTERMSIG(status_);
    }

    int kill(int sig) const { return ::kill(pid_, sig); }
    int pid() const { return pid_; }

  private:
    pid_t pid_{};
    int status_;
    bool alive_{false}, fail_{false};

    void check_alive() {
        while (alive_) {
            int status;
            int wid = waitpid(pid_, &status, WNOHANG | WUNTRACED);
            if (wid == pid_) {
                status_ = status;
                alive_ = test_is_alive();
            } else {
                break;
            }
        }
    }
    bool test_is_alive() const { return kill(0) != -1; }
};

template <typename T, typename... Args>
    requires std::invocable<T, Args...>
pid_t start_process(T &&f, Args &&...args) {
    static_assert(std::is_invocable<typename std::decay<T>::type,
                                    typename std::decay<Args>::type...>::value,
                  "arguments must be invocable after conversion to rvalues");
    int pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        std::invoke(std::forward<T>(f), std::forward<Args...>(args)...);
        exit(0);
    }
    return pid;
}

}  // namespace jlgxy::multiproc

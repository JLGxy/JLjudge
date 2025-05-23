#pragma once

#include <algorithm>
#include <charconv>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "judge_logs.h"

namespace jlgxy::po {

using strvec = std::vector<std::string>;

constexpr auto _size_inf = std::numeric_limits<std::size_t>::max();

class ArgNotFound : public std::exception {
  public:
    std::string what_str_;
    explicit ArgNotFound(std::string_view s) : what_str_(s) {}
    const char *what() const noexcept override { return what_str_.c_str(); }
};
class InvalidArg : public std::exception {
  public:
    std::string what_str_;
    explicit InvalidArg(std::string_view s) : what_str_(s) {}
    const char *what() const noexcept override { return what_str_.c_str(); }
};
class NotExist : public std::exception {
  public:
    std::string what_str_;
    explicit NotExist(std::string_view s) : what_str_(s) {}
    const char *what() const noexcept override { return what_str_.c_str(); }
};

template <typename T>
concept my_number = requires(T num) {
    std::from_chars(std::declval<const char *>(), std::declval<const char *>(), num);
};

class Parser {
  public:
    Parser() = default;
    Parser(const Parser &) = delete;
    Parser(Parser &&) noexcept = default;
    Parser &operator=(const Parser &) = delete;
    Parser &operator=(Parser &&) noexcept = default;

    // `name` must be unique
    void add(const std::string_view name, const char short_name, const std::string_view description,
             bool optional, std::size_t min_arg, std::size_t max_arg) {
        opt_vector_.emplace_back(name, short_name, description, optional, min_arg, max_arg);
    }

    template <typename T>
    T get(std::string_view, const std::optional<T> & = std::nullopt) = delete;
    template <my_number T>
    T get(std::string_view, const std::optional<T> & = std::nullopt);

    void show_usage() {
        std::cerr << "Usage:" << " ";
        std::cerr << name_str_ << " [options]";
        std::cerr << "Options: " << std::endl;
        for (const auto &opt : opt_vector_) {
            std::cerr << "  ";
            if (opt.short_name)
                std::cerr << "    ";
            else
                std::cerr << "-" << opt.short_name << ", ";
            int len = 6;
            len += 2 + static_cast<int>(opt.name.length());
            std::cerr << "--" << opt.name;
            do {
                std::cerr << " ";
                len++;
            } while (len < 16);
            std::cerr << std::endl;
        }
        exit(1);
    }

    void show_version() {
        std::cerr << name_str_ << " " << version_str_ << std::endl;
        exit(1);
    }

    void parse_check(int argc, char **argv) {
        strvec argvec;
        argvec.reserve(argc);
        for (int i = 0; i < argc; i++) argvec.emplace_back(argv[i]);
        for (int i = 1; i < argc; i++) {
            if (argvec[i] == "--help" || argvec[i] == "-h" || argvec[i] == "-?") {
                show_usage();
            }
        }
        for (int i = 1; i < argc; i++) {
            if (argvec[i] == "--version" || argvec[i] == "-v") {
                show_version();
            }
        }

        auto find_opt = [](std::vector<option_value> &v, const option &opt) {
            auto it = std::ranges::find_if(v, [&](const option_value &pr) {
                return std::addressof(pr.first) == std::addressof(opt);
            });
            return it;
        };
        auto add_or_merge = [&find_opt](std::vector<option_value> &v, const option &opt,
                                        std::string_view s) {
            auto it = find_opt(v, opt);
            if (it != v.end()) {
                it->second.emplace_back(s);
            } else {
                v.emplace_back(opt, std::vector{std::string{s}});
            }
        };
        auto add_only = [&find_opt](std::vector<option_value> &v, const option &opt) {
            auto it = find_opt(v, opt);
            if (it == v.end()) {
                v.emplace_back(opt, strvec{});
            }
        };

        for (int i = 1; i < argc; i++) {
            auto &arg = argvec[i];
            if (arg.empty()) throw InvalidArg("empty argument is invalid");
            if (arg[0] != '-') throw InvalidArg("unexpected token");
            if (arg.length() == 1) throw InvalidArg("unexpected token");
            if (arg[1] != '-') {
                const auto &opt = find_option_by_short_name(arg[1]);
                if (arg.length() > 2) {
                    add_or_merge(args_, opt, arg.substr(2));
                } else if (i + 1 < argc && (argvec[i + 1].empty() || argvec[i + 1][0] != '-')) {
                    add_or_merge(args_, opt, argvec[++i]);
                } else {
                    add_only(args_, opt);
                }
            } else {
                if (arg.length() < 3) throw InvalidArg("unexpected token");
                auto pos = arg.find('=');
                if (pos == std::string::npos) pos = arg.length();
                std::string_view namesv(arg.data() + 2, pos - 2);
                const auto &opt = find_option_by_name(namesv);
                if (pos != arg.length()) {
                    add_or_merge(args_, opt, arg.substr(pos + 1));
                } else {
                    add_only(args_, opt);
                }
            }
        }
        for (const auto &[opt, arg] : args_) {
            if (arg.size() < opt.min_cnt || arg.size() > opt.max_cnt)
                throw InvalidArg(fmt::format(
                        JLGXY_FMT("invalid number of argument for {}, expect [{},{}], got {}"),
                        opt.name, opt.min_cnt, opt.max_cnt, arg.size()));
        }
        for (auto &opt : opt_vector_) {
            if (!opt.optional && std::ranges::find_if(args_, [&](const option_value &arg) {
                                     return std::addressof(arg.first) == std::addressof(opt);
                                 }) == args_.end()) {
                throw ArgNotFound("missing argument `" + opt.name + "`");
            }
        }
    }

    void set_name(std::string_view name, std::string_view version) {
        name_str_ = std::string{name};
        version_str_ = std::string{version};
    }

  private:
    struct option {
      public:
        std::string name;
        char short_name;
        std::string desc;
        bool optional;
        std::size_t min_cnt, max_cnt;
        option(std::string_view lname, char sname, std::string_view descr, bool empty,
               std::size_t min_c, std::size_t max_c)
                : name(lname),
                  short_name(sname),
                  desc(descr),
                  optional(empty),
                  min_cnt(min_c),
                  max_cnt(max_c) {}
    };

    using option_value = std::pair<const option &, strvec>;

    std::string name_str_, version_str_;
    std::vector<option> opt_vector_;
    std::vector<option_value> args_;

    const option &find_option_by_name(std::string_view s) const {
        auto it =
                std::ranges::find_if(opt_vector_, [&](const option &opt) { return opt.name == s; });
        if (it == opt_vector_.end()) throw NotExist("no such argument: --" + std::string(s));
        return *it;
    }

    const option &find_option_by_short_name(char s) const {
        auto it = std::ranges::find_if(opt_vector_,
                                       [&](const option &opt) { return opt.short_name == s; });
        if (it == opt_vector_.end()) throw NotExist(std::string("no such argument: -") + s);
        return *it;
    }
    const option_value &get_value_by_name(std::string_view name) {
        auto it = std::ranges::find_if(
                args_, [&](const option_value &arg) -> bool { return arg.first.name == name; });
        if (it == args_.end()) {
            throw ArgNotFound("not found: " + std::string(name));
        }
        return *it;
    }
};

// if such argument exists, return true, otherwise false.
template <>
inline bool Parser::get<bool>(std::string_view name, const std::optional<bool> &) {
    return std::ranges::any_of(
            args_, [&](const option_value &arg) -> bool { return arg.first.name == name; });
}

// find such argument and return in std::string. if there's no such argument, return `default_value`
// if given or throw if not.
template <>
inline std::string Parser::get<std::string>(std::string_view name,
                                            const std::optional<std::string> &default_value) {
    try {
        const auto &val = get_value_by_name(name);
        if (val.second.size() != 1)
            throw InvalidArg(fmt::format(JLGXY_FMT("expected 1 argument for {}, got {}"), name,
                                         val.second.size()));
        return val.second.front();
    } catch (ArgNotFound &e) {
        if (default_value.has_value()) return default_value.value();
        throw e;
    }
}

// find such argument and return in strvec. if there's no such argument, return
// `default_value` if given or throw if not.
template <>
inline strvec Parser::get<strvec>(std::string_view name,
                                  const std::optional<strvec> &default_value) {
    try {
        const auto &val = get_value_by_name(name);
        return val.second;
    } catch (ArgNotFound &e) {
        if (default_value.has_value()) return default_value.value();
        throw e;
    }
}

template <my_number T>
inline T to_int(std::string_view s) {
    T ret;
    if (std::from_chars(s.begin(), s.end(), ret).ec == std::errc{}) return ret;
    throw std::runtime_error("the string can't be converted to a number");
}

template <my_number T>
inline T Parser::get(std::string_view name, const std::optional<T> &default_value) {
    try {
        const auto &val = get_value_by_name(name);
        if (val.second.size() != 1)
            throw InvalidArg(fmt::format(JLGXY_FMT("expected 1 argument for {}, got {}"), name,
                                         val.second.size()));
        return to_int<T>(val.second.front());
    } catch (ArgNotFound &e) {
        if (default_value.has_value()) return default_value.value();
        throw e;
    }
}

class CommandBase {
  public:
    virtual ~CommandBase() = default;
    virtual std::string_view get_name() = 0;
    virtual std::string_view get_desc() = 0;
    virtual void init_parser() = 0;
    virtual int run() = 0;
    Parser parser;
};

class CommandHandler {
  public:
    void add_command(std::unique_ptr<CommandBase> ptr) {
        ptr->init_parser();
        cmd_vector_.emplace_back(std::move(ptr));
    }

    void show_usage() const {
        std::cerr << "Usage: " << name_str_ << " [command] [options]" << std::endl;
        std::cerr << "Commands:" << std::endl;
        for (const auto &cmd : cmd_vector_) {
            std::cerr << "  " << cmd->get_name() << std::endl;
        }
        exit(1);
    }

    void show_version() {
        std::cerr << name_str_ << " " << version_str_ << std::endl;
        exit(1);
    }

    std::pair<std::string, int> parse(int argc, char **argv) {
        if (argc <= 1) show_usage();
        std::string_view tcmd = argv[1];
        auto it = std::ranges::find_if(cmd_vector_, [&](const std::unique_ptr<CommandBase> &cmd) {
            return cmd->get_name() == tcmd;
        });
        if (it == cmd_vector_.end()) {
            throw NotExist("unknown command `" + std::string{tcmd} + "`");
        }
        auto &ptr = *it;
        ptr->parser.parse_check(argc - 1, argv + 1);
        return {std::string{ptr->get_name()}, ptr->run()};
    }

    void set_name(std::string_view name, std::string_view version) {
        name_str_ = std::string{name};
        version_str_ = std::string{version};
    }

  private:
    std::string name_str_, version_str_;
    std::vector<std::unique_ptr<CommandBase>> cmd_vector_;
};

}  // namespace jlgxy::po

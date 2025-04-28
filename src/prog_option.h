#pragma once

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jlgxy::po {

class Parser {
  public:
    void add_string(const std::string_view name, const char short_name,
                    const std::string_view description, bool optional = true) {
        opt_vector_.emplace_back(name, short_name, description, optional, false);
    }
    void add_bool(const std::string_view name, const char short_name,
                  const std::string_view description, bool optional = true) {
        opt_vector_.emplace_back(name, short_name, description, optional, true);
    }

    template <typename T>
    T get(std::string_view) = delete;

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
        std::vector<std::string> argvec;
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
        for (int i = 1; i < argc; i++) {
            auto &arg = argvec[i];
            if (arg.empty()) throw std::runtime_error("empty argument is invalid");
            if (arg[0] != '-') throw std::runtime_error("unexpected token");
            if (arg.length() == 1) throw std::runtime_error("unexpected token");
            if (arg[1] != '-') {
                const auto &opt = find_option_by_short_name(arg[1]);
                if (arg.length() > 2) {
                    args_.emplace_back(opt, arg.substr(2));
                } else if (i < argc - 1 && (argvec[i + 1].empty() || argvec[i + 1][0] != '-')) {
                    args_.emplace_back(opt, argvec[++i]);
                } else {
                    args_.emplace_back(opt, "");
                }
            } else {
                if (arg.length() < 3) throw std::runtime_error("unexpected token");
                auto pos = arg.find('=');
                if (pos == std::string::npos) pos = arg.length();
                std::string_view namesv(arg.data() + 2, pos - 2);
                const auto &opt = find_option_by_name(namesv);
                if (pos != arg.length()) {
                    args_.emplace_back(opt, arg.substr(pos + 1));
                } else {
                    args_.emplace_back(opt, "");
                }
            }
        }
        for (const auto &[opt, arg] : args_) {
            if (opt.is_bool && !arg.empty()) throw std::runtime_error("unexpected token");
        }
        for (auto &opt : opt_vector_) {
            if (!opt.optional &&
                std::find_if(args_.begin(), args_.end(),
                             [&](const std::pair<const option &, std::string> &arg) {
                                 return std::addressof(arg.first) == std::addressof(opt);
                             }) == args_.end()) {
                throw std::runtime_error("missing argument `" + opt.name + "`");
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
        bool is_bool;
        option(std::string_view lname, char sname, std::string_view descr, bool empty,
               bool is_boolean)
                : name(lname),
                  short_name(sname),
                  desc(descr),
                  optional(empty),
                  is_bool(is_boolean) {}
    };

    std::string name_str_, version_str_;
    std::vector<option> opt_vector_;
    std::vector<std::pair<const option &, std::string>> args_;

    const option &find_option_by_name(std::string_view s) {
        auto it = std::find_if(opt_vector_.begin(), opt_vector_.end(),
                               [&](const option &opt) { return opt.name == s; });
        if (it == opt_vector_.end())
            throw std::runtime_error("invalid argument --" + std::string(s));
        return *it;
    }

    const option &find_option_by_short_name(char s) {
        auto it = std::find_if(opt_vector_.begin(), opt_vector_.end(),
                               [&](const option &opt) { return opt.short_name == s; });
        if (it == opt_vector_.end())
            throw std::runtime_error(std::string("invalid argument -") + s);
        return *it;
    }
};

template <>
inline bool Parser::get<bool>(std::string_view name) {
    return std::any_of(args_.begin(), args_.end(),
                       [&](const std::pair<const option &, std::string> &arg) -> bool {
                           return arg.first.name == name;
                       });
}

template <>
inline std::string Parser::get<std::string>(std::string_view name) {
    auto it = std::find_if(args_.begin(), args_.end(),
                           [&](const std::pair<const option &, std::string> &arg) -> bool {
                               return arg.first.name == name;
                           });
    if (it == args_.end()) throw std::runtime_error("missing argument: " + std::string(name));
    return it->second;
}

class CommandHandler {
  public:
    void add_command(const std::string_view cmd, Parser &parser, const std::string_view desc) {
        cmd_vector_.emplace_back(std::string(cmd), parser, desc);
    }

    void show_usage() const {
        std::cerr << "Usage: " << name_str_ << " [command] [options]" << std::endl;
        std::cerr << "Commands:" << std::endl;
        for (const auto &[cmd, psr, desc] : cmd_vector_) {
            std::cerr << "  " << cmd << std::endl;
        }
        exit(1);
    }

    void show_version() {
        std::cerr << name_str_ << " " << version_str_ << std::endl;
        exit(1);
    }

    std::string parse(int argc, char **argv) {
        if (argc <= 1) show_usage();
        std::string_view tcmd = argv[1];
        auto it = std::find_if(cmd_vector_.begin(), cmd_vector_.end(),
                               [&](const subcmd &cmd) { return cmd.name == tcmd; });
        if (it == cmd_vector_.end()) {
            throw std::runtime_error("unknown command `" + std::string{tcmd} + "`");
        }
        it->parser.parse_check(argc - 1, argv + 1);
        return it->name;
    }

    void set_name(std::string_view name, std::string_view version) {
        name_str_ = std::string{name};
        version_str_ = std::string{version};
    }

  private:
    struct subcmd {
        std::string name;
        Parser &parser;
        std::string desc;
        subcmd(std::string_view name_, Parser &parser_, std::string_view descr_)
                : name(name_), parser(parser_), desc(descr_) {}
    };
    std::string name_str_, version_str_;
    std::vector<subcmd> cmd_vector_;
};

}  // namespace jlgxy::po

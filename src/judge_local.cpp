//
// Copyright (c) 2024-2025 JLGxy, a1co0av5ce5az1cz0ap_
//

#include "judge_local.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#define FMT_ENFORCE_COMPILE_STRING 1

#include "config.h"
#include "fmt/core.h"
#include "html_templates.h"
#include "judge_core.h"
#include "judge_logs.h"
#include "prog_option.h"
#include "xlsxwriter.h"     // IWYU pragma: keep
#include "yaml-cpp/yaml.h"  // IWYU pragma: keep

namespace jlgxy {

TestdirWrapper::TestdirWrapper(fs::path t) : pth_(std::move(t)) {
    if (fs::is_directory(pth_)) {
        fs::remove_all(pth_);
    }
    fs::create_directories(pth_);
}
fs::path TestdirWrapper::getpath() const { return pth_; }
TestdirWrapper::~TestdirWrapper() { fs::remove_all(pth_); }

JudgeOne::JudgeOne(fs::path dd, fs::path td, std::string ss)
        : data_dir_(std::move(dd)), temp_dir_(std::move(td)), rstr_(std::move(ss)) {}

list_result_t JudgeOne::run(const fs::path &code_file, const conf_t &config) const {
    TestdirWrapper wr(temp_dir_ / randstr());
    fs::path test_dir = wr.getpath();
    if (fs::exists(test_dir)) {
        fs::remove_all(test_dir);
    }
    fs::copy(data_dir_, test_dir, fs::copy_options::recursive);
    fs::copy(code_file, test_dir);

    std::string user_name = code_file.parent_path().parent_path().filename();
    std::string prob_name = code_file.parent_path().filename();

    const auto cur_dir = fs::current_path();
    fs::current_path(test_dir);
    Judger judge(temp_dir_, config);
    // judge.config_ = config;
    fs::path compiled = temp_dir_ / get_name(user_name, prob_name, "", rstr_);
    fs::copy_file(compiled, "./jljudge_main");
    try {
        fs::path checker_compiled = temp_dir_ / get_name("chk", prob_name, "chk", rstr_);
        fs::copy_file(checker_compiled, "./jljudge_checker");
        if (config.is_interactive) {
            fs::path interactor_compiled = temp_dir_ / get_name("ina", prob_name, "ina", rstr_);
            fs::copy_file(interactor_compiled, "./jljudge_interactor");
        }
    } catch (std::exception &e) {
        fs::current_path(cur_dir);
        return {_failed_r};
    }
    list_result_t ress = judge.run_all_ordered(0, "", true);
    fs::current_path(cur_dir);

    return ress;
}

void read_contest_config(const fs::path &file, contest_conf_t &contest_conf) {
    contest_conf = contest_conf_t();
    std::ifstream conf_stream(file);
    YAML::Node node = YAML::Load(conf_stream);

    for (std::size_t i = 0; i < node["problems"].size(); i++) {
        const auto &cur_node = node["problems"][i];
        contest_conf.problems.emplace_back(cur_node.as<std::string>());
        contest_conf.prob_id[cur_node.as<std::string>()] = static_cast<int>(i);
    }
    if (contest_conf.prob_id.size() < node["problems"].size()) {
        throw JudgeError(file.filename().string() + ": problem name should be unique");
    }
}

table_t to_table(const all_res_t &res, const std::vector<std::pair<std::string, conf_t>> &probs) {
    std::unordered_map<std::string, std::pair<int, const conf_t *>> probid;
    table_t tab(res.r.size(), probs.size());
    for (std::size_t i = 0; i < probs.size(); i++) {
        probid.emplace(probs[i].first, std::make_pair(i, &probs[i].second));
        tab.cols[i] = probs[i].first;
    }
    for (std::size_t i = 0; i < res.r.size(); i++) {
        const auto &[user_name, user_res] = res.r[i];
        tab.rows[i] = user_name;
        for (const auto &sub : user_res.subs) {
            const auto &[j, conf] = probid[sub.prob_name];
            scores_t cur_score = sub.result.list_res.calc_score(*conf);
            tab.tab[i][j] = cur_score.score;
        }
    }
    return tab;
}

namespace sb_base64 {

std::string base64_encode(const std::string_view text) {
    std::string ret;
    std::size_t i;
    for (i = 0; i + 3 <= text.length(); i += 3) {
        ret.push_back(_alphabet_map[text[i] >> 2]);
        ret.push_back(_alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)]);
        ret.push_back(_alphabet_map[((text[i + 1] << 2) & 0x3c) | (text[i + 2] >> 6)]);
        ret.push_back(_alphabet_map[text[i + 2] & 0x3f]);
    }

    if (i < text.length()) {
        std::size_t tail = text.length() - i;
        if (tail == 1) {
            ret.push_back(_alphabet_map[text[i] >> 2]);
            ret.push_back(_alphabet_map[(text[i] << 4) & 0x30]);
            ret.push_back('=');
            ret.push_back('=');
        } else {
            ret.push_back(_alphabet_map[text[i] >> 2]);
            ret.push_back(_alphabet_map[((text[i] << 4) & 0x30) | (text[i + 1] >> 4)]);
            ret.push_back(_alphabet_map[(text[i + 1] << 2) & 0x3c]);
            ret.push_back('=');
        }
    }
    return ret;
}

}  // namespace sb_base64

namespace save {

template <int Len, typename It, typename Num>
void num_to_bytes(It &&it, Num x) {
    std::vector<std::byte> r;
    for (int i = 0; i < Len; i++) {
        *(it++) = std::byte{static_cast<unsigned char>(x & 0xff)};
        x >>= 8;
    }
}

template <typename It>
void double_to_bytes(It &&it, double x) {
    auto *pt = reinterpret_cast<std::byte *>(&x);
    it = std::copy(pt, pt + 8, it);
}

template <typename It>
void bool_to_bytes(It &&it, bool x) {
    *(it++) = std::byte(x);
}

template <typename It>
void string_to_bytes(It &&it, const std::string_view s) {
    num_to_bytes<4>(it, s.length());
    for (auto c : s) *(it++) = static_cast<std::byte>(c);
}

template <typename Int, int Len, typename It>
Int read_num(It &&it) {
    Int r = 0;
    for (int i = 0; i < Len; i++) r = r | (std::to_integer<Int>(*(it++)) << (i << 3));
    return r;
}

template <typename It>
double read_double(It &&it) {
    auto *pt = reinterpret_cast<double *>(&*it);
    it += 8;
    return *pt;
}

template <typename It>
bool read_bool(It &&it) {
    return std::to_integer<int>(*(it++));
}

template <typename It>
std::string read_string(It &&it) {
    int len = read_num<int, 4>(it);
    std::string s;
    s.reserve(len);
    for (int i = 0; i < len; i++) s.push_back(std::to_integer<char>(*(it++)));
    return s;
}

template <typename It>
verdict_t read_verdict(It &&it) {
    return verdict_t(read_num<short, 2>(it));
}

template <typename It>
void result_to_binary(It &&it, const result_t &r) {
    num_to_bytes<2>(it, static_cast<int>(r.res));
    num_to_bytes<8>(it, r.tm_used);
    num_to_bytes<8>(it, r.mem_used);
    double_to_bytes(it, r.score);
    num_to_bytes<4>(it, r.returnval);
    string_to_bytes(it, r.info);
}
template <typename It>
result_t result_from_binary(It &&it) {
    result_t res{verdict_t::_wt, 0, 0, 0, 0, ""};
    res.res = read_verdict(it);
    res.tm_used = read_num<tm_usage_t, 8>(it);
    res.mem_used = read_num<mem_usage_t, 8>(it);
    res.score = read_double(it);
    res.returnval = read_num<int, 4>(it);
    res.info = read_string(it);
    return res;
}

template <typename It>
void scores_to_binary(It &&it, const scores_t &s) {
    num_to_bytes<4>(it, s.scores.size());
    for (auto d : s.scores) {
        double_to_bytes(it, d);
    }
    double_to_bytes(it, s.score);
    num_to_bytes<2>(it, static_cast<int>(s.final_verdict));
}
template <typename It>
scores_t scores_from_binary(It &&it) {
    scores_t s;
    int len;
    len = read_num<int, 4>(it);
    for (int i = 0; i < len; i++) s.scores.emplace_back(read_double(it));
    s.score = read_double(it);
    s.final_verdict = read_verdict(it);
    return s;
}

template <typename It>
void list_result_to_binary(It &&it, const list_result_t &r) {
    bool_to_bytes(it, r.has_started);
    num_to_bytes<4>(it, r.results.size());
    for (const auto &t : r.results) {
        result_to_binary(it, t);
    }
}
template <typename It>
list_result_t list_result_from_binary(It &&it) {
    list_result_t r{};
    r.has_started = read_bool(it);
    int len = read_num<int, 4>(it);
    for (int i = 0; i < len; i++) {
        r.results.emplace_back(result_from_binary(it));
    }
    return r;
}

template <typename It>
void user_res_to_binary(It &&it, const user_res_t &r) {
    num_to_bytes<4>(it, r.subs.size());
    for (const auto &sub : r.subs) {
        string_to_bytes(it, sub.prob_name);
        list_result_to_binary(it, sub.result.list_res);
        scores_to_binary(it, sub.result.sco);
        num_to_bytes<8>(it, sub.code_len);
        string_to_bytes(it, sub.compiler->name);
        num_to_bytes<8>(
                it, chrono::duration_cast<judge_time_duration>(sub.judge_time.time_since_epoch())
                            .count());
    }
}
template <typename It>
user_res_t user_res_from_binary(It &&it, std::string_view user_name,
                                const std::vector<const Compiler *> &comps) {
    user_res_t r;
    int len = read_num<int, 4>(it);
    for (int i = 0; i < len; i++) {
        std::string prob_name = read_string(it);
        auto lr = list_result_from_binary(it);
        auto sc = scores_from_binary(it);
        auto len = read_num<std::size_t, 8>(it);
        auto compname = read_string(it);
        auto time_tick = read_num<judge_time_duration::rep, 8>(it);
        sub_info_t sub;
        sub.prob_name = std::move(prob_name);
        sub.user_name = std::string(user_name);
        sub.code_len = len;
        sub.judge_time = chrono::system_clock::time_point(judge_time_duration(time_tick));
        auto [found, compc] = find_compiler_by_name(comps, compname);
        if (!found) {
            throw JudgeError("unknown compiler: " + compname);
        }
        sub.compiler = compc;
        sub.result.list_res = std::move(lr);
        sub.result.sco = std::move(sc);
        r.subs.emplace_back(std::move(sub));
    }
    return r;
}

template <typename It>
void all_res_to_binary(It &&it, const all_res_t &r) {
    num_to_bytes<4>(it, r.r.size());
    for (const auto &[user_name, user_res] : r.r) {
        string_to_bytes(it, user_name);
        user_res_to_binary(it, user_res);
    }
}
template <typename It>
all_res_t all_res_from_binary(It &&it, const std::vector<const Compiler *> &comps) {
    all_res_t r;
    int len = read_num<int, 4>(it);
    for (int i = 0; i < len; i++) {
        std::string user_name = read_string(it);
        auto cur_ures = user_res_from_binary(it, user_name, comps);
        // for(auto &sub: cur_ures.subs) sub.user_name = user_name;
        r.r.emplace_back(user_name, std::move(cur_ures));
    }
    return r;
}

void print_binary(const std::vector<std::byte> &v) {
    std::string s;
    for (auto c : v) s += fmt::format(JLGXY_FMT("{} "), c);
    jl::prog.println(JLGXY_FMT("{}"), s);
}

void save_file(const fs::path &file, const all_res_t &r) {
    std::vector<std::byte> vec;
    vec.emplace_back(std::byte{'L'});
    vec.emplace_back(std::byte{'J'});
    num_to_bytes<8>(std::back_inserter(vec), 1L);
    all_res_to_binary(std::back_inserter(vec), r);
    std::ofstream(file, std::ios::binary)
            .write(reinterpret_cast<char *>(vec.data()), static_cast<std::streamsize>(vec.size()));
}

all_res_t load_file(const fs::path &file, const std::vector<const Compiler *> &comps) {
    if (!fs::is_regular_file(file)) {
        throw JudgeError("judge data not found");
    }
    std::vector<std::byte> vec;
    std::ifstream fin(file, std::ios::binary);
    std::vector<char> out_buf(1 << 26);
    while (fin) {
        fin.read(out_buf.data(), static_cast<std::streamsize>(out_buf.size()));
        vec.resize(vec.size() + fin.gcount());
        auto *pt = reinterpret_cast<char *>(vec.data() + vec.size() - fin.gcount());
        memcpy(pt, out_buf.data(), fin.gcount());
    }
    return all_res_from_binary(vec.begin() + 10, comps);
}

}  // namespace save

void generateexcel(const table_t &table, time_t st, time_t run, time_t ed) {
    time_t now_c = time(nullptr);
    const auto fn = "result" + localstr(now_c, "-%Y%m%d-%H%M%S") + ".xlsx";
    jl::prog.println(JLGXY_FMT("{}"), fn);
    lxw_workbook *workbook = workbook_new(fn.c_str());
    lxw_worksheet *worksheet = workbook_add_worksheet(workbook, "score");

    worksheet_protect(worksheet, nullptr, nullptr);

    if (workbook == nullptr) throw;
    if (worksheet == nullptr) throw;

    int row = 0;
    do {
        int col = 0;
        for (const auto &s : table.cols) {
            worksheet_write_string(worksheet, row, ++col, s.c_str(), nullptr);
        }
        worksheet_write_string(worksheet, row, ++col, "total", nullptr);
    } while (false);
    for (int i = 0; i < static_cast<int>(table.rows.size()); i++) {
        ++row;
        int col = 0;
        worksheet_write_string(worksheet, row, col, table.rows[i].c_str(), nullptr);
        double sum = 0;
        for (auto c : table.tab[i]) {
            worksheet_write_number(worksheet, row, ++col, c, nullptr);
            sum += c;
        }
        worksheet_write_number(worksheet, row, ++col, sum, nullptr);
    }

    // lxw_format *format = workbook_add_format(workbook);
    // format_set_num_format(format, "yyyy/mm/dd hh:mm:ss");
    worksheet_write_string(worksheet, row + 2, 0, "start time:", nullptr);
    worksheet_write_string(worksheet, row + 2, 1, localstr(st, "%Y/%m/%d %H:%M:%S").c_str(),
                           nullptr);
    worksheet_write_string(worksheet, row + 3, 0, "end time:", nullptr);
    worksheet_write_string(worksheet, row + 3, 1, localstr(ed, "%Y/%m/%d %H:%M:%S").c_str(),
                           nullptr);
    worksheet_write_string(worksheet, row + 4, 0, "total used:", nullptr);
    worksheet_write_number(worksheet, row + 4, 1, static_cast<double>(ed - st), nullptr);
    worksheet_write_string(worksheet, row + 5, 0, "compiling used:", nullptr);
    worksheet_write_number(worksheet, row + 5, 1, static_cast<double>(run - st), nullptr);
    worksheet_write_string(worksheet, row + 6, 0, "running used", nullptr);
    worksheet_write_number(worksheet, row + 6, 1, static_cast<double>(ed - run), nullptr);

    worksheet_set_column(worksheet, 0, 0, 18, nullptr);
    worksheet_set_column(worksheet, 1, table.cols.size() + 1, 10, nullptr);

    workbook_close(workbook);
}

void submission_set::init() {
    for (const auto &[user, prob] : mp) {
        users.emplace(user);
        probs.emplace(prob);
    }
}
bool submission_set::contains_prob(const std::string_view prob) const {
    return (probs.find("*") != probs.end()) || (probs.find(prob) != probs.end());
}
bool submission_set::contains(const std::string_view user, const std::string_view prob) const {
    return mp.find(std::make_pair("*"sv, "*"sv)) != mp.end() ||
           mp.find(std::make_pair(user, "*"sv)) != mp.end() ||
           mp.find(std::make_pair("*"sv, prob)) != mp.end() ||
           mp.find(std::make_pair(user, prob)) != mp.end();
}
void submission_set::loads_from_args(int argc, char **argv) {
    if (!argc) {
        mp = {{"*", "*"}};
    } else {
        for (int i = 0; i < argc; i++) {
            std::string rs = argv[i];
            auto m = rs.find('/');
            if (m == std::string::npos) {
                jl::prog.println(JLGXY_FMT("Invalid argument: \"{}\""), rs);
                exit(1);
            }
            auto m2 = rs.find('/', m + 1);
            if (m2 != std::string::npos) {
                jl::prog.println(JLGXY_FMT("Invalid argument: \"{}\""), rs);
                exit(1);
            }
            if (m == 0 || m + 1 == rs.length()) {
                jl::prog.println(JLGXY_FMT("Invalid argument: \"{}\""), rs);
                exit(1);
            }
            mp.emplace(rs.substr(0, m), rs.substr(m + 1));
        }
    }
    init();
}
void submission_set::loads_from_args(const std::vector<std::string> &args) {
    std::vector<char *> carg;
    carg.reserve(args.size());
    for (const auto &arg : args) carg.emplace_back(const_cast<char *>(arg.c_str()));
    return loads_from_args(static_cast<int>(carg.size()), carg.data());
}

void print_problem_config_warning(const std::string_view name, const std::string_view what_arg) {
    jl::prog.println(JLGXY_FMT("\033[35m\033[1mwarning:\033[0m in problem {}:"), name);
    jl::prog.println(JLGXY_FMT("  {}"), what_arg);
}

tm_usage_t get_tot_judge_time(const conf_t &config) {
    tm_usage_t ret = 0;
    for (const auto &tc : config.testcase_conf) {
        ret += tc.time_lim;
    }
    return ret;
}

int compare_strint(std::string_view a, std::string_view b) {
    auto oa = a, ob = b;
    while (a.size() > 1 && a[0] == '0') a = a.substr(1);
    while (b.size() > 1 && b[0] == '0') b = b.substr(1);
    if (a.length() != b.length()) return a.length() < b.length() ? -1 : 1;
    int r = a.compare(b);
    if (r) return r;
    return oa.compare(ob);
}

int compare_filename(const std::string_view a, const std::string_view b) {
    auto read_int = [](const std::string_view s) {
        std::size_t len = 0;
        while (len < s.size() && std::isdigit(s[len])) len++;
        return s.substr(0, len);
    };
    std::size_t cur = 0;
    while (cur < a.size() && cur < b.size()) {
        if (std::isdigit(a[cur]) != std::isdigit(b[cur])) {
            return std::isdigit(a[cur]) > std::isdigit(b[cur]) ? -1 : 1;
        }
        if (!std::isdigit(a[cur])) {
            if (a[cur] != b[cur]) return a[cur] < b[cur] ? -1 : 1;
            cur++;
        } else {
            int r = compare_strint(read_int(a.substr(cur)), read_int(b.substr(cur)));
            if (r) return r;
            while (cur < a.size() && std::isdigit(a[cur])) cur++;
        }
    }
    if (a.size() == b.size()) return 0;
    return a.size() < b.size() ? -1 : 1;
}

JudgeAll::JudgeAll(fs::path dd, fs::path sd, fs::path td)
        : data_dir(std::move(dd)),
          source_dir(std::move(sd)),
          temp_dir(std::move(td)),
          rstr_(randstr(4)) {
    temp_dir /= randstr();
    if (!fs::is_directory(data_dir)) {
        throw JudgeError("can't find data directory");
    }
    if (!fs::is_directory(source_dir)) {
        throw JudgeError("can't find source directory");
    }
    fs::create_directories(temp_dir);
}
JudgeAll::~JudgeAll() { fs::remove_all(temp_dir); }

void JudgeAll::add_range(const std::vector<std::pair<std::string, std::string>> &s) {
    for (const auto &[u, p] : s) subs.mp.emplace(u, p);
    subs.init();
}

// TODO(JLGxy): test
// TODO(JLGxy): more language support
void JudgeAll::load_compilers() {
    const fs::path conf_file(data_dir / "contest.yaml");
    std::ifstream conf_stream(conf_file);
    YAML::Node node = YAML::Load(conf_stream);

    node.begin();
    for (auto curnode : node["compilers"]) {
        std::unique_ptr<Compiler> compp(std::make_unique<Compiler>());
        compp->name = (curnode["name"]).as<std::string>();
        compp->compiler = (curnode["path"]).as<std::string>();
        for (auto snode : curnode["args"]) {
            compp->argvec.emplace_back(snode.as<std::string>());
        }
        for (auto snode : curnode["suffixes"]) {
            compp->suffix.emplace_back(snode.as<std::string>());
        }
        compilers.emplace_back(std::move(compp));
    }
    for (const auto &pt : compilers) compilers_p.emplace_back(pt.get());
}

void JudgeAll::judge_main() {
    // redirect_err();

    const jl::ProgressBarWrapper progressbar;
    load_probs();

    cur_prop_ = 0.1;
    // auto start_time = std::time(nullptr);
    get_problem_compile_list();
    compile_all();
    check_problem_compile_files();

    tasks_.clear();
    for (const auto &user_entry : fs::directory_iterator(source_dir)) {
        if (!user_entry.is_directory()) continue;
        const std::string user_name = user_entry.path().filename();
        for (const auto &[prob_name, config] : probs) {
            if (!subs.contains(user_name, prob_name)) continue;
            auto [found_code, compc, code] = find_code_at(user_entry.path() / prob_name, config);
            if (found_code) {
                tasks_.push_back(
                        {user_entry.path(), user_name, prob_name, config, compc, std::move(code)});
            }
        }
    }

    base_prop_ = 0.1;
    cur_prop_ = 0.2;
    get_user_compile_list();
    compile_all();
    // auto start_running = std::time(nullptr);

    base_prop_ = 0.3;
    cur_prop_ = 0.7;
    tm_usage_t tot_run_time = 0, cur_run_time = 0;
    for (const auto &t : tasks_) {
        tot_run_time += get_tot_judge_time(t.config);
    }
    std::map<std::string, user_res_t> all_user_res;
    for (const auto &t : tasks_) {
        user_res_t &user_res = all_user_res[t.user_name];
        jl::prog.println(JLGXY_FMT("testing -- {}::{}"), t.user_name, t.prob_name);
        std::size_t sz = fs::file_size(t.code);
        sub_info_t sub;
        sub.prob_name = t.prob_name;
        sub.user_name = t.user_name;
        sub.code_len = sz;
        sub.judge_time = chrono::system_clock::now();
        sub.compiler = t.compc;

        fs::path exe = temp_dir / get_name(t.user_name, t.prob_name, "", rstr_);
        if (fs::is_regular_file(exe)) {
            JudgeOne runs(data_dir / t.prob_name, temp_dir, rstr_);
            list_result_t rs = runs.run(t.code, t.config);
            sub.result.list_res = std::move(rs);
        } else {
            sub.result.list_res = list_result_t{_ce_r};
        }
        user_res.subs.emplace_back(std::move(sub));
        cur_run_time += get_tot_judge_time(t.config);
        prop_ = base_prop_ +
                cur_prop_ * static_cast<double>(cur_run_time) / static_cast<double>(tot_run_time);
        jl::prog.setprogress(prop_);
    }
    for (auto &[user_name, user_res] : all_user_res) {
        all_res.r.emplace_back(user_name, std::move(user_res));
    }
    merge_user();
    calc_all_score();

    save_file();
    export_results();
}

void JudgeAll::merge_user() {
    if (all_res.r.empty()) return;
    sort(all_res.r.begin(), all_res.r.end(),
         [](const std::pair<std::string, user_res_t> &a,
            const std::pair<std::string, user_res_t> &b) { return a.first < b.first; });
    std::size_t lst = 0;
    for (std::size_t i = 1; i < all_res.r.size(); i++) {
        if (all_res.r[i].first == all_res.r[lst].first) {
            std::copy(std::make_move_iterator(all_res.r[i].second.subs.begin()),
                      std::make_move_iterator(all_res.r[i].second.subs.end()),
                      std::back_inserter(all_res.r[lst].second.subs));
        } else {
            ++lst;
            if (lst != i) all_res.r[lst] = std::move(all_res.r[i]);
        }
    }
    all_res.r.resize(lst + 1);
}

void JudgeAll::remove_range() {
    for (auto &[user_name, user_res] : all_res.r) {
        const auto &un = user_name;
        auto it =
                std::remove_if(user_res.subs.begin(), user_res.subs.end(),
                               [&](const sub_info_t &s) { return subs.contains(un, s.prob_name); });
        user_res.subs.erase(it, user_res.subs.end());
    }
}

void JudgeAll::load_project() { all_res = save::load_file(_projectfile, compilers_p); }

void JudgeAll::load_probs() {
    probs.clear();
    read_contest_config(data_dir / "contest.yaml", contest_config);
    for (const auto &prob_name : contest_config.problems) {
        fs::directory_entry prob_entry(data_dir / prob_name);
        if (!prob_entry.is_directory()) {
            throw ProblemConfigError(prob_name, "can't find problem directory");
        }
        auto conf_file = prob_entry.path() / "conf.yaml";
        if (!fs::is_regular_file(conf_file)) {
            throw ProblemConfigError(prob_name, "can't find problem config file");
        }
        conf_t config;
        try {
            read_config(conf_file, config);
        } catch (std::exception &e) {
            // rethrow
            throw ProblemConfigError(prob_name, e.what());
        }
        if (config.name != prob_name) {
            throw ProblemConfigError(prob_name,
                                     "The problem name should be same as the directory name.");
        }
        probs.emplace_back(prob_name, std::move(config));
    }
    check_valid();
}

// TODO(JLGxy): export statistics
void JudgeAll::export_results() {
    // auto end_time = std::time(nullptr);
    // std::cout << all_res.to_str() << std::endl;
    // auto table = to_table(all_res, probs);
    // generateexcel(table, start_time, start_running, end_time);
    for (auto &[user_name, user_res] : all_res.r) {
        sort(user_res.subs.begin(), user_res.subs.end(),
             [&](const sub_info_t &a, const sub_info_t &b) {
                 return contest_config.prob_id.at(a.prob_name) <
                        contest_config.prob_id.at(b.prob_name);
             });
    }
    time_t now_c = time(nullptr);
    auto result_name = "result" + localstr(now_c, "-%Y%m%d-%H%M%S") + ".html";
    jl::prog.println(JLGXY_FMT("saved to: {}"), result_name);
    std::ofstream(result_name) << generate_html();
}

std::pair<double, double> JudgeAll::calc_sd(const std::vector<double> &s) {
    double mean = std::accumulate(s.begin(), s.end(), 0.0) / static_cast<double>(s.size());
    double vari = 0.0;
    for (auto v : s) {
        vari += square(v - mean);
    }
    vari /= static_cast<double>(s.size());
    double sd = std::sqrt(vari);
    return {mean, sd};
}

prob_sub_vec JudgeAll::get_all_subs() const {
    auto prob_num = contest_config.prob_id.size();
    prob_sub_vec all_subs(prob_num);
    for (const auto &[user_name, user_res] : all_res.r) {
        for (const auto &sub : user_res.subs) {
            auto prob_idx = contest_config.prob_id.at(sub.prob_name);
            all_subs[prob_idx].emplace_back(&sub);
        }
    }
    return all_subs;
}

prob_sub_vec JudgeAll::filter_sub(prob_sub_vec &&subs,
                                  const std::function<bool(const sub_info_t &s)> &pred) {
    std::for_each(subs.begin(), subs.end(), [&pred](std::vector<const sub_info_t *> &v) {
        auto it = std::remove_if(v.begin(), v.end(),
                                 [&pred](const sub_info_t *s) { return !pred(*s); });
        v.erase(it, v.end());
    });
    return subs;
}

std::string JudgeAll::generate_bests(std::size_t best_cnt) const {
    auto prob_num = contest_config.prob_id.size();
    auto ac_subs = filter_sub(get_all_subs(), is_ac_sub);

    std::string html = std::string(_stat_template_begin);
    for (std::size_t i = 0; i < prob_num; i++) {
        std::sort(ac_subs[i].begin(), ac_subs[i].end(),
                  iter_comp_iter<sub_info_t::comp_max_tm_usage>{});
        if (ac_subs[i].size() > best_cnt) ac_subs[i].resize(best_cnt);
        html.append(_stat_template_problem_head);
        for (const auto *sub : ac_subs[i]) {
            html += fmt::format(JLGXY_FMT(_stat_template_problem_body), sub->user_name,
                                contest_config.problems[i],
                                verdict_to_str(sub->result.sco.final_verdict),
                                verdict_to_str_short(sub->result.sco.final_verdict),
                                tu_to_str(sub->result.list_res.get_max_tm_mem().first),
                                mu_to_str(sub->result.list_res.get_max_tm_mem().second),
                                sub->compiler->name, std::to_string(sub->code_len) + "B");
        }
        html.append(_stat_template_problem_tail);
    }
    html.append(_stat_template_end);
    return html;
}

void JudgeAll::export_bests(std::size_t best_cnt) const {
    time_t now_c = time(nullptr);
    auto stat_name = "statistic" + localstr(now_c, "-%Y%m%d-%H%M%S") + ".html";
    jl::prog.println(JLGXY_FMT("saved to: {}"), stat_name);
    std::ofstream(stat_name) << generate_bests(best_cnt);
}

void JudgeAll::export_stats(std::size_t best_cnt) const {
    auto ac_subs = filter_sub(get_all_subs(), is_ac_sub);
    std::vector<std::vector<tm_usage_t>> tms(contest_config.prob_id.size());
    std::vector<std::vector<mem_usage_t>> mems(contest_config.prob_id.size());
    std::vector<std::vector<double>> scores(contest_config.prob_id.size());
    for (const auto &[user_name, user_res] : all_res.r) {
        for (const auto &sub : user_res.subs) {
            auto prob_idx = contest_config.prob_id.at(sub.prob_name);
            if (sub.result.sco.final_verdict == verdict_t::_ac) {
                auto [tm, mem] = sub.result.list_res.get_max_tm_mem();
                tms[prob_idx].emplace_back(tm);
                mems[prob_idx].emplace_back(mem);
            }
            mems[prob_idx].emplace_back(sub.result.sco.score);
        }
    }
    auto prob_num = contest_config.prob_id.size();
    std::vector<double> score_mean(prob_num), score_sd(prob_num);
    for (std::size_t i = 0; i < prob_num; i++) {
        std::sort(tms[i].begin(), tms[i].end());
        std::sort(mems[i].begin(), mems[i].end());
        if (tms[i].size() > best_cnt) tms[i].resize(best_cnt);
        if (mems[i].size() > best_cnt) mems[i].resize(best_cnt);
        scores[i].resize(all_res.r.size(), 0.0);
        auto [mean, sd] = calc_sd(scores[i]);
        score_mean[i] = mean;
        score_sd[i] = sd;
    }
}

void JudgeAll::save_file() const { save::save_file(_projectfile, all_res); }

std::tuple<bool, const Compiler *, fs::path> JudgeAll::find_code_at(const fs::path &dir,
                                                                    const conf_t &config) {
    const auto &name = config.name;
    for (const auto &compc : config.compiler) {
        for (const auto &suf : compc->suffix) {
            auto file = dir / (name + suf);
            if (fs::is_regular_file(file)) {
                return {true, compc, file};
            }
        }
    }
    return {false, nullptr, fs::path()};
}

namespace {
template <typename T>
void remove_duplicated(std::vector<T> &v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
}
}  // namespace

void JudgeAll::read_config(const fs::path &conf_file, conf_t &conf) const {
    conf = conf_t();
    std::ifstream conf_stream(conf_file);
    YAML::Node node = YAML::Load(conf_stream);

    conf.name = node["name"].as<std::string>();
    for (const auto &cname_node : node["compilers"]) {
        auto &&cname = cname_node.as<std::string>();
        auto [found, compc] = find_compiler_by_name(compilers_p, cname);
        if (!found) throw std::runtime_error("compiler(" + cname + ") not found");
        conf.compiler.emplace_back(compc);
    }
    conf.input_file = node["input_file"].as<std::string>();
    conf.output_file = node["output_file"].as<std::string>();
    conf.checker = node["checker"].as<std::string>();
    {
        auto &&cname = node["checker_compiler"].as<std::string>();
        auto [found, compc] = find_compiler_by_name(compilers_p, cname);
        if (!found) throw std::runtime_error("compiler(" + cname + ") not found");
        conf.checker_compiler = compc;
    }
    const auto type_string = node["type"].as<std::string>();
    if (type_string == "interactive") {
        conf.is_interactive = true;
    } else if (type_string == "traditional") {
        conf.is_interactive = false;
    } else {
        throw std::runtime_error("invalid problem type: " + trans(type_string));
    }
    conf.has_subtasks = node["has_subtasks"].as<bool>();
    if (conf.is_interactive) {
        conf.interactor = node["interactor"].as<std::string>();
        {
            auto &&cname = node["interactor_compiler"].as<std::string>();
            auto [found, compc] = find_compiler_by_name(compilers_p, cname);
            if (!found) throw std::runtime_error("compiler(" + cname + ") not found");
            conf.interactor_compiler = compc;
        }
    }
    for (std::size_t i = 0; i < node["testcases"].size(); i++) {
        const auto &&cur_node = node["testcases"][i];
        auto &cur_conf = conf.testcase_conf.emplace_back();
        cur_conf.time_lim = cur_node["time_limit"].as<tm_usage_t>();
        cur_conf.mem_lim = cur_node["memory_limit"].as<mem_usage_t>();
        cur_conf.input_file = cur_node["input_file"].as<std::string>();
        cur_conf.answer_file = cur_node["answer_file"].as<std::string>();
    }
    if (conf.has_subtasks) {
        for (std::size_t i = 0; i < node["subtasks"].size(); i++) {
            const auto &&cur_node = node["subtasks"][i];
            auto &cur_conf = conf.subtask_conf.emplace_back();
            cur_conf.tot_score = cur_node["score"].as<double>();
            cur_conf.scoring = to_scoring_t(cur_node["scoring"].as<std::string>());
            const auto &&tc_nodes = cur_node["testcases"];
            for (auto it = tc_nodes.begin(); it != tc_nodes.end(); ++it) {
                cur_conf.testcases.emplace_back(it->as<int>() - 1);
            }
            remove_duplicated(cur_conf.testcases);
            const auto &&pre_node = cur_node["pre"];
            if (pre_node) {
                for (auto k : pre_node) {
                    cur_conf.pre.emplace_back(k.as<int>() - 1);
                }
                remove_duplicated(cur_conf.pre);
            }
            if (cur_node["punishment"]) {
                cur_conf.punish = cur_node["punishment"].as<double>();
            }
        }
    } else {
        auto &cur_conf = conf.subtask_conf.emplace_back();
        cur_conf.tot_score = 100.0;
        cur_conf.scoring = scoring_t::_c_sum;
        for (std::size_t i = 0; i < node["testcases"].size(); i++) {
            cur_conf.testcases.emplace_back(i);
        }
    }

    conf.dep = std::make_unique<SubtaskDependencies>(conf.subtask_conf.size());
    for (size_t i = 0; i < conf.subtask_conf.size(); i++) {
        for (auto u : conf.subtask_conf[i].pre) {
            conf.dep->dag_[u].emplace_back(i);
        }
    }
    conf.dep->init();
}

void JudgeAll::check_valid() const {
    for (const auto &[prob_name, config] : probs) {
        const auto dir = data_dir / prob_name;
        tm_usage_t max_time_lim = 0;
        mem_usage_t max_mem_lim = 0;
        for (const auto &testcase : config.testcase_conf) {
            const auto in_file = dir / testcase.input_file;
            const auto ans_file = dir / testcase.answer_file;
            if (!fs::is_regular_file(in_file) || !path_contains(dir, in_file)) {
                throw ProblemConfigError(
                        prob_name, "can't find file: " + prob_name + " / " + testcase.input_file);
            }
            if (!fs::is_regular_file(ans_file) || !path_contains(dir, ans_file)) {
                throw ProblemConfigError(
                        prob_name, "can't find file: " + prob_name + " / " + testcase.answer_file);
            }

            max_time_lim = std::max(max_time_lim, testcase.time_lim);
            max_mem_lim = std::max(max_mem_lim, testcase.mem_lim);
        }
        int subid = 0;
        for (const auto &subtask : config.subtask_conf) {
            subid++;
            if (subtask.testcases.empty()) {
                print_problem_config_warning(prob_name, "empty subtask #" + std::to_string(subid));
            }
            for (auto id : subtask.testcases) {
                if (id < 0 || id >= static_cast<int>(config.testcase_conf.size())) {
                    throw ProblemConfigError(
                            prob_name, "in subtask #" + std::to_string(subid) +
                                               ": invalid testcase #" + std::to_string(id + 1) +
                                               ", violates the range [" + std::to_string(1) + ", " +
                                               std::to_string(config.testcase_conf.size()) + "]");
                }
            }
            for (auto id : subtask.pre) {
                if (id < 0 || id >= static_cast<int>(config.subtask_conf.size())) {
                    throw ProblemConfigError(
                            prob_name, "in subtask #" + std::to_string(subid) +
                                               ": requirements invalid, subtask #" +
                                               std::to_string(id + 1) + ", violates the range [" +
                                               std::to_string(1) + ", " +
                                               std::to_string(config.subtask_conf.size()) + "]");
                }
            }
        }
        if (max_time_lim > (60 * 1000)) {
            print_problem_config_warning(prob_name, "time limit is too long");
        }
        if (max_mem_lim > (4 << 20)) {
            print_problem_config_warning(prob_name, "memory limit is too big");
        }
        if (config.input_file.find('/') != std::string::npos ||
            config.input_file.find('\n') != std::string::npos) {
            throw ProblemConfigError(prob_name,
                                     "invalid input file name: " + trans(config.input_file));
        }
        if (config.output_file.find('/') != std::string::npos ||
            config.output_file.find('\n') != std::string::npos) {
            throw ProblemConfigError(prob_name,
                                     "invalid output file name: " + trans(config.output_file));
        }
        if (config.is_interactive) {
            if (config.input_file.empty() || config.output_file.empty()) {
                throw ProblemConfigError(
                        prob_name,
                        "interactive problems must have an input file and an output file");
            }
        }

        auto checker_file = dir / (config.checker + ".cpp");
        if (!fs::is_regular_file(checker_file) || !path_contains(dir, checker_file)) {
            throw ProblemConfigError(prob_name, "can't find checker: " + config.checker);
        }
        if (config.is_interactive) {
            auto interactor_file = dir / (config.interactor + ".cpp");
            if (!fs::is_regular_file(interactor_file) || !path_contains(dir, interactor_file)) {
                throw ProblemConfigError(prob_name, "can't find interactor: " + config.interactor);
            }
        }
    }
}

void JudgeAll::get_problem_compile_list() {
    tot_compile_task_ = 0;
    for (const auto &[prob_name, config] : probs) {
        if (!subs.contains_prob(prob_name)) continue;
        fs::path prob_path = data_dir / prob_name;
        tot_compile_task_++;
        compile_list_.push({prob_path / (config.checker + ".cpp"),
                            temp_dir / get_name("chk", prob_path.filename().string(), "chk", rstr_),
                            config.checker_compiler});
        if (config.is_interactive) {
            tot_compile_task_++;
            compile_list_.push(
                    {prob_path / (config.interactor + ".cpp"),
                     temp_dir / get_name("ina", prob_path.filename().string(), "ina", rstr_),
                     config.interactor_compiler});
        }
    }
}
void JudgeAll::check_problem_compile_files() {
    for (const auto &[prob_name, config] : probs) {
        if (!subs.contains_prob(prob_name)) continue;
        fs::path prob_path = data_dir / prob_name;
        if (!fs::is_regular_file(temp_dir /
                                 get_name("chk", prob_path.filename().string(), "chk", rstr_))) {
            throw ProblemConfigError(prob_name, "falied to compile checker");
        }
        if (config.is_interactive) {
            if (!fs::is_regular_file(
                        temp_dir / get_name("ina", prob_path.filename().string(), "ina", rstr_))) {
                throw ProblemConfigError(prob_name, "falied to compile interactor");
            }
        }
    }
}
void JudgeAll::get_user_compile_list() {
    tot_compile_task_ = 0;
    tot_compiled_ = 0;
    for (const auto &t : tasks_) {
        tot_compile_task_++;
        compile_list_.push(
                {t.code, temp_dir / get_name(t.user_name, t.prob_name, "", rstr_), t.compc});
    }
}

void JudgeAll::inc_compile_progress() {
    std::lock_guard guard(compile_list_lock_);
    tot_compiled_++;
    jl::prog.println("compiled: {} out of {}", tot_compiled_, tot_compile_task_);
    prop_ = base_prop_ + cur_prop_ * tot_compiled_ / tot_compile_task_;
    jl::prog.setprogress(prop_);
}

void JudgeAll::compiles(JudgeAll &ja, const fs::path &temp_dir) {
    while (true) {
        compile_prog p;
        {
            std::lock_guard guard(ja.compile_list_lock_);
            if (ja.compile_list_.empty()) {
                break;
            }
            p = ja.compile_list_.front();
            ja.compile_list_.pop();
        }
        compile_to(p.src, p.exe, *p.compiler, temp_dir);
        ja.inc_compile_progress();
    }
}
void JudgeAll::compile_all() {
    std::vector<std::thread> vec;
    vec.reserve(_max_threads);
    for (int i = 0; i < _max_threads; i++) {
        vec.emplace_back(compiles, std::ref(*this), temp_dir);
    }
    for (auto &t : vec) {
        t.join();
    }
}

void JudgeAll::calc_all_score() {
    std::map<std::string, const conf_t *> mp;
    for (const auto &[name, conf] : probs) {
        mp[name] = &conf;
    }
    for (auto &[user_name, user_res] : all_res.r) {
        for (auto &sub : user_res.subs) {
            sub.result.sco = sub.result.list_res.calc_score(*mp[sub.prob_name]);
        }
    }
}

bool JudgeAll::exist_prob(const std::string_view x) const {
    return contest_config.prob_id.find(x) != contest_config.prob_id.end();
}

std::string JudgeAll::generate_ranklist() const {
    std::vector<row> users;
    for (const auto &[user_name, user_res] : all_res.r) {
        double tot_score = 0;

        for (const auto &sub : user_res.subs) {
            if (exist_prob(sub.prob_name)) tot_score += sub.result.sco.score;
        }

        users.push_back(row{&user_res, &user_name, tot_score});
    }
    std::sort(users.begin(), users.end());

    auto html =
            fmt::format(JLGXY_FMT("    <div style=\"width:{}em; margin-bottom:2em\">\n      <div "
                                  "class=\"grid-container\">\n        <div class=\"grid-item "
                                  "bb\">#</div>\n        "
                                  "<div class=\"grid-item bb\">名称</div>\n"),
                        to_string_n((static_cast<double>(probs.size()) * 6) + 22.5, 1));

    for (const auto &[prob_name, prob_conf] : probs) {
        html += "        <div class=\"grid-item bb\">" + prob_name + "</div>\n";
    }
    html += "        <div class=\"grid-item bb\">总分</div>\n";
    int id = 0;
    int rank = 0;
    for (const auto &[user_res_p, user_name_p, user_score] : users) {
        if (!id || abs(user_score - users[id - 1].score) > 1e-6) rank = id;
        html += "        <div class=\"grid-item\">" + std::to_string(rank + 1) + "</div>\n";
        html += "        <div class=\"grid-item\">" + *user_name_p + "</div>\n";
        std::size_t pt = 0;
        for (const auto &[prob_name, prob_conf] : probs) {
            const auto prob_index = contest_config.prob_id.at(prob_name);
            while (pt < user_res_p->subs.size() &&
                   (!exist_prob(user_res_p->subs[pt].prob_name) ||
                    contest_config.prob_id.at(user_res_p->subs[pt].prob_name) < prob_index))
                pt++;
            if (pt < user_res_p->subs.size() && user_res_p->subs[pt].prob_name == prob_name) {
                if (user_res_p->subs[pt].result.list_res.has_started) {
                    html += R"qwq(        <div class="grid-item"><a class="clk" href="#)qwq" +
                            rand_by(*user_name_p, prob_name) + "\">" +
                            to_string_n(user_res_p->subs[pt].result.sco.score, 2) + "</a></div>\n";
                } else {
                    html += R"qwq(        <div class="grid-item"><a class="clk" href="#)qwq" +
                            rand_by(*user_name_p, prob_name) + "\">..</a></div>\n";
                }
            } else {
                html += "        <div class=\"grid-item\">-</div>\n";
            }
        }
        html += "        <div class=\"grid-item\">" + to_string_n(user_score, 2) + "</div>\n";
        id++;
    }
    html += "      </div>\n    </div>\n";

    return html;
}

std::string JudgeAll::generate_submission_info(const sub_info_t &sub, const conf_t &conf,
                                               const std::string_view user_name) {
    const list_result_t &sub_res = sub.result.list_res;
    const scores_t &scores = sub.result.sco;
    std::string html;

    {
        auto [tm, mem] = sub_res.get_max_tm_mem();
        auto timestr = localstr(chrono::system_clock::to_time_t(sub.judge_time), "%y-%m-%d %T");
        auto detail_table = fmt::format(
                JLGXY_FMT(_html_template_submission_detail), conf.name, user_name,
                verdict_to_str(scores.final_verdict), verdict_to_str_short(scores.final_verdict),
                to_string_n(scores.score, 2), tu_to_str(tm), mu_to_str(mem), sub.compiler->name,
                std::to_string(sub.code_len) + "B", timestr);
        html += detail_table;
    }

    html += _html_template_testcases_head;
    std::string script;
    int id = 0;
    for (const auto &testcase_res : sub_res.results) {
        std::string uid = randstr(24);
        auto cur = fmt::format(JLGXY_FMT(_html_template_testcases_body), std::to_string(id + 1),
                               verdict_to_str(testcase_res.res), uid,
                               verdict_to_str_sjlac(testcase_res.res),
                               tu_to_str(testcase_res.tm_used), mu_to_str(testcase_res.mem_used),
                               to_string_n(testcase_res.score * 100, 1));
        if (!testcase_res.info.empty()) {
            std::string cur_script = fmt::format(
                    JLGXY_FMT(R"(document.getElementById("{}").onclick = ()=>alert("{}");)"), uid,
                    trans(testcase_res.info));
            script += cur_script;
        }
        html += cur;
        ++id;
    }
    html += _html_template_testcases_tail;
    html += "    <script>" + script + "</script>\n";

    if (sub_res.has_started) {
        html += _html_template_subtask_head;
        int sid = 0;  // subtask id
        for (const auto &cur_conf : conf.subtask_conf) {
            int passed = 0;
            tm_usage_t max_tm = 0;
            mem_usage_t max_mem = 0;
            for (auto testcase_id : cur_conf.testcases) {
                if (sub_res.results[testcase_id].res == verdict_t::_ac) passed++;
                max_tm = std::max(max_tm, sub_res.results[testcase_id].tm_used);
                max_mem = std::max(max_mem, sub_res.results[testcase_id].mem_used);
            }

            auto cur = fmt::format(
                    JLGXY_FMT(_html_template_subtasks_body), std::to_string(sid + 1),
                    std::to_string(passed) + " / " + std::to_string(cur_conf.testcases.size()),
                    tu_to_str(max_tm), mu_to_str(max_mem),
                    to_string_n(scores.scores[sid], 2) + " / " +
                            to_string_n(cur_conf.tot_score, 2));
            html += cur;
            ++sid;
        }
        html += _html_template_subtasks_tail;
    }
    return html;
}

std::string JudgeAll::generate_html() const {
    std::map<std::string, const conf_t *> mp;
    for (const auto &[name, conf] : probs) {
        mp[name] = &conf;
    }
    std::string columns = "0.75fr 2fr 1fr";
    for (std::size_t i = 0; i < probs.size(); i++) {
        columns += " 1fr";
    }
    auto html = fmt::format(JLGXY_FMT(_html_template_begin), columns);
    html += generate_ranklist();
    for (const auto &[user_name, user_res] : all_res.r) {
        for (const auto &sub : user_res.subs) {
            if (!exist_prob(sub.prob_name)) continue;
            html += "    <h3 id=\"";
            html += rand_by(user_name, sub.prob_name) + "\">";
            html += user_name;
            html += " : ";
            html += sub.prob_name + "</h3>\n";
            html += generate_submission_info(sub, *(mp[sub.prob_name]), user_name);
        }
    }
    html += _html_template_end;
    return html;
}

void CliRunner::err_usage() {
    jl::prog.println(JLGXY_FMT("Usage: judgecli <command> [options]"));
    jl::prog.println(JLGXY_FMT("Commands:"));
    jl::prog.println(JLGXY_FMT("  new           create contest or problem directories"));
    jl::prog.println(JLGXY_FMT("  export        export judgement result"));
    jl::prog.println(JLGXY_FMT("  judge         judge sources"));
    jl::prog.println(JLGXY_FMT("  rejudge       rejudge sources"));
    jl::prog.println(JLGXY_FMT("  version       print version"));
    exit(1);
}
void CliRunner::err_newprob_usage() {
    jl::prog.println(JLGXY_FMT("Usage: judgecli new <type> <name>"));
    jl::prog.println(JLGXY_FMT("Types:"));
    jl::prog.println(JLGXY_FMT(
            "  contest       create a directory <name> and initialize an empty contest."));
    jl::prog.println(
            JLGXY_FMT("  problem       create a problem <name> with default configuration."));
    exit(1);
}
void CliRunner::newprob(int argc, char **argv) {
    if (argc != 4) {
        err_newprob_usage();
    }
    std::string name = argv[3];
    if (strcmp(argv[2], "contest") == 0) {
        if (name.find('/') != std::string::npos) {
            jl::prog.println(JLGXY_FMT("{}"), JudgeError("contest name can't contain '/'").what());
            exit(2);
        }
        fs::path cp(name);
        if (fs::exists(cp)) {
            jl::prog.println(JLGXY_FMT("{}"),
                             JudgeError("file or directory already exists").what());
            exit(2);
        }
        fs::create_directory(cp);
        fs::create_directory(cp / ".jljudge");
        fs::create_directory(cp / "data");
        fs::create_directory(cp / "sources");
        std::ofstream(cp / "data" / "contest.yaml") << _contest_config_template;
    } else if (strcmp(argv[2], "problem") == 0) {
        if (name.find('/') != std::string::npos) {
            jl::prog.println(JLGXY_FMT("{}"), JudgeError("problem name can't contain '/'").what());
            exit(2);
        }
        if (!fs::is_directory("data")) {
            jl::prog.println(JLGXY_FMT("{}"),
                             JudgeError("can't create problem outside a contest directory").what());
            exit(2);
        }
        auto cp = fs::path("data") / name;
        if (fs::exists(cp)) {
            jl::prog.println(JLGXY_FMT("{}"),
                             JudgeError("file or directory already exists").what());
            exit(2);
        }
        fs::create_directory(cp);
        std::ofstream(cp / "conf.yaml") << fmt::format(JLGXY_FMT(_problem_config_template), name);
        std::ofstream(cp / "my_checker.cpp") << fmt::format(JLGXY_FMT(_problem_checker_template));
    } else {
        err_newprob_usage();
    }
    exit(0);
}
int CliRunner::try_run(int argc, char **argv) {
    if (argc < 2) err_usage();

    if (strcmp(argv[1], "new") == 0) {
        newprob(argc, argv);
    }
    if (strcmp(argv[1], "version") == 0) {
        jl::prog.println(JLGXY_FMT("JLjudge version {} build {}"), JLGXY_VERSION,
                         JLGXY_VERSION_BUILD);
        return 0;
    }

    jlgxy::JudgeAll judgeall(fs::current_path() / "data", fs::current_path() / "sources",
                             fs::current_path() / ".jljudge" / "temp");
    judgeall.load_compilers();
    if (strcmp(argv[1], "rejudge") == 0) {
        judgeall.subs.loads_from_args(argc - 2, argv + 2);
        judgeall.load_probs();
        judgeall.load_project();
        judgeall.remove_range();
        judgeall.judge_main();
        return 0;
    }
    if (strcmp(argv[1], "judge") == 0) {
        judgeall.subs.loads_from_args(argc - 2, argv + 2);
        judgeall.judge_main();
        jl::prog.println("finish, pid={}", getpid());
        return 0;
    }
    if (strcmp(argv[1], "export") == 0) {
        if (argc > 2) err_usage();
        judgeall.load_probs();
        judgeall.load_project();
        judgeall.export_results();
        return 0;
    }
    if (strcmp(argv[1], "stat") == 0) {
        if (argc > 2) err_usage();
        judgeall.load_probs();
        judgeall.load_project();
        judgeall.export_bests();
        return 0;
    }
    err_usage();
    return 0;
}
int CliRunner::run(int argc, char **argv) {
    try {
        return try_run(argc, argv);
    } catch (std::exception &e) {
        jl::prog.finish();
        jl::prog.println(JLGXY_FMT("{}"), e.what());
        exit(2);
    }
}

namespace cli {

class Judge {
  public:
    constexpr static std::string_view _name = "judge";
    constexpr static std::string_view _desc = "judge sources";
    static po::Parser init_parser() {
        po::Parser p;
        p.add("add", 'a', "add submissions to judge", true, 0, _size_inf);
        return p;
    }
    static int run(po::Parser &p) {
        jlgxy::JudgeAll judgeall(fs::current_path() / "data", fs::current_path() / "sources",
                                 fs::current_path() / ".jljudge" / "temp");
        judgeall.load_compilers();
        judgeall.subs.loads_from_args(p.get<std::vector<std::string>>("add"));
        judgeall.judge_main();
        return 0;
    }
};

class CliHandler {
  public:
    int run(int argc, char **argv) {
        try {
            return run_throw(argc, argv);
        } catch (std::exception &e) {
            jl::prog.finish();
            jl::prog.println(JLGXY_FMT("{}"), e.what());
            exit(2);
        }
    }

  private:
    po::CommandHandler handler_;

    int run_throw(int argc, char **argv) {
        add<Judge>();
        auto [name, ret] = handler_.parse(argc, argv);
        return ret;
    }

    template <typename T>
    void add() {
        handler_.add_command(T::_name, T::init_parser(), T::_desc, T::run);
    }
};
}  // namespace cli

}  // namespace jlgxy

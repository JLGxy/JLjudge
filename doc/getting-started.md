## 安装

### 手动编译

目前仅支持 linux x64 环境下编译运行。首先安装 gcc（或 clang）编译器和 cmake 工具。

进入源代码所在目录执行：

```sh
mkdir build && cd build
cmake ..
make
```

#### 构建 docker（可选）

```sh
docker build -t jljudge .
```

## 使用方式

### 创建新比赛

```sh
judge-cli new contest <contest-name>
```

将会在当前目录下创建一个比赛文件夹，并命名为 `<contest-name>`

### 创建新题目

在比赛目录中运行

```sh
judge-cli new problem <problem-name>
```

将会在比赛的 `data` 目录中创建一个题目，并包含默认配置。

### 比赛目录

`judge-cli new contest` 将会创建一个比赛目录，比赛目录中应当包含如下文件。

```
<contest-name>/
├── data
│   ├── contest.yaml
│   └── <problem-1>
│       ├── conf.yaml
│       ├── <problem-1>-1.ans
│       ├── <problem-1>-1.in
│       ├── <problem-1>-2.ans
│       ├── <problem-1>-2.in
│       ├── <problem-1>-3.ans
│       ├── <problem-1>-3.in
│       ├── ...
│       ├── special-judge.cpp
│       └── testlib.h
└── sources
    ├── <competitor-1>
    │   ├── <problem-1>
    │   │   └── <problem-1>.cpp
    │   ├── <problem-2>
    │   │   └── <problem-2>.cpp
    │   └── ...
    ├── <competitor-2>
    │   ├── <problem-1>
    │   │   └── <problem-1>.cpp
    │   ├── <problem-2>
    │   │   └── <problem-2>.cpp
    │   └── ...
    └── ...
```

比赛的测试数据应放在 `data` 文件夹。

选手代码应放在 `source` 文件夹。

### 配置文件

#### 比赛配置

`data` 目录应直接包含一个 `contest.yaml` 文件，文件应该包含以下内容

```yaml
# 所有比赛题目
problems:
  - <problem-1>
  - <problem-2>

# 声明所有编译配置
compilers:
  -
    name: gcc-c11  # 名称
    path: /usr/bin/gcc  # 编译器路径
    args: ["${source}", "-o", "${executable}", "-static", "-std=c11", "-O2"]  # 编译参数
    suffixes: [".c"]  # 选手代码文件后缀
  -
    name: gcc-c++14
    path: /usr/bin/g++
    args:  # 也可以这样
      - "${source}"
      - "-o"
      - "${executable}"
      - "-static"
      - "-std=c++14"
      - "-O2"
    suffixes:
      - ".cpp"

```

#### 题目配置

每个题目文件夹内部应包含一个 `conf.yaml`，用来声明题目评测选项。

文件应当包含如下内容

```yaml
name: <problem-name>  # 与文件夹名称相同
type: traditional  # 对于传统题、函数交互题、通信题使用 traditional，IO 交互题使用 interactive

compiler: gcc-c++14  # 在 contest.yaml 中声明

input_file: foo.in  # 选手代码的输入文件名
output_file: foo.out  # 选手代码的输出文件名

# 如果想使用 stdin/stdout 请将 input_file 与 output_file 留空
# input_file: ''
# output_file: ''

# 题目数据文件夹中需要有 my_checker.cpp
checker: my_checker
checker_compiler: gcc-c++14

# 对于 IO 交互题，还需要
# interactor: interactor
# interactor_compiler: gcc-c++14

testcases:
  -
    time_limit: 1000  # 测试点时间限制，单位是 ms
    memory_limit: 524288  # 测试点空间限制，单位为 KiB
    input_file: bar1.in  # 输入数据文件名
    answer_file: bar1.ans  # 答案数据文件名
  -
    time_limit: 1000
    memory_limit: 524288
    input_file: bar2.in
    answer_file: bar2.ans

has_subtasks: true  # 是否有 subtask
subtasks:  # 如果有 subtask
  -
    scoring: avg  # 也可以是 min 或 max
    score: 100  # subtask 的分数，可以是小数
    testcases: [1,2]  # 包含的所有测试点

```

### 评测

```sh
judge-cli judge
```

将会测试 `source` 目录内所有选手的所有题目代码。

如果之前评测过，那么 `judge` 命令结束时将会覆盖本地以前的测试结果，因此请确保之前的测试结果已经导出。如果不希望覆盖，请使用 `rejudge` 命令。

#### 单题测试

```sh
judge-cli judge "<competitor-1>/<problem-1>" "<competitor-2>/<problem-2>" ...
```

仅测试选手 `<competitor-x>` 在题目 `<problem-x>` 的提交。忽略其他提交。

`<competitor-x>` 和 `<problem-x>` 都可以用 `*` 代替，分别表示所有选手和所有题目。

#### 重测

```sh
judge-cli rejudge
```

```sh
judge-cli rejudge "<competitor-1>/<problem-1>" "<competitor-2>/<problem-2>" ...
```

用法及参数与 `judge` 命令相同。在测试前会先读取本地以前的测试结果。仅覆盖被重测的提交的评测结果，其他提交仍保持上一次的结果。

### 导出结果

```sh
judge-cli export
```

在比赛文件夹内生成 `result-xxx.html`，包含比赛排行榜与评测的详细信息。

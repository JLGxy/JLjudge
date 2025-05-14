## 子任务依赖

```yaml
has_subtasks: true
subtasks:
  -
    scoring: min
    score: 30
    testcases: [1,2,3]
  -
    scoring: min
    score: 30
    testcases: [4,5,6]
    pre: [1]  # 依赖子任务 1
  -
    scoring: min
    score: 40
    testcases: [7,8,9,10]
    pre: [2]  # 依赖子任务 2
```

pre 字段用来声明子任务依赖，如果存在 pre 中的子任务没有通过，则当前子任务得 0 分。

## 实现 hack

```yaml
has_subtasks: true
subtasks:
  -
    scoring: avg
    score: 100
    testcases: [1,2,3]
  -
    scoring: min
    score: 0
    testcases: [4,5]
    pre: [1]
    punishment: -3
```

可以通过 punishment 实现类似 UOJ 的 hack 功能。

`punishment: <p>` 表示若当前子任务依赖的子任务全部通过，且当前子任务没有通过，则将得分加上 p。
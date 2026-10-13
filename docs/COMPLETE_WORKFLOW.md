# IL2CPP 完整分析流程

本流程用于自有项目、授权测试和安全审计。核心原则是：每个结论都要能回到固定样本、固定版本、可复现触发步骤和动态证据。

## 0. 建立案件和样本基线

先为一次分析创建独立目录，并记录 APK、`libil2cpp.so`、`global-metadata.dat`、热更 DLL 和资源包的哈希：

```powershell
python workflow.py init --name game-v1 --out out/cases/game-v1 `
  --package com.example.game --abi arm64-v8a `
  --sample C:\samples\game.apk `
  --sample C:\samples\libil2cpp.so `
  --sample C:\samples\global-metadata.dat
```

在 `case.json` 中补齐 Unity 版本、IL2CPP 版本、构建号、架构、模块名、image base、PAC/Thumb 状态和来源设备。不要把不同版本的文件混在同一个案件目录。

分包或资源容器先统一收集：

```powershell
python tool.py collect --input game.apk --input config.arm64_v8a.apk --input main.obb --output out/cases/game-v1/package
```

APKS/XAPK 会先展开；使用 `--package` 和 `--device` 时会收集设备上全部 `pm path` 结果。工具会生成 `merged-input.apk`，可继续交给 `tool.py static`；`package-manifest.json` 保存每个输入的大小和 SHA-256。

阶段标记：

```powershell
python workflow.py mark --case out/cases/game-v1 --stage inventory --status completed
```

## 1. 环境识别

先判断目标的运行方式，再选择后续链路：

- Unity Mono、IL2CPP、HybridCLR、ILRuntime、Lua 或其他脚本运行时。
- Android ARM64、ARMv7、x86_64，或 PC `GameAssembly.dll`。
- root + `frida-server`、Gadget 重打包，还是只能做静态分析。
- 是否存在加固、反调试、metadata 加密、so 加密、AssetBundle 加密和热更更新器。

记录应用包名、进程名、模块名、ABI、Unity/IL2CPP 版本、启动路径和加载顺序。先运行：

```powershell
python tool.py doctor
python tool.py static --apk C:\samples\game.apk --recover
```

静态审计只产生线索，不能证明运行时使用了这些文件；split APK 也必须分别核对。

## 2. 静态审计和 metadata 恢复

对未加密样本，先完成 APK 审计和类型恢复：

```powershell
python tool.py static --apk C:\samples\game.apk --recover --out out/cases/game-v1/static
```

检查以下结果：

- `static-report.json`：ABI、`libil2cpp.so`、metadata、Managed DLL、DEX、资源包和字符串线索。
- `recovered/dump.cs`、`DummyDll/`、`il2cpp.h`、`script.json`。
- `recovery-status.json`：解析器版本、输入哈希、产物数量和限制。

若 metadata 被加密、拆分、压缩或运行时生成，静态恢复失败是预期分支。此时不要把失败的 `dump.cs` 当作事实，转入运行时恢复：

```powershell
python tool.py dynamic --pkg com.example.game --mode dumpcs
python tool.py dynamic --pkg com.example.game --mode dumpso
```

`dumpcs` 用运行时类型信息生成结构；`dumpso` 用已加载镜像重建原生 ELF。两者都应记录设备、进程、模块基址和产物哈希。

设备上已安装的包可以在静态恢复失败后自动切换到运行时 `dumpcs`：

```powershell
python tool.py static --package com.example.game --device DEVICE_ID --recover --runtime-fallback
```

## 3. 托管层与 native 边界识别

对每个关键类和方法建立映射：

```text
程序集/命名空间/类/方法/签名
        -> MethodInfo / methodPointer
        -> 模块 + RVA
        -> 运行时绝对地址
        -> native 调用者和动态行为
```

判定规则：

- 有有效 method pointer、进入 `libil2cpp.so` 的 AOT 方法，进入 native 反汇编链路。
- 通过 `il2cpp_runtime_invoke`、HybridCLR 解释器或反射执行的方法，优先使用 `invoke`/托管层 hook。
- `Assembly.Load(byte[])`、`LoadMetadataForAOTAssembly` 和 HybridCLR native loader 是热更边界。
- Java SDK、支付、登录和系统能力从 Java hook 单独追踪。

## 4. 地址校准与符号导入

统一使用以下地址模型：

```text
runtime_address = module_base + static_rva
```

在动态转储、IDA/Ghidra 和 Frida 日志中同时保存：

- 模块名称和模块基址。
- 静态 RVA、运行时地址、image base。
- ABI、Thumb/PAC 状态。
- 方法签名和实际参数个数。
- 采集时间和样本哈希。

导入符号并验证少量已知函数：

```powershell
python tool.py dynamic --pkg com.example.game --mode symbols --target ghidra
python tool.py dynamic --pkg com.example.game --mode trace --ns Game --cls Player --method Update --argc 0
```

如果入口地址不一致，先校准模块基址和 image base，再判断是否是版本不匹配或函数指针并非 AOT 地址。

批量生成地址校准报告：

```powershell
python tool.py calibrate classes.json --module-base 0x7a00000000 --image-base 0x0 --out address-calibration.json
```

## 5. 触发复现和动态验证

为每个目标建立可重复触发步骤，例如：

```text
启动 -> 登录 -> 打开指定界面 -> 点击操作 -> 等待请求 -> 记录响应和状态变化
```

在 `notes.md` 记录触发条件、线程、时间窗口、输入、输出和日志。按成本从低到高使用：

1. `trace`：确认方法是否执行及参数。
2. `invoke`：观察反射、HybridCLR 和解释执行路径。
3. `net`、`fileio`、`unitylog`、`strings`：关联外部行为。
4. `scan`、对象转储、字段读取：关联运行时状态。
5. `stalk`：只对已定位的短目标调用做指令级追踪。

结构化记录触发事件和环境组合：

```powershell
python workflow.py event --case out/cases/game-v1 --kind trigger `
  --note "进入登录页并点击提交" `
  --data '{"screen":"login","action":"submit"}'
python workflow.py matrix --case out/cases/game-v1 --status verified `
  --unity 2021.3 --abi arm64-v8a --frida 17.x --device DEVICE_ID
```

事件保存到 `events.jsonl`，兼容性结果保存到 `case.json` 的 `compatibility` 数组。

## 6. Obfuz、加密和反分析分支

推荐顺序：

1. 先用运行时 dump 获取真实类型、签名和字段。
2. 先用 `crypto` 观察标准加解密入口。
3. 先用 `stalk --stalk-mode call` 找关键子调用。
4. 用 `block` 观察控制流平坦化。
5. 用 `xor`、`table`、`mul`、`branch` 或 `insn` 分析短循环。
6. 用 `host/analyze.py` 做离线统计，再回写 Ghidra/IDA 注释。

```powershell
python tool.py dynamic --pkg com.example.game --mode crypto
python tool.py dynamic --pkg com.example.game --mode stalk --cls Crypto --method Encrypt --stalk-mode call
python tool.py dynamic --pkg com.example.game --mode stalk --cls Crypto --method Encrypt --stalk-mode xor --max-records 20000
python tool.py analyze out/cases/game-v1/stalker-xor.jsonl --mode xor --xor-key
```

反检测只用于自有构建或明确授权的测试。优先使用 `anti --anti-action audit` 记录暴露面；需要验证注入兼容性时再使用相应测试配置。

## 7. 旁支链路

```text
net    -> 明文请求/响应 -> 序列化和业务方法
scan   -> 地址和写入者 -> native 调用链
hot    -> 解密 DLL -> dnSpyEx/ILSpy -> 回到 runtime_invoke
assets -> 解密 AssetBundle -> AssetStudio/UnityPy
scene  -> 活对象和字段 -> dump/trace
```

这些结果必须带上同一个案件编号和样本版本，不能只保存孤立日志。

## 8. 结果回写和验证闭环

每一个结论至少回写到以下两个位置：

- Ghidra/IDA：函数名、RVA、参数、调用者、控制流备注。
- `notes.md`/结构化 JSON：触发步骤、动态日志文件、输入输出、可信度和未解决问题。

验证至少做三次：

1. 静态 RVA 与运行时地址复算一致。
2. hook 参数、返回值和对象字段与业务行为一致。
3. 重启进程或重复触发后，结论仍能在同一版本样本上复现。

第 1 项可以用 `crosscheck` 把运行时 `classes.json` 的 RVA 和 Il2CppDumper `script.json` 的 `ScriptMethod` 地址做批量交叉校验：

```powershell
python tool.py crosscheck `
  --static out/cases/game-v1/static/recovered/script.json `
  --dynamic out/cases/game-v1/classes.json `
  --image-base 0x0 `
  --out out/cases/game-v1/crosscheck.json
```

地址匹配只是证据：共享代码和泛型方法可能对应多个名字，输入构建一致性仍需单独核对。

最后校验案件：

```powershell
python workflow.py verify --case out/cases/game-v1
```

验证失败时不要覆盖旧产物；创建新的案件目录并记录版本差异。

动态命令增加 `--case out/cases/game-v1` 后，host 收到的文本和二进制产物会自动登记到 `case.json`。

如果完整 Agent 在启动期导致 Unity loading 变慢，使用延迟加载模式：

```powershell
python tool.py dynamic --pkg com.example.game --mode hot --late-agent --startup-delay 20
```

该模式先注入最小 bootstrap、恢复应用运行，等待指定秒数后才加载完整 Agent。启动期 DLL 可能因此错过，适合优先保证自动登录和主界面流程稳定的目标。

跨版本差异和边界报告：

```powershell
python tool.py diff out/v1/classes.json out/v2/classes.json --json out/v1-v2.json
python tool.py analyze classes.json --mode boundary --json boundary-report.json
```

前者比较类、方法 RVA 和字段偏移；后者筛出有 RVA 的 AOT/native 方法及缺少 RVA 的可能托管/解释执行方法，后者仍需结合 `invoke` 和动态调用栈复核。

捕获原始托管 DLL 后，用 ILSpyCmd 输出可读 C# 文件：

```powershell
python tool.py decompile-managed `
  --dll out\pixel4-letsfarm\raw-hot-early\com.moonjoy.letsfarm\20261013_103429\hotupdate_2663936_1791858872375.dll `
  --out out\pixel4-letsfarm\hotfix-decompiled
```

输出包含 `src/`、`decompile.log`、`report.json`。首次运行会用 .NET 自动把 ILSpyCmd
安装到 `tools\`（需本机有 dotnet），缺失时无需手动准备。ILSpy 结果是反编译近似代码，不是原始源码。

## 阶段清单

```text
[ ] inventory                 样本、版本、ABI、设备和哈希
[ ] static_audit              APK/包结构和敏感线索
[ ] metadata_recovery         静态恢复或运行时 dumpcs
[ ] runtime_dump              classes、fields、RVA、dumpso
[ ] address_calibration       module base、image base、RVA 校准
[ ] managed_native_boundary   AOT、HybridCLR、Java、脚本边界
[ ] trigger_reproduction      可重复触发步骤
[ ] dynamic_validation        hook、网络、内存、日志验证
[ ] obfuscation_analysis      crypto、Stalker、离线分析
[ ] result_backfill           Ghidra/IDA 和案件笔记回写
[ ] verification               重复运行、交叉证据、哈希校验
```

# il2cpp-harness —— Unity IL2CPP 静态 / 动态分析工具

完整、可复现的阶段化分析流程见 [`docs/COMPLETE_WORKFLOW.md`](docs/COMPLETE_WORKFLOW.md)。
案件清单和样本哈希使用 `workflow.py` 管理：

```powershell
python workflow.py --help
python workflow.py init --name game-v1 --out out/cases/game-v1 --sample C:\samples\game.apk
python workflow.py verify --case out/cases/game-v1
# 记录可复现触发事件和兼容性验证
python workflow.py event --case out/cases/game-v1 --kind trigger --note "进入登录页并点击提交" --data '{"screen":"login","action":"submit"}'
python workflow.py matrix --case out/cases/game-v1 --status verified --unity 2021.3 --abi arm64-v8a --frida 17.x --device DEVICE_ID
# 也可通过统一入口调用
python tool.py workflow --help
```

补充入口：

```powershell
# 收集 split APK / APKS / XAPK / OBB，并记录全部输入哈希
python tool.py collect --input C:\samples\base.apk --input C:\samples\config.arm64_v8a.apk --output out\cases\game-v1\package

# 把 classes.json 中的 RVA 转成指定模块基址下的运行时地址
python tool.py calibrate out\cases\game-v1\classes.json --module-base 0x7a00000000 --out out\cases\game-v1\address-calibration.json

# 比较两个版本的类、方法 RVA 和字段偏移
python tool.py diff out\v1\classes.json out\v2\classes.json --json out\v1-v2.json

# 生成证据回写包和 Ghidra/IDA 注释脚本
python tool.py backfill out\cases\game-v1\classes.json --calibration out\cases\game-v1\address-calibration.json --out out\cases\game-v1\backfill

# 使用 ILSpyCmd 将捕获的 HotFix DLL 还原为 C# 文件
python tool.py decompile-managed `
  --dll out\pixel4-letsfarm\raw-hot-early\com.moonjoy.letsfarm\20261013_103429\hotupdate_2663936_1791858872375.dll `
  --out out\pixel4-letsfarm\hotfix-decompiled

# 离线识别 AOT/native 与可能的托管/解释执行边界
python tool.py analyze out\cases\game-v1\classes.json --mode boundary --json out\cases\game-v1\boundary-report.json
```

## 统一入口（推荐）

在本目录执行 `python tool.py --help` 查看工具入口。

```powershell
# 环境检查：不启动或附加应用
python tool.py doctor

# 本地 APK：审计 + 类型/签名恢复
python tool.py static --apk C:\builds\game.apk --recover

# 从指定设备提取当前包，然后审计 + 类型恢复
python tool.py static --device 127.0.0.1:7555 --package com.moonjoy.letsfarm --recover

# 追加选定方法的原生伪 C 导出
python tool.py static --apk C:\builds\game.apk --recover --decompile `
  --filter '^GameUtility\$\$' --limit 20

# 动态入口直接转交已有 host/run.py 参数
python tool.py dynamic --help
python tool.py dynamic --device DEVICE_ID --attach PID --mode list
# 动态产物自动登记到案件 case.json
python tool.py dynamic --pkg com.example.game --mode dump --case out\cases\game-v1
# 启动期较重的目标：先让应用运行，再加载完整 Agent
python tool.py dynamic --pkg com.example.game --mode hot --late-agent --startup-delay 20
```

静态默认只做 APK 审计；`--recover` 添加类型恢复，`--decompile` 添加原生反编译。
对已安装包可加 `--runtime-fallback`，静态 metadata 恢复失败时尝试运行时 `dumpcs`。
静态输入不需要 Frida/root，不启动应用；类型恢复需 .NET，原生反编译首次运行会
下载 Ghidra 和独立 JDK。可使用 `--abi` 选择原生库架构。

每次静态任务默认创建 `out/static/<名称>-<时间戳>/`，也可以用 `--out` 指定新目录。
`workflow.json` 记录各步骤退出码；步骤失败时不会继续处理，成功产物与失败日志均保留。
说明：`static --package` 保持兼容模式，默认审计首个 APK；需要完整 split 安装包时，先使用
`tool.py collect --package ... --device ...` 收集全部输入，再对收集结果进行后续分析，不能把 base.apk
的检查结果当成全安装包覆盖。

动态模式依赖原有 Frida 环境并实际附加/启动进程；当前 MuMu 的 ARM64/Houdini 限制
仍存在，待原生 ARM64 测试设备到位后验证。静态伪 C 与 DummyDll 不是原始源码。

离线分析已有产物（不连接设备、不附加进程）：

```powershell
python tool.py analyze .\path\to\classes.json `
  --mode classes --find-method GetPlatform
python tool.py analyze .\path\to\records.jsonl --mode block --top 30
python tool.py analyze .\path\to\heap_strings.json --mode strings --grep 'https?://'
```

动态 Agent 已同步完整，包含指令级追踪、网络/内存分析、Unity 日志与堆字符串、
Java 层 Hook、性能剖析、主动调用与字段读写、资源/场景枚举、文件/加密监控、
反检测审计、运行时 dump.cs 与 so 重建等能力。静态审计、类型恢复、原生伪 C 和
离线结果分析能力也继续保留。

动态模式的完整入口和参数以 `host/run.py --help` 为准；可使用 `python tool.py dynamic --help`
转发到该入口。Agent 按文件名顺序拼接加载，请保持 `agent/00-utils.js` 到 `agent/99-entry.js`
的文件名顺序。

---

面向 **Unity 2021.3.x + IL2CPP + arm64** 的进程注入方案，覆盖三件事：

| 能力 | 入口 | 产出 |
|---|---|---|
| 运行时转储类/方法/字段 | `--mode dump` | `classes.json`（含 RVA）、`script.json`（IDA/Ghidra 符号） |
| Hook 拦截与改写 | `--mode trace` / `invoke` | 实时参数日志、改参/改返回值/整段替换 |
| 抓 HybridCLR 热更 DLL | `--mode hot` | 内存里解密后的原始 PE 文件（可直接 dnSpy 打开） |

核心思路：**不碰静态文件**。global-metadata.dat 加密、Obfuz 符号混淆、HybridCLR dll 加密都只影响磁盘形态，
运行时内存里一定是明文，所有信息从进程里"问"出来，天然绕开壳。

---

## 1. 环境准备

### 1.1 安装（Windows PowerShell）

```powershell
pip install frida frida-tools      # 注意：frida 与 frida-server 主版本必须一致
frida --version                    # 假设输出 17.x.x
```

### 1.2 有 root：frida-server（小米/一加 开发者选项已开 root 授权）

```powershell
# 下载对应版本：frida-server-<ver>-android-arm64.xz，解压
adb push frida-server-17.x.x-android-arm64 /data/local/tmp/fs
adb shell "chmod 755 /data/local/tmp/fs"
adb shell "su -c '/data/local/tmp/fs -D &'"          # -D 后台守护
adb shell "su -c 'setenforce 0'"                      # 个别 ROM 需要
frida-ps -U | Select-String 游戏包名                   # 验证连通
```

> 建议把 `fs` 改名（如 `vendor_thermal`），并改默认端口 27042 到自定义端口，
> 规避常见的 frida 检测（扫进程名 / 扫端口 / 扫 `/proc/self/maps` 里的 frida-agent）。

### 1.3 无 root：frida-gadget（重打包）

```powershell
# 1) 下载 frida-gadget-17.x.x-android-arm64.so.xz
apktool d game.apk -o game_dec
# 2) 放 so
copy libfrida-gadget.so game_dec\lib\arm64-v8a\libfrida-gadget.so
# 3) 放配置（文件名必须和 so 对应：libfrida-gadget.config.so）
copy scripts\gadget.config game_dec\lib\arm64-v8a\libfrida-gadget.config.so
# 4) 在入口 Activity 的 onCreate 里最早处插入 smali：
#    const-string v0, "frida-gadget"
#    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
apktool b game_dec -o game_patched.apk
# 5) 签名 + v2/v3 对齐后安装
```

`scripts/gadget.config`：

```json
{ "interaction": { "type": "listen", "address": "127.0.0.1", "port": 27042, "on_load": "wait" } }
```

`on_load: "wait"` 会让进程等你 `frida -U -n Gadget` 连上再继续，抓启动期加载的 DLL 必须用这个。
使用 listen 模式时，还需要在主机执行端口转发，例如 `adb forward tcp:27042 tcp:27042`。

---

## 2. 用法

一切从 `host/run.py` 出发（默认 spawn 模式，先注入再 resume，才能抓到最早的 DLL 加载）：

```powershell
cd il2cpp-harness
python host/run.py --pkg com.your.game --mode dump
python host/run.py --pkg com.your.game --mode dump --images Assembly-CSharp.dll --class-filter "Game\.Net"
python host/run.py --pkg com.your.game --mode trace --ns Game.Net --cls LoginMgr --method SendLogin --argc 3
python host/run.py --pkg com.your.game --mode invoke --filter HotUpdate
python host/run.py --pkg com.your.game --mode hot
python host/run.py --attach 12345 --mode dump        # 已运行的进程
python host/run.py --pkg com.your.game --mode interactive   # JS REPL
# 如确需启用 evaljs，仅在隔离调试设备上显式加：
python host/run.py --pkg com.your.game --mode interactive --allow-eval
```

默认情况下 interactive 的 `evaljs` 已禁用；`--allow-eval` 会允许执行进程内
JavaScript，只应在自有构建和隔离设备上使用。

输出在 `out/<包名>/<时间戳>/`：
`classes.json`、`script.json`、`hotupdate_*.dll`。

### 2.1 interactive 里能直接用的对象

```js
IL2CPP.findMethod(null, 'Game', 'PlayerData', 'AddGold', 1).methods
IL2CPP.rva(IL2CPP.methodPointer(mi))        // 拿 RVA 去 IDA 下断
Dump.dumpClass('Game', 'PlayerData')        // 看字段偏移
Dump.listImages()
Hook.hookMethod('Game', 'PlayerData', 'AddGold', 1, { onEnter(a){ console.log(a[0]); } })
HybridCLR.scanSymbols()                     // 看 hybridclr 符号有没有被 strip
```

---

## 3. 三种场景的做法

### 3.1 运行时转储（绕 metadata 加密）

遍历链路：`il2cpp_domain_get` → `il2cpp_domain_get_assemblies` → `il2cpp_assembly_get_image`
→ `il2cpp_image_get_class` → `il2cpp_class_get_methods / _fields`。

脚本只用 **Unity 显式导出的 `il2cpp_*` API**，不硬编码 `Il2CppClass`/`MethodInfo` 结构体偏移
（这些布局每个 Unity 版本都变，硬编码一升版本就崩）。
只有 `Il2CppString`（len@16 / chars@20）和 `Il2CppArray`（len@24 / data@32）这两类没有公开 API 的对象用偏移，
且启动时 `selfCheck()` 会用 `il2cpp_string_new("ABCDE")`、`il2cpp_array_new(byte,7)` 自检，不通过会直接告警。

产物用途：
- `script.json` → IDA/Ghidra 批量重命名函数（`{name, rva}`）
- `classes.json` 的 `fields[].offset` → hook 里直接读写对象成员

> **Obfuz 提示**：符号混淆只改 metadata 里的名字，运行时字符串是解密后的真实名字，
> 所以动态 dump 出来的名字往往比静态解析 metadata 得到的"乱码名"更可读 —— 这是动态方案对混淆的优势。

### 3.2 Hook 拦截与改写

IL2CPP 生成的原生函数签名（arm64 AAPCS，参数走 X0~X7）：

```c
// 实例方法
R f(Il2CppObject* __this, P0..Pn, const MethodInfo* method);
// 静态方法
R f(P0..Pn, const MethodInfo* method);
```

所以 `args[0]` 对实例方法是 `this`，**`MethodInfo*` 永远是最后一个参数**。改参用 `args[i].replace()`，
改返回值用 `retval.replace()`（见 `agent/30-hook.js` 的 `Hook.examples()`）。

三档粒度：

| 方式 | 适用 | 注意 |
|---|---|---|
| `Hook.hookMethod(ns, cls, m, argc)` | 常规 AOT 方法 | 重载多时用 `hookMethodBySig` 按参数类型名精确匹配 |
| `Hook.hookRuntimeInvoke(filter)` | **HybridCLR 解释执行的方法**、反射调用、虚调用 | 全局单点，性能开销大，务必加 filter |
| `Hook.replaceMethod(...)` | 整段换实现 | `NativeCallback` 的参数类型必须和原生签名**完全一致**（含末尾 `MethodInfo*`），否则寄存器/栈错乱直接崩 |

在 hook 回调里调用 `il2cpp_*` API（如 `il2cpp_string_new`）前，若当前不是托管线程，要先 `il2cpp_thread_attach(domain)`。

### 3.3 抓 HybridCLR 热更 DLL

三套 hook 同时装（`--mode hot`），优先级从高到低：

**A. 原生入口（最准）**
```
hybridclr::metadata::InterpreterImage::Load(const byte* imageData, size_t size)
hybridclr::metadata::Assembly::Create(const byte* imageData, uint64_t size)
```
mangled 名（`arm64 Itanium ABI`）：`_ZN9hybridclr8metadata16InterpreterImage4LoadEPKvm`。
`args[0]=this, args[1]=dll 首字节, args[2]=长度`。
即便符号被 strip，也可以在 IDA 里搜字符串 `"image can't be init again"` 找到该函数，把 RVA 填进 `HC.hookNative` 的候选列表。

**B. 托管层（最通用）**
Hook `System.Reflection.Assembly::Load(byte[])`（HybridCLR 官方加载方式），
从 `Il2CppArray` 读出原始 PE。同时也会抓 `RuntimeApi::LoadMetadataForAOTAssembly(byte[], mode)` 的补充元数据 DLL。

**C. libc 兜底**
Hook `open/openat/fopen`，记录所有 `.dll/.bytes/.dat/.pdb` 的打开路径 + 回溯，用于定位 DLL 从哪来（assets / persistentDataPath / AB 包）。

**改写热更逻辑（不重打包）**：把改好的 dll 放到设备
`/data/local/tmp/il2cpp-harness/patch/<抓到的文件名>.dll`，脚本在加载时会用 `writeByteArray` 覆盖缓冲区，
实现"改 dll → 下次启动生效"。注意 patch 不能比原 dll 大（缓冲区是按原长度分配的）。

---

## 4. 目录结构

```
tool.py               统一入口：static / dynamic / analyze / diff / crosscheck / collect /
                      calibrate / backfill / decompile-managed / workflow / doctor
workflow.py           案件与样本基线管理（init/verify/event/matrix/mark）
agent/                按文件名顺序拼接加载，共享 globalThis API，不要改名
  00-utils.js         偏移常量、string/array 读写、分片回传、自检
  10-il2cpp-api.js    il2cpp_* 导出 API 绑定（延迟调用 bindIl2cpp）
  20-dump.js          转储 / 导出 IDA script
  30-hook.js          hook / replace / 参数读写助手
  40-hybridclr.js     热更 DLL 抓取与替换
  50-stalker.js       指令级追踪（call/block/insn/xor/table/mul/branch）
  60-nettrace.js      进程内网络抓包（SSL/socket 明文）
  70-memscan.js       内存扫描（CE 式多次过滤收敛）
  80-anti.js          反检测绕过 / 暴露面自检
  85-extras.js        Java hook、Unity 日志、堆字符串、批量 hook、性能剖析
  90-invoke.js        主动调用、静态字段读写、时间倍速
  93-assets.js        AssetBundle 捕获与场景枚举
  96-dumpextra.js     运行时 dump.cs / 重建 libil2cpp.so
  98-monitor.js       文件 I/O 与加密调用监控
  99-entry.js         引导（轮询等 libil2cpp.so 就绪）+ rpc.exports
host/
  run.py              动态 CLI 驱动：spawn/attach、收数据落盘、interactive REPL
  analyze.py          离线分析已有 JSON/JSONL 产物
  memdump.py          Frida 进程内存快照（喂给 carve）
  mitm.py             通过 ADB 设置设备 HTTP 代理（与 SSL hook 互补）
  provision_server.py 按本机 frida 版本下载并推送匹配的 frida-server
  repack.py           重打包 + 签名 / 替换文件 / 注入 frida-gadget
  capture_hot_test.py 限时热更抓取辅助脚本（需真实设备）
static/               不注入、不启动应用的静态能力
  analyze.ps1         APK 审计
  recover.py          Il2CppDumper / Il2CppInspector 类型/签名恢复
  decompile_native.py Ghidra / IDA(Hex-Rays) 原生伪 C 导出
  decompile_managed.py ILSpyCmd 托管 DLL 反编译
  collect.py          split APK/APKS/XAPK/OBB 收集与哈希
  calibrate.py        静态 RVA → 运行时地址
  diff.py             两个 classes.json 跨版本比较
  crosscheck.py       运行时 RVA 与 Il2CppDumper ScriptMethod 地址交叉校验
  emulate.py          Unicorn 离线函数模拟（需 unicorn/capstone）
  patch.py            改写 libil2cpp.so 字节（写新文件）
  carve.py            从内存/二进制 dump 离线捞字符串与内嵌镜像
  _elf.py             emulate/patch 共用的最小 ELF64 解析
  backfill.py         证据回写包 + Ghidra/IDA 注释脚本
docs/
  COMPLETE_WORKFLOW.md 完整、可复现的阶段化分析流程
tests/
  test_offline.py     离线逻辑单元测试（python tool.py selftest）
scripts/
  gadget.config       frida-gadget 配置（无 root 重打包用）
tools/                仅提交 native-tools-source.json；Ghidra/JDK/Il2CppDumper/
                      ILSpyCmd 等按需下载到此目录，已在 .gitignore 中忽略
```

加载顺序按文件名排序拼接（`run.py` 自动做），不要改名。

---

## 5. 常见坑 / 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `未找到 libil2cpp.so` | attach 太早 / 模块名不对 | 用 spawn 模式；Windows 加 `--module GameAssembly.dll` |
| `il2cpp 就绪超时` | 有反调试把进程挂起，或 Unity 启动就崩 | 先看 `adb logcat`，确认进程活着 |
| dump 出 0 个 image | domain 未初始化 | 等游戏进主界面后再调；`Dump.listImages()` 验证 |
| 字符串读出乱码/`<unreadable>` | 偏移不匹配或指针是值类型装箱 | 看启动日志里 `偏移自检` 是否通过 |
| Hook 上去就崩 | 参数签名写错 / 在回调里调了非线程安全的 il2cpp API | 先只打日志不改值；必要处 `il2cpp_thread_attach` |
| 抓不到热更 DLL | hook 装晚了 | 必须 spawn；gadget 用 `on_load: "wait"`；再不行看 C 方案的文件路径日志 |
| 找不到 hybridclr 符号 | so 被 strip | 用方案 B；或 IDA 搜 `"image can't be init again"` 拿 RVA |
| 进程检测到 frida 后退出 | 反注入（扫 maps/端口/线程名） | 改名 server、改端口、用 gadget、hook `strstr`/`open` 看它扫什么 |
| Obfuz 混淆后类名是乱码 | 正常现象 | 用 token + 参数签名定位，不要依赖名字 |

---

## 6. 静态 APK 审计（无需注入）

静态审计不需要向应用添加代码，也不需要 root、Frida 或运行应用。脚本会检查 APK
中的 ABI、`libil2cpp.so`、`global-metadata.dat`、托管 DLL、DEX、调试符号、AssetBundle
以及文本资源中的疑似敏感字符串。

分析本地 APK：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\static\analyze.ps1 `
  -ApkPath C:\path\to\game.apk
```

从已连接设备提取并分析：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\static\analyze.ps1 `
  -Device 127.0.0.1:7555 `
  -Package com.moonjoy.letsfarm `
  -PullFromDevice
```

输出包括：

- `static-report.json`：结构化报告
- `static-summary.txt`：摘要和敏感字符串线索
- `extracted\`：后续分析使用的解压目录

默认输出到 `out\static\`。报告中的 API key、secret 和 private key 只是匹配线索，
需要结合业务确认是否为真实凭据；如果是真实凭据，应从客户端移除并立即轮换。

恢复 IL2CPP 类型和方法目录（需要本机安装 .NET）：

```powershell
python .\static\recover.py `
  --input .\out\static\mumu-current\extracted `
  --output .\out\static\mumu-current\recovered
```

首次运行会下载官方 Il2CppDumper 6.7.46 发布包到 `tools\`，随后使用 ARM64
`libil2cpp.so` 和元数据生成 `dump.cs`、`DummyDll\`、`il2cpp.h`、`script.json`、
`stringliteral.json`。需要 Python 3.9+ 和可用的 .NET 运行时；当前主机 .NET 10
通过 Major roll-forward 已完成验证。

`dump.cs` 与 DummyDll 是类型、签名和字段结构，方法体为空/占位，不能作为原始
C# 源码或可运行工程。日志和状态记录在 `parser.log` 与 `recovery-status.json`。
解析器的版本自动调整或保护告警应保留，并对关键地址在原生反汇编器中复核。

对原生 ARM64 机器码生成少量伪 C（需要联网下载 Ghidra 和 JDK 21）：

```powershell
python .\static\decompile_native.py `
  --filter '^(GameUtility|ConfigProxy|FarmMockConfigAsset)\$\$' `
  --limit 20 `
  --timeout 15
```

默认输入当前 `mumu-current` 构建，输出到：
`out\static\mumu-current\native-decompiled\`。
其中 `functions\*.c` 是 Ghidra 生成的伪 C，`index.json` 保存元数据签名与对应文件，
`ghidra.log` 保存分析日志。伪 C 的参数类型、方法边界和间接调用需要人工复核；
它不是原始 C#，也不应直接用于修改或替换程序。

---

## 7. 进阶与补充手段

这些入口用于在默认静态/动态链路之外补齐特定盲区，仅限自有或已获授权的目标。

### 7.1 反编译交叉：IDA/Hex-Rays 与 Il2CppInspector

Ghidra 伪 C 不够干净时，用 IDA 的 Hex-Rays 复核同一批地址（IDA 为商业软件，
不随仓库分发，需本机已装 `idat64`）：

```powershell
python tool.py static --apk game.apk --recover --decompile --engine ida `
  --ida-path "C:\Program Files\IDA\idat64.exe"   # 或让 idat64 在 PATH 上
```

> `--engine` 默认 `ghidra`（自动下载，无需额外安装）；指定 `ida` 时需要本机
> 已装 Hex-Rays，通过 `--ida-path` 或 PATH 找到 `idat64`。也可直接调底层脚本
> `python static\decompile_native.py --engine ida --binary ... --symbols ...`。

用 Il2CppInspector 对照 Il2CppDumper 的恢复结果（某些 Unity 版本/metadata 布局更稳）：

```powershell
python static\recover.py --engine il2cppinspector `
  --input .\out\static\mumu-current\extracted `
  --output .\out\static\mumu-current\recovered-inspector `
  --inspector-cli C:\tools\Il2CppInspector\Il2CppInspector.exe
```

两套引擎的 `script.json`/地址可用 `tool.py crosscheck` 交叉校验，互相补漏。

### 7.2 离线函数模拟（对抗混淆，不连设备）

把单个自包含函数（校验、字符串解密、密钥调度）从 `libil2cpp.so` 切出来用
Unicorn 直接跑，不启动 app。需要 `pip install unicorn capstone`：

```powershell
python tool.py emulate --binary libil2cpp.so --rva 0x1A2B3C `
  --arg 0=0x40000000 --arg 1=16 --map 0x40000000=input.bin `
  --read 0x40000000:64 --trace --out emulate.json
```

它**不**模拟 IL2CPP 运行时：遇到对外部函数/分配/`il2cpp_*` 的调用会落到未映射
内存。适合叶子函数，或在首个无法解析的调用处停下看状态。结果是证据，需与真实
运行时行为交叉验证。这是动态 `stalk` 的离线补充。

### 7.3 Patch libil2cpp（比外部 hook 更彻底）

把改动直接烧进运行时库（加日志桩、NOP 掉反调试、翻转分支），再重打包重装。
始终写新文件、不就地改；给出 `旧字节:新字节` 时会先校验，避免 RVA 过期写坏：

```powershell
python tool.py patch --binary libil2cpp.so --out libil2cpp.patched.so `
  --patch "rva:0x1A2B3C=00008052:200080d2"   # 先校验旧字节再写
```

产物附带 `*.patch.json`，记录文件偏移、前后字节和前后 SHA-256。

### 7.4 进程内存取证：dump + carve

hook 没覆盖到的结构，可整段快照内存再离线捞。先 dump（走 Frida）：

```powershell
python tool.py memdump --attach 12345 --out out\memdump
python tool.py memdump --pkg com.your.game --module libil2cpp.so --out out\dump
```

再对导出的 `segments\*.bin` 做离线 carve（ASCII/UTF-16 字符串、敏感串、内嵌
PE/ELF/DEX/ZIP 可抽取）：

```powershell
python tool.py carve out\dump\segments\*.bin --secrets --extract --out out\carved
```

### 7.5 MITM 代理（协议层全量留存，与 SSL hook 互补）

进程内 SSL hook 在抗 pinning、免装证书上更省事；代理则给出可回放的完整协议日志，
适合未做 pinning 的流量。该入口只通过 ADB 设置/清除/查看设备 HTTP 代理，不装 CA、
不绕 pinning、不启动代理本身：

```powershell
python tool.py mitm set --device 127.0.0.1:7555 --host 127.0.0.1 --port 8080 --reverse
python tool.py mitm status --device 127.0.0.1:7555
python tool.py mitm clear --device 127.0.0.1:7555
```

### 7.6 frida-server 自动下载并推送

按本机安装的 frida 版本（二者主版本必须一致）拉取对应 ABI 的 frida-server，
push 到设备并 chmod；可改名、改端口规避最朴素的 frida 检测：

```powershell
python tool.py provision-server --device 127.0.0.1:7555
python tool.py provision-server --device DEVICE --name vendor_thermal --port 47000 --start
```

### 7.7 重打包 + 签名（闭环 patch / gadget）

把 `patch` 产出的 `libil2cpp.so` 换回 APK 再签名，或无 root 时注入 frida-gadget。
需要 PATH 上有 `apktool`、`zipalign`、`apksigner`、`keytool`；未指定签名库时会在
`tools\` 生成一个调试用 keystore：

```powershell
# 换入打过补丁的 so
python tool.py repack --apk game.apk --out game.patched.apk `
  --replace lib/arm64-v8a/libil2cpp.so=libil2cpp.patched.so

# 无 root：注入 gadget（smali 的 loadLibrary 注入为尽力而为，失败会提示手动补）
python tool.py repack --apk game.apk --out game.gadget.apk `
  --gadget libfrida-gadget.so --abi arm64-v8a
```

### 7.8 离线单元测试

纯 Python 的离线逻辑（ELF 映射、patch、carve、emulate、diff、calibrate、
crosscheck、analyze）有单元测试，用合成样本运行、不依赖设备：

```powershell
python tool.py selftest          # 等价于 python -m unittest discover -s tests
```

`emulate` 的用例在未安装 `unicorn` 时会自动跳过。

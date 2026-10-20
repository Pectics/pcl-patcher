# PCL 原版 Minecraft 下载恢复补丁

针对 `Plain Craft Launcher 2.exe` **2.99.0.0** 的本地补丁，用于恢复被移除的
原版 Minecraft 下载 / 安装功能。

- 补丁程序：`pcl_download_unlock.py`
- 已生成的补丁副本：`Plain Craft Launcher 2.unlocked.exe`
- 分析工具（可选）：`tools/`
- 参照样本：`Plain Craft Launcher 2.exe.backup`（2.13.1.1，下载功能正常）

| 文件 | SHA-256 |
| --- | --- |
| `Plain Craft Launcher 2.exe`（2.99.0.0 原版） | `5b64d6d540c376390470cea3ab99d47661e8bca81be2ba647ea83e7d2e9428fa` |
| `Plain Craft Launcher 2.unlocked.exe`（补丁后） | `ac62969bb5b778f52526b5d55c85d1f0c4f703ee5134b0acb555424f5a61cebf` |

> 仅修改你自己电脑上的本地副本。请遵守 Minecraft 最终用户许可协议。

---

## 1. 结论先看

2.99.0.0 **并没有删除下载引擎**。Mojang / BMCLAPI 版本清单请求、版本 JSON
解析、资源与库文件下载、安装、Forge/Fabric 等加载器安装，全都还在。

被移除的只有下载页（`PageDownloadInstall`）的入口初始化方法
`LoaderInit`：

| 版本 | `LoaderInit` 行为 |
| --- | --- |
| 2.13.1.1 | `PageLoaderInit(..., DlClientListLoader, AddressOf LoadMinecraft_OnFinish, ..., autoRun:=True)` |
| 2.99.0.0 | 构造一个占位加载器，界面只显示“关闭下载”按钮；启动时抛出<br>`为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……` |

因此，把 `LoaderInit` 的方法体改回“启动 `DlClientListLoader` 并在完成后回调
`LoadMinecraft_OnFinish`”即可恢复整条链路。补丁不做任何代码注入，也不新增
节区，只重写这一个方法内部的 IL 字节。

补丁后的等价 VB 代码：

```vb
Private Sub LoaderInit()
    ControlInit()
    PageLoaderInit(
        LoadMinecraft, PanLoad, PanAllBack,
        Nothing,
        DlClientListLoader,
        New Action(Of LoaderTask(Of String, DlClientListResult))(
            AddressOf LoadMinecraft_OnFinish),
        Nothing,
        autoRun:=True)
End Sub
```

---

## 2. 分析过程摘要

### 2.1 版本与结构

两个文件都是单文件 .NET（WinForms/WPF）程序集：

| | 备份（可用） | 新版本 |
| --- | --- | --- |
| AssemblyVersion | `2.13.1.1` | `2.99.0.0` |
| 目标方法 RVA | `0x2EB98` | `0x2E578` |
| `LoaderInit` 代码长度 | 62 字节 | 94 字节 |
| 强名称 / Authenticode | 无 | 无 |

`DlClientListLoader`、`DlClientListMojangMain`、`DlClientListBmclapiMain`
等全部保留，且新旧版本实现基本一致（新版本把 `McVersion` 移到了内嵌的
`PCLCS.dll` 中，`VersionToDrop` 逻辑正常）。

### 2.2 定位禁用点

在新版本中检索用户字符串，可发现新增的：

```
为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……
关闭下载
删除：为遵守相关法律法规，PCL 暂时不再提供 MC 下载功能，非常抱歉 qwq……
```

对引用这些字符串的方法做 IL 扫描：

- `PCL.PageDownloadInstall.LoaderInit` —— 使用“关闭下载”，是下载页初始化入口；
- `_Closure$__._Lambda$__3-0` —— 占位加载器启动时直接 `throw new Exception(上面的文字)`；
- `PCL.ModModpack.ModpackInstall()`（无参重载）—— 整合包安装入口的禁用桩；
- `FormMain.ShowUpdateLog` —— 仅更新日志文本。

对比 `LoaderInit`：

**2.13.1.1**

```text
ldarg.0
ldfld        DisabledPageAnimControls
ldarg.0
callvirt     get_BtnStart
callvirt     Add
ldarg.0
ldarg.0
callvirt     get_LoadMinecraft
ldarg.0
callvirt     get_PanLoad
ldarg.0
callvirt     get_PanAllBack
ldnull
ldsfld       ModDownload::DlClientListLoader
ldarg.0
ldftn        PageDownloadInstall::_Lambda$__R2-3   ' → LoadMinecraft_OnFinish
newobj       Action(Of LoaderTask(Of String, DlClientListResult))::.ctor
ldnull
ldc.i4.1
call         MyPageRight::PageLoaderInit
ret
```

**2.99.0.0**

```text
ldarg.0
call         ControlInit
ldarg.0
ldarg.0
callvirt     get_LoadMinecraft
ldarg.0
callvirt     get_PanLoad
ldarg.0
callvirt     get_PanAllBack
ldnull
ldstr        "关闭下载"                  ' 占位按钮标题
ldsfld       _Closure$__::$IR3-3
...
newobj       <一个会抛异常的占位加载器>
ldarg.0
ldftn        PageDownloadInstall::_Lambda$__R3-4   ' 同样是 LoadMinecraft_OnFinish
newobj       Action(...)::.ctor
ldnull
ldc.i4.1
call         MyPageRight::PageLoaderInit
ret
```

2.99.0.0 仍然传入了同一个完成回调 `_Lambda$__R3-4`（内容就是调用
`LoadMinecraft_OnFinish`），只是把真正的 `DlClientListLoader` 换成了一个
会抛异常的占位加载器。

### 2.3 补丁方法

只改 `LoaderInit` 的代码区：

```text
02                         ldarg.0
28 <ControlInit>           call ControlInit
02 02                      ldarg.0, ldarg.0
6F <get_LoadMinecraft>     callvirt get_LoadMinecraft
02 6F <get_PanLoad>        ...
02 6F <get_PanAllBack>     ...
14                         ldnull
7E <DlClientListLoader>    ldsfld
02                         ldarg.0
FE 06 <lambda R3-4>        ldftn
73 <Action ctor>           newobj
14 17                      ldnull, ldc.i4.1
28 <PageLoaderInit spec>   call
2A                         ret
```

所有 token 都从目标程序集自身的元数据中按名称解析，其余字节用 `nop` 填充。
方法头、元数据、节表均不变；`AssemblyVersion` 检查为 `2.99.0.0`，
并校验方法指纹与 token 指向，不匹配会拒绝修改。

---

## 3. 用法

```bash
# 1) 先干跑，确认识别正确
python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" --dry-run

# 2) 生成补丁副本（默认输出 *.unlocked.exe）
python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe"

# 或指定输出
python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" -o "PCL-unlocked.exe"

# 原地替换（自动备份为 *.unlock-backup）
python3 pcl_download_unlock.py "Plain Craft Launcher 2.exe" --in-place
```

无需安装任何第三方 Python 包。重复运行是安全的：已打过补丁的文件会被识别。

### 运行补丁后

1. 用输出文件替换或直接运行 `*.unlocked.exe`；
2. 打开 PCL → 下载 → 安装原版；
3. 版本列表应正常出现（Mojang / BMCLAPI），选择版本后即可安装。

如果下载页仍然不可见，请检查 PCL 设置中的 `UiHiddenPageDownload`
（隐藏下载页）是否为 `False`；本补丁不会修改任何配置文件。

---

## 4. 验证

补丁程序会做：

- 程序集名 / 版本检查（`Plain Craft Launcher 2` / `2.99.0.0`）；
- `LoaderInit` 指纹检查（必须以 `ControlInit()` 开始，并包含“关闭下载”占位逻辑）；
- `PageLoaderInit` 必须解析到 `PCL.MyPageRight.PageLoaderInit`；
- 完成回调必须是 `PageDownloadInstall` 自己的 `_Lambda$__R3-4`；
- 类型检查（静态）：
  - `DlClientListLoader` 类型为 `LoaderTask(Of String, DlClientListResult)`；
  - `PageLoaderInit` 的 MethodSpec 泛型实参同为
    `(String, DlClientListResult)`；
  - 完成回调是 `Action(Of LoaderTask(Of String, DlClientListResult))`；
  - `LoadMinecraft` 返回 `PCL.MyLoading`，参数类型与签名一致。
- 补丁后回读校验：重新解析 PE/元数据，确认方法体字节与新 IL 一致。
- **Windows 实机 JIT 校验**：在 .NET Framework 4.x 下用
  `RuntimeHelpers.PrepareMethod` 强制 JIT 该方法的最终版本，返回 `JIT OK`；
  并已确认下载页可正常进入。

补丁只改变这一个方法体内的 94 字节，实际字节差异为 65 字节，全部落在
`0x2C79E..0x2C7E0`（即 `LoaderInit` 代码区 `0x2C784..0x2C7E1` 内），
文件其余部分完全一致。

> **重要：方法尾部填充必须用 `ret`（`0x2A`），不能用 `nop`（`0x00`）。**
> .NET Framework 的 JIT 会把 `ret` 之后、方法末尾的不可达 `nop` 视为
> “可落入方法末尾”的路径，从而抛出 `InvalidProgramException`。
> 补丁程序已按此实现。

> 已保留原文件，并在 Windows 上实机验证：补丁后的程序可启动，下载页可进入，
> 版本列表加载正常。

---

## 5. 已知限制

- **整合包安装**另有一个禁用入口：`PCL.ModModpack.ModpackInstall()` 无参重载
  被替换成只弹提示的桩。本补丁不处理它；直接安装原版游戏不受影响。
- 如果 PCL 后续发布新构建，token / 偏移可能变化。补丁程序会按名称重新解析
  token，并在指纹不符时拒绝修改；届时可能需要更新版本白名单。
- 本补丁恢复的是客户端侧入口。Mojang / BMCLAPI 的下载源本身若不可达，
  仍需要在 PCL 设置中切换下载源。

---

## 6. 目录

```
pcl_download_unlock.py      补丁程序（可独立运行）
README.md                   本文
tools/dnmeta.py             极简 .NET PE / 元数据解析（分析用）
tools/ilscan.py             IL 字符串/调用扫描（分析用）
tools/ildis.py              IL 反汇编（分析用）
Plain Craft Launcher 2.exe             2.99.0.0（目标）
Plain Craft Launcher 2.exe.backup      2.13.1.1（对照）
```

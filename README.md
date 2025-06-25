## 这是一份针对AMD的FchSmmDispatcher驱动逆向分析的项目报告
因为个人原因中断 我希望在smm驱动中实现执行自定义的c代码来实现一些游戏辅助功能 希望有人看到可以继续下去

# SMM 驱动分析与游戏辅助功能实现 - 项目进度日志

**项目名称:** SMM 驱动分析与游戏辅助功能实现

**最后更新日期:** 2025-06-25

## 核心项目目标

深入分析特定SMM驱动（当前目标二进制 `FHB/FchSmmDispatcher.efi`）的内部机制，寻找安全的入口点或方法，在SMM中插入自定义处理逻辑，最终目标是实现游戏辅助功能（如自瞄、鼠标移动）并规避反作弊系统的检测。

## 当前主要策略 (基于对目标二进制的逆向分析)

1.  **核心策略:** **通过对目标SMM模块 `FHB/FchSmmDispatcher.efi` 进行深入的静态和（未来可能的）动态逆向工程，识别其内部结构、关键函数（特别是SMI Handler注册与分发逻辑）、数据流以及未使用的代码/数据区域。利用这些信息，在模块内安全地植入自定义代码，并通过已有的或新构造的SMI入口点触发执行，以实现隐蔽的游戏辅助功能。**
2.  **主要分析工具:** IDA Pro (通过 `ida-pro-mcp` 插件), Radare2 (命令行逆向工具), 和 Rizin (命令行逆向工具)。(未来可能结合GDB, QEMU等进行动态分析)。

-----

## 针对 `FHB/FchSmmDispatcher.efi` 的逆向分析与发现

*(新方案 - 缺乏公开资料，侧重纯逆向，按隐蔽性高低轮流实验)*

### A. 初步分析与核心问题识别

1.  **入口点与主要初始化函数识别 (使用IDA Pro + MCP):**

      * 模块入口点 `_ModuleEntryPoint` (地址 `0x1324`) 被识别。
      * `_ModuleEntryPoint` 调用 `sub_13A8` (地址 `0x13a8`, 大小 `0x60a`) 作为其主要的初始化函数。
      * `sub_13A8` 的初步反编译分析显示：
          * 它接收 `ImageHandle` 和 `SystemTable` 作为参数。
          * `qword_8A98` (已确认为 `gBS` - Boot Services Table) 从 `SystemTable` 偏移 `0x60` 处获取。
          * 通过 `gBS` 和其他定位到的协议接口进行多次服务调用。
          * 多个本地函数 (`sub_4FD0`, `sub_4FE8`, `sub_5040`, `sub_71F0`, `sub_74E4` 等) 被注册为回调/Handler。

2.  **关键数据 (GUID) 的识别问题:**

      * 在 `sub_13A8` 中用作服务调用参数的 `unk_XXXX` 地址，以及在模块其他地方发现的GUID，大部分已被成功识别（详见 D.1 小节）。这些GUID包括标准EFI协议、SMM事件协议、PCD TokenSpace GUID以及部分AMD厂商特定的GUID。
      * 这些GUID值是静态存在于文件中的，并非动态计算或通过标准PE重定位填充。

### B. 当前分析重点

1.  **确定 `qword_8D38` 链表（其数据源自AMD私有HOB）的最终消费者及其具体用途。** 这是"方向一"剩下的主要疑点，理解此链表如何被使用可能揭示FCH相关的关键配置逻辑。
2.  **解决 `qword_8AD0` 的确切初始化机制及其作为PCD服务提供者的具体工作方式。** `sub_4C04` 中对此的初始化逻辑与标准 `EFI_SMM_BASE2_PROTOCOL` 接口用法存在疑点。
3.  **[已解决] 获取 `sub_4FD0` (IDA显示地址 `0x4FD0`) 的确切文件偏移量，以便完成将其入口patch为跳转到代码洞 `0x7850` (RVA `0x17850`) 的二进制修改操作。**
      - 确认IDA地址即为文件偏移（ImageBase=0）
      - 成功在文件偏移`0x4FD0`处写入跳转指令`E9 7B 28 00 00`
      - 在代码洞`0x7850`处写入功能等效的shellcode（执行原函数逻辑后返回）
4.  **基于已找到的代码洞和潜在的劫持点，设计并测试SMM Shellcode，初步验证在SMM中执行自定义代码的可行性。** (方向二后续)
5.  **如果"方向一"对 `qword_8D38` 的追踪和"方向二"的入口劫持均遇到难以突破的障碍，则需重新评估其他潜在的攻击面或考虑引入动态分析方法。**

### C. 后续逆向分析计划

**总体策略:** 依次探索以下四种在SMM中实现自定义逻辑的方案，目标是找到隐蔽性和可行性的最佳结合点，以规避反作弊检测。

#### 方向一：利用现有SMI Handler的"预期行为"或"副作用"（理论最高隐蔽性）

  * **分析重点**:
      * （新增）明确 `qword_8D38` 链表的消费者，分析其数据如何影响系统行为。
      * （新增）彻底搞清 `qword_8AD0` 的来源和它提供的PCD服务的具体细节。
      * （新增）分析未知协议 `af62673d-deda-43ae-8f03-9c2d89fd78da` (`unk_8190`) 的其他潜在功能。
      * （原）深入逆向分析已识别的SMI Handler，理解其数据来源、逻辑分支，寻找可被外部影响的环节和不改变核心行为前提下的"副作用"利用点。

#### 方向二：在模块的"空白区域"或"数据区域"植入代码，并通过微小改动劫持执行流（较高隐蔽性）

  * **分析重点**:
      * （已完成初步）精确查找安全空白区。已在 `.text` 节末尾发现约1968字节代码洞 (RVA `0x17850`，文件偏移 `0x7850`)。已将测试shellcode写入。
      * （进行中）确定可靠的劫持点（如修改 `sub_4FD0` 入口或其他函数调用/指针），并完成二进制patch。
      * 确保不破坏原有功能，处理执行流返回，关注权限和可能的校验和问题。

#### 方向三：修改模块的SMI Handler注册表/机制（中等隐蔽性）

  * **核心思想**: 定位和理解模块内部管理SMI Handler的数据结构（如函数指针数组/链表）。通过Patch文件或运行时修改（若可能）该结构，将某个SMI的处理指向我们的代码。
  * **分析重点**: 准确找到Handler注册表的结构和位置，评估修改可行性（内存区域权限、完整性校验），确保自定义Handler能安全处理SMI上下文并返回。

#### 方向四：注册一个全新的SMI Handler（较低隐蔽性，但技术上可能更直接）

  * **核心思想**: 尝试通过模块可能暴露的私有服务，或通过标准的 `gSmst->SmiHandlerRegister`（如果可用且适用）来注册一个新的SMI Handler。
  * **分析重点**: 寻找私有注册服务接口，评估标准`gSmst`服务的可用性和权限，设计不与现有SMI冲突的SMI号或事件源。关注新Handler在SMM内部留下的痕迹。

**当前实验顺序:** 我们将从 **方向一** 开始探索，如果难度过大或未找到可行路径，则依次尝试 **方向二**、**方向三**，最后考虑 **方向四**。

-----

### D. 详细分析进展

#### D.1. 已识别的关键GUID和服务及其作用

| RVA (固件内地址) | GUID | 官方名称 / 宏符号 | 阶段 & 类别 | 主要作用和在模块中的观察点 |
| :--- | :--- | :--- | :--- | :--- |
| `0x8270`, `0x8100` | `f4ccbfb7-f6e0-47fd-9dd4-10a8f150c191` | `EFI_SMM_BASE2_PROTOCOL_GUID` | 核心SMM Protocol | `sub_13A8`用其定位服务，并通过其接口偏移`+8`处函数获取SMM服务表`qword_8AD8`和`qword_8AE0`。这些服务表用于注册SMI Handler。 |
| `0x80F0` | `e49d33ed-513d-4634-b698-6f55aa751c1b` | `gEfiSmbusHcProtocolGuid` | DXE Protocol | `sub_13A8`定位此协议到`qword_8B98` (`unk_8B18`)。`sub_71F0`使用`qword_8B98+72`处的服务收集信息。 |
| `0x8120`, `0x81F0` | `47b7fa8c-f4bd-4af6-8200-333086f0d2c8` | `gEfiSmmReadyToLockProtocolGuid` | SMM 事件 Protocol | 触发`sub_4FD0` (设置`byte_8AF0=1`)和`sub_74E4` (设置`byte_8BB8=1`)。 |
| `0x82B0`, `0x8260` | `24e70042-d5c5-4260-8c39-0ad3aa32e93d` | `EFI_SMM_END_OF_DXE_PROTOCOL_GUID` | SMM 事件 Protocol | 触发`sub_4FE8` (间接设置`byte_8B00=1`)和`sub_71F0` (数据收集)。 |
| `0x8230` | `96f5296d-05f7-4f3c-8467-e456890e0cb5` | `gEdkiiEndOfS3ResumeGuid` | SMM 事件 Protocol | 触发`sub_5040` (设置`byte_8B00=0`)。 |
| `0x81D0` | `2a3cfebd-27e8-4d0a-8b79-d688c2a3e1c0` | `gEfiSmmLockBoxCommunicationGuid` | SMM 通信 GUID | `sub_4F7C`用此GUID在`qword_8AE0`提供的数组中查找LockBox元数据链表头。 |
| `0x8740` | `aea6b965-dcf5-4311-b4b8-0f12464494d2` | S3 Boot Script LockBox GUID | LockBox GUID | `sub_53F0` (被`sub_56D8`调用时) 以此为目标与LockBox交互。 |
| `0x8720` | `b5af1d7a-b8cf-4eb3-8925-a820e16b687d` | Original Boot Script Data LockBox GUID (`BootScriptDataOrg`) | LockBox GUID | `sub_53F0` (被`sub_5AF4`调用时) 或 `sub_5094` (被`sub_56D8`调用时) 以此为目标与LockBox交互。 |
| `0x8710` | `627ee2da-3bf9-439b-929f-2e0e6e9dba62` | `gBootScriptSmmPrivateDataGuid` | LockBox GUID | `sub_56D8` 调用 `sub_5094` 以此GUID保存S3引导脚本的私有元数据到LockBox。 |
| `0x80B0` | `11b34006-d85b-4d0a-a290-d5a571310ef7` | `PCD_PROTOCOL_GUID` | DXE Protocol | `sub_4C04` 定位到 `qword_8AC8`，用于访问Dynamic PCD。 |
| `0x8170` | `13a3f0f6-264a-3ef0-f2e0-dec512342f34` | `EFI_PCD_PROTOCOL_GUID` | DXE Protocol | `sub_4C04` 定位到 `qword_8AB8`。`sub_4A50` 也用此GUID尝试通过 `qword_8AD0` 获取PCD服务，失败则用 `qword_8AB8`。 |
| `0x82D0` | `5be40f57-fa68-4610-bbbf-e9c5fcda365` | `gGetPcdInfoProtocolGuid` | DXE Protocol | `sub_4C04` 定位到 `qword_8AC0`，用于只读查询PCD元数据。 |
| `0x8130` | `fd0f4478-0efd-461d-ba2d-e58c45fd5f5e` | `gEfiGetPcdInfoProtocolGuid` (旧版) | DXE Protocol | `sub_4C04` 定位到 `qword_8AA8`，兼容旧版PCD信息获取。 |
| `0x82C0` | `c2702b74-800c-4131-8746-8fb5b89ce4ac` | `EFI_SMM_ACCESS2_PROTOCOL_GUID` | SMM Protocol | `sub_13A8` 定位，用于获取SMRAM Map (`GetCapabilities` at offset +24)。 |
| `0x8290` | `05ad34ba-6f02-4214-952e-4da0398e2bb9` | `EFI_DXE_SERVICES_TABLE_GUID` | 系统配置表 | `sub_13A8` 中作为参数传递给 `sub_54C0` (可能用于获取DXE服务表本身或相关信息)。 |
| `0x8150` | `dcfa911d-26eb-469f-a220-38b7dc461220` | `EFI_MEMORY_ATTRIBUTES_TABLE_GUID` | 系统配置表 | `sub_71F0` 中作为参数传递给 `sub_54C0` 来获取内存属性表。 |
| `0x8240` | `d4d8435f-fffb-4acb-a04d-ff0fad677fe9` | `gEfiAmdAgesaPkgTokenSpaceGuid` | PCD Token-Space GUID | `sub_13A8` 中与PCD服务 (`sub_4A50` 返回) 一起使用，访问AGESA包级别的PCD。 |
| `0x81B0` | `7788adf0-9788-4a3f-83fa-cb512e7cf8dd` | `gEfiAmdAgesaModulePkgTokenSpaceGuid` | PCD Token-Space GUID | `sub_64D8` 和 `sub_636C` 中与PCD服务一起使用，访问AGESA模块级别的PCD。 |
| `0x8000` | `5b1b31a1-9562-11d2-8e3f-00a0c969723b` | `gEfiLoadedImageProtocolGuid` | DXE Protocol | `sub_4C04` 获取模块自身的 `LoadedImageProtocol`，可能用于检查镜像类型。 |
| `0x8280` | `13fa7698-c831-49c7-87ea-8f43fcc25196` | `gEfiEventVirtualAddressChangeGuid` | 事件组 GUID | `sub_4C04` 创建事件并注册 `sub_4AD8` 作为此事件的回调，用于虚拟地址转换。 |
| `unk_8190` | `af62673d-deda-43ae-8f03-9c2d89fd78da` | *未知* | SMM Protocol? | `sub_13A8` 尝试定位。若成功，`qword_8D38` 指向其接口+8处链表头；若失败，`sub_6C7C` 从HOB填充`qword_8D38`链表。 |
| HOB Data | `d97d161a-16cd-4ada-b9f6-aec3f9fccc2c` | *AMD私有HOB GUID* | HOB GUID | `sub_6C7C` 在HOB列表中搜索此GUID的扩展HOB，提取数据填充到`qword_8D38`链表。 |
| SMM Comm (Proto) | `5e5e23bc-...-0a4d` | *私有SMM通信协议* (`unk_8040`) | SMM Protocol | `sub_636C` (LegacyBoot Handler) 使用此协议向SMM发送S3私有数据信息。 |
| SMM Comm (Header)| `5c4061f0-...-cec0` | *私有SMM通信处理器GUID* (`qword_81C0/81C8`) | SMM 通信 `HeaderGuid` | `sub_636C` 将此GUID置于通信缓冲区头部，用于SMM内部路由到特定处理器。 |

#### D.2. 已分析的关键函数及其交互作用

  * **`sub_13A8` (模块入口点调用)**: 负责整个模块的核心初始化。

      * 获取 `gBS` (`qword_8A98`) 和 `gST` (`qword_8A90`, `qword_8AA0`)。
      * 调用 `sub_4C04()` 进行早期服务定位和事件注册。
      * 使用 `sub_4A50()` 和 `gEfiAmdAgesaPkgTokenSpaceGuid` 读取PCD值。
      * 定位 `EFI_SMM_ACCESS2_PROTOCOL` 获取SMRAM Map信息。
      * 定位 `EFI_SMM_BASE2_PROTOCOL_GUID` 并初始化SMM服务表 `qword_8AD8` 和 `qword_8AE0`。
      * 通过SMM服务表注册多个SMI Handlers (`sub_4FD0`, `sub_4FE8`, `sub_5040`, `sub_71F0`, `sub_74E4`)。
      * 初始化LockBox、SMBus等协议。
      * 处理 `qword_8D38` 链表的初始化（通过未知协议`unk_8190`或从HOB填充）。

  * **`sub_4C04()` (早期初始化)**:

      * 使用 `gBS` 定位多种PCD服务协议。
      * 尝试通过 `EFI_SMM_BASE2_PROTOCOL` 初始化 `qword_8AD0` (推测为SMM环境PCD服务)。
      * 注册 `sub_4AD8` 作为 `gEfiEventVirtualAddressChangeGuid` 事件的回调。

  * **SMI Handlers (部分)**:

      * `sub_4FD0()`: (`SMMReadyToLock`时) 设置 `byte_8AF0 = 1`。
      * `sub_71F0()`: (`EndOfDxe`时) 进行复杂的数据收集，包括枚举EFI实体、通过SMBus获取数据、获取内存属性表。
      * `sub_56D8()`: (`ExitBootServices`或`LegacyBoot`时) 处理S3引导脚本相关的LockBox保存操作。
      * `sub_636C()`: (`LegacyBoot`时) 通过私有SMM通信协议将S3相关信息发送到SMM。

#### D.3. "方向一" 分析小结与当前状态

  * **已取得进展**：
      * 识别了多个关键SMI Handler及其触发事件。
      * 明确了全局标志位如何影响关键函数（如LockBox操作和内存安全检查）的行为。
      * 阐明了SMM LockBox的创建和访问机制。
      * 发现了一个内部数据链表 `qword_8D38`，其数据来源于AMD私有HOB。
  * **当前挑战与未解之谜**：
      * **`qword_8D38` 链表的消费者**：其最终如何被使用仍然未知。
      * **未知协议 `unk_8190` 的具体功能**：此协议的功能和用途不明。
      * **`qword_8AD0` 的确切初始化和性质**：其初始化逻辑与标准协议不完全匹配。
      * **直接利用"副作用"的难度**：由于回调与标准SMM事件流绑定，且关键数据在早期确定，从外部精确利用较为困难。

#### D.4. "方向二" 初步探索与进展

  * **节区分析**：
      * `.text` 节 (代码): RVA `0x11000` - `0x17FFF`, 权限 `r-x`。
      * `.data` 节 (数据): RVA `0x18000` - `0x18FFF`, 权限 `rw-`。
  * **代码洞发现**：
      * 在 `.text` 节末尾发现一个约 **1968字节** (`0x7B0`) 的连续 `0x00` 填充区域，RVA为 `0x17850`。此区域文件偏移为 `0x7850`，具有可执行权限，是理想的shellcode植入点。
  * **劫持与Patch**：
      * 已选择 `sub_4FD0` (RVA `0x4FD0`, 文件偏移 `0x4FD0`) 作为patch目标。
      * 已成功将其入口修改为跳转到代码洞的指令 `E9 7B 28 01 00`。
  * **当前挑战**：
      * **地址映射问题**：IDA Pro显示的地址与Radare2显示的RVA存在不一致。**（已通过确认ImageBase为0解决）**
      * **自动化Patch**：通过脚本工具执行精确的二进制patch命令存在不便，推荐使用十六进制编辑器。

-----


### 先前分析存档 (针对 `FHB/PiSmmCore.efi`)

**(此部分为先前对 `FHB/PiSmmCore.efi` 的分析结果，现已存档，备查)**

### A. 空白区域探测与分析

1.  **大块空白区域识别:**

      * **`sect_2` 节:** \~4 KB, 只读, 几乎完全填充`0x00`。
      * **`.xdata` 节:** \~4 KB, 只读, 几乎完全填充`0x00`。
      * **`.reloc` 节末尾:** \~3.8 KB, 只读, 有效数据后的区域填充`0x00`。

2.  **`.text` 节末尾空白区域详细探测:**

      * `.text` 节范围: `0x00011000` - `0x00018fff` (权限 `r-x`)。
      * **发现:** 从 `0x000180ce` 到 `0x00018fff` (约3.8 KB) 区域**全部填充为0x00字节**，且具有可执行权限。

3.  **初步总结的可利用空白区域 (大约):**

      * `.text` 节末尾 (可执行): \~3.8 KB
      * 其他只读节区 (可修改PE头改变权限): \~11.8 KB
      * **总计主要空白区域: 约 15.6 KB**。

### B. `PiSmmCore.efi` 初始化流程与关键函数初步分析

1.  **模块入口点 `entry0` (`0x00011138`):**

      * 调用 `fcn.00011164` (主要初始化函数)。
      * 有条件地调用其他函数。

2.  **`fcn.00011164` (主要初始化函数) 初步分析:**

      * **发现 "SMST" 字符串引用**，表明可能在查找和使用SMM Services Table (`gSmst`)。
      * **推测的 `gSmst` 服务调用 (基于rax内容和偏移量):**
          * `call qword [rax + 0x40]` (可能是 `SmmRegisterProtocolNotify`)
          * `call qword [rax + 0x48]` (可能是 `SmmInstallConfigurationTable`)
          * `call qword [rax + 0x18]` (可能是 `SmmAllocatePool`)
      * **当前状态**: 未在直接代码中观察到 `SmiHandlerRegister` 的调用。SMI的注册可能在更深层次的调用中。

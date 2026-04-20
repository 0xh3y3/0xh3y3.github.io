---
title: 'Linux ptrace 调用速查表'
published: 2026-04-20
description: '整理常用及现代内核支持的 ptrace 请求、选项与事件，附 x86_64 数值速查与 shellcode 参数约定'
tags: [Pwn, Linux, ptrace, syscall]
category: 'Pwn'
draft: false
---

> 本文整理了常用及现代内核支持的 `ptrace` 请求（requests）、选项（options）与事件（events），并说明各参数的语义与典型用法。跨架构/内核版本可能存在差异，实际以目标系统头文件 `include/uapi/linux/ptrace.h` 与手册页为准。

## 函数签名

```
long ptrace(int request, pid_t pid, void *addr, void *data);  syscall 101
```
- `request`: `PTRACE_*` 请求常量。
- `pid`: 要操作的"被跟踪线程"（tracee）的 TID（线程 ID）。除 `PTRACE_TRACEME` 外，其它请求通常要求 tracee 处于"ptrace-stop"状态。
- `addr` / `data`: 随请求变化；本文在每个请求条目中说明其含义。
- 返回值：成功返回非负值（部分请求返回读取到的数据），失败返回 `-1` 并设置 `errno`。

---

## 请求（Requests）

| 请求                            | 作用                          | `addr`                              | `data`                          | 备注/典型用法                                                    |
| ----------------------------- | --------------------------- | ----------------------------------- | ------------------------------- | ---------------------------------------------------------- |
| `PTRACE_TRACEME`              | 调用线程声明自身可被其父进程跟踪            | 忽略                                  | 忽略                              | 一般随后 `raise(SIGSTOP)`，父进程 `wait()` 观测到停止后开始跟踪；仅由 tracee 使用 |
| `PTRACE_PEEKTEXT`             | 读取 tracee 指令空间一个机器字         | 目标地址                                | 忽略                              | 旧接口，现代更常用 `PTRACE_PEEKDATA`/`process_vm_readv`             |
| `PTRACE_PEEKDATA`             | 读取 tracee 数据空间一个机器字         | 目标地址                                | 忽略                              | 经典读接口，返回值即读取内容（失败为 `-1`）                                   |
| `PTRACE_PEEKUSER`             | 读取旧版"用户区"寄存器块一个机器字          | 偏移                                  | 忽略                              | 旧接口，现代用 `PTRACE_GETREGSET`/`GETREGS` 替代                    |
| `PTRACE_POKETEXT`             | 写入 tracee 指令空间一个机器字         | 目标地址                                | 要写入的字                           | 常用于设置断点（写入 `int3`）                                         |
| `PTRACE_POKEDATA`             | 写入 tracee 数据空间一个机器字         | 目标地址                                | 要写入的字                           | 常用于修改内存缓冲/变量                                               |
| `PTRACE_POKEUSER`             | 写旧版"用户区"一个机器字               | 偏移                                  | 要写入的字                           | 旧接口，不推荐                                                    |
| `PTRACE_CONT`                 | 继续运行 tracee                 | 忽略或 0                               | 将要注入的信号或 0                      | 解除 `ptrace-stop`，并可投递信号到 tracee                            |
| `PTRACE_KILL`                 | 终止 tracee                   | 忽略                                  | 忽略                              | 直接杀死被跟踪线程                                                  |
| `PTRACE_SINGLESTEP`           | 单步执行一条指令                    | 忽略或 0                               | 信号或 0                           | 单步后再次进入 `ptrace-stop`                                      |
| `PTRACE_SYSCALL`              | 在下次系统调用入口/出口处停止             | 忽略或 0                               | 信号或 0                           | 用于系统调用跟踪                                                   |
| `PTRACE_ATTACH`               | 附加到已存在的线程，令其进入停止态           | 忽略                                  | 忽略                              | 传统 attach，tracee 会 `SIGSTOP`，需 `wait()` 等待                 |
| `PTRACE_DETACH`               | 从 tracee 分离并继续运行            | 忽略或 0                               | 信号或 0                           | 解除跟踪，常配合 `PTRACE_CONT` 的语义                                 |
| `PTRACE_GETREGS`              | 复制通用寄存器到 tracer 缓冲          | 忽略                                  | 指向 `struct user_regs_struct`    | 旧接口；跨架构兼容推荐 `GETREGSET`                                    |
| `PTRACE_SETREGS`              | 从 tracer 缓冲写回通用寄存器          | 忽略                                  | 指向 `struct user_regs_struct`    | 旧接口                                                        |
| `PTRACE_GETFPREGS`            | 获取 FPU 寄存器                  | 忽略                                  | 指向 `struct user_fpregs_struct`  | 旧接口                                                        |
| `PTRACE_SETFPREGS`            | 设置 FPU 寄存器                  | 忽略                                  | 指向 `struct user_fpregs_struct`  | 旧接口                                                        |
| `PTRACE_GETFPXREGS`           | 获取 x86 扩展 FPU（SSE）寄存器       | 忽略                                  | 指向 `struct user_fpxregs_struct` | x86 专用旧接口                                                  |
| `PTRACE_SETFPXREGS`           | 设置 x86 扩展 FPU（SSE）寄存器       | 忽略                                  | 指向 `struct user_fpxregs_struct` | x86 专用旧接口                                                  |
| `PTRACE_SETOPTIONS`           | 设置跟踪选项（见 Options）           | 忽略                                  | 选项位掩码                           | 必须在 tracee 停止时调用                                           |
| `PTRACE_GETEVENTMSG`          | 读取最近事件的附加消息                 | 忽略                                  | 指向 `unsigned long`              | 如 fork/clone 事件中的子 TID                                     |
| `PTRACE_GETSIGINFO`           | 获取待投递信号的 `siginfo_t`        | 忽略                                  | 指向 `siginfo_t`                  | 读取造成停止的信号信息                                                |
| `PTRACE_SETSIGINFO`           | 设置将要投递的 `siginfo_t`         | 忽略                                  | 指向 `siginfo_t`                  | 修改下次投递信号的细节                                                |
| `PTRACE_GETREGSET`            | 通过 `NT_*` 类型读取寄存器集合         | `addr` 为 regset 类型                  | `data` 指向 `struct iovec`        | 现代接口，跨架构统一                                                 |
| `PTRACE_SETREGSET`            | 通过 `NT_*` 类型写寄存器集合          | `addr` 为 regset 类型                  | `data` 指向 `struct iovec`        | 现代接口，跨架构统一                                                 |
| `PTRACE_SEIZE`                | 无信号/无停止地附加                  | 忽略或 0                               | 选项位掩码                           | 现代 attach，后续用 `PTRACE_INTERRUPT` 主动停止                      |
| `PTRACE_INTERRUPT`            | 强制使 tracee 进入 `ptrace-stop` | 忽略                                  | 忽略                              | 与 `SEIZE` 配合使用，无需发送信号                                      |
| `PTRACE_LISTEN`               | 继续等待下一个"组停止"（group-stop）    | 忽略                                  | 忽略                              | 仅在 `SEIZE` 模式下使用                                           |
| `PTRACE_PEEKSIGINFO`          | 扫描待处理信号队列                   | 指向 `struct ptrace_peeksiginfo_args` | 指向 `siginfo_t` 缓冲               | 可批量读取若干 `siginfo_t`                                        |
| `PTRACE_GETSIGMASK`           | 读取 tracee 的信号屏蔽集            | `addr` 为 `sigset_t` 大小              | `data` 指向 `sigset_t`            | 需 `SEIZE` 模式                                               |
| `PTRACE_SETSIGMASK`           | 设置 tracee 的信号屏蔽集            | `addr` 为 `sigset_t` 大小              | `data` 指向 `sigset_t`            | 需 `SEIZE` 模式                                               |
| `PTRACE_SECCOMP_GET_FILTER`   | 读取 seccomp 过滤器（BPF 程序）      | `addr` 为过滤器索引                       | `data` 指向缓冲                     | 仅在支持 seccomp 的新内核上可用                                       |
| `PTRACE_SECCOMP_GET_METADATA` | 读取 seccomp 过滤器元信息           | `addr` 为过滤器索引                       | `data` 指向元信息结构                  | 新内核可用                                                      |

> 架构特定（x86/i386 等）旧接口：`PTRACE_GET_THREAD_AREA`、`PTRACE_SET_THREAD_AREA` 等；仅在对应架构/旧内核有效，现代代码建议统一使用 `GETREGSET/SETREGSET`。

### 请求数值（x86_64）速查

```
PTRACE_TRACEME             = 0
PTRACE_PEEKTEXT            = 1
PTRACE_PEEKDATA            = 2
PTRACE_PEEKUSER            = 3
PTRACE_POKETEXT            = 4
PTRACE_POKEDATA            = 5
PTRACE_POKEUSER            = 6
PTRACE_CONT                = 7
PTRACE_KILL                = 8
PTRACE_SINGLESTEP          = 9
PTRACE_GETREGS             = 12
PTRACE_SETREGS             = 13
PTRACE_GETFPREGS           = 14
PTRACE_SETFPREGS           = 15
PTRACE_ATTACH              = 16
PTRACE_DETACH              = 17
PTRACE_GETFPXREGS          = 18   ; x86 旧接口
PTRACE_SETFPXREGS          = 19   ; x86 旧接口
PTRACE_SYSCALL             = 24

PTRACE_SETOPTIONS          = 0x4200
PTRACE_GETEVENTMSG         = 0x4201
PTRACE_GETSIGINFO          = 0x4202
PTRACE_SETSIGINFO          = 0x4203
PTRACE_GETREGSET           = 0x4204
PTRACE_SETREGSET           = 0x4205
PTRACE_SEIZE               = 0x4206
PTRACE_INTERRUPT            = 0x4207
PTRACE_LISTEN              = 0x4208
PTRACE_PEEKSIGINFO         = 0x4209
PTRACE_GETSIGMASK          = 0x420A
PTRACE_SETSIGMASK          = 0x420B
PTRACE_SECCOMP_GET_FILTER  = 0x420C
PTRACE_SECCOMP_GET_METADATA= 0x420D

; 系统调用号（x86_64）
SYS_ptrace                 = 101
```

> 注：以上为 Linux x86_64 常见定义；不同架构或更老内核可能有所差异，务必以目标系统的 `include/uapi/linux/ptrace.h` 为准。

### Shellcode 参数约定（x86_64）

- `rax`: 系统调用号（如 `SYS_ptrace = 101`）
- `rdi, rsi, rdx, r10, r8, r9`: 对应系统调用第 1–6 个参数

示例：`ptrace(PTRACE_TRACEME, 0, 0, 0)` 的最小汇编片段（x86_64 Linux）：

```asm
; 将当前线程置为可被父进程跟踪（仅 tracee 自身可用）
mov     rax, 101          ; SYS_ptrace
xor     rdi, rdi          ; request = PTRACE_TRACEME (0)
xor     rsi, rsi          ; pid = 0
xor     rdx, rdx          ; addr = 0
xor     r10, r10          ; data = 0
syscall

; 常见做法：随后触发停止，便于父进程接管
; mov   rax, 62           ; SYS_kill
; mov   rdi, 0            ; getpid() 可用时传自身 pid；在纯汇编中可先调用 getpid(39)
; mov   rsi, 19           ; SIGSTOP
; syscall
```

---

## 选项（Options，配合 `PTRACE_SETOPTIONS`/`PTRACE_SEIZE`）

- `PTRACE_O_TRACESYSGOOD`: 在系统调用停止时将 `SIGTRAP` 的高位标记（`0x80`），便于区分普通 `SIGTRAP`。
- `PTRACE_O_TRACEFORK`: 跟踪 `fork()` 产生的子进程，生成 `PTRACE_EVENT_FORK`。
- `PTRACE_O_TRACEVFORK`: 跟踪 `vfork()`，生成 `PTRACE_EVENT_VFORK`。
- `PTRACE_O_TRACECLONE`: 跟踪 `clone()`，生成 `PTRACE_EVENT_CLONE`。
- `PTRACE_O_TRACEEXEC`: 跟踪 `execve()`，生成 `PTRACE_EVENT_EXEC`。
- `PTRACE_O_TRACEVFORKDONE`: 跟踪 `vfork` 结束，生成 `PTRACE_EVENT_VFORK_DONE`。
- `PTRACE_O_TRACEEXIT`: 在进程退出前停止，生成 `PTRACE_EVENT_EXIT`。
- `PTRACE_O_TRACESECCOMP`: 在 seccomp 触发时停止，生成 `PTRACE_EVENT_SECCOMP`。
- `PTRACE_O_EXITKILL`: 若 tracer 终止，则被跟踪的所有 tracee 也被终止（内核 3.8+）。
- `PTRACE_O_SUSPEND_SECCOMP`: 在被跟踪期间暂时挂起 seccomp（较新内核）。

> 选项必须在 tracee 处于 `ptrace-stop` 的状态下设置；`SEIZE` 模式可在 attach 之初一次性提供选项掩码。

---

## 事件（Events，配合 `PTRACE_GETEVENTMSG`）

- `PTRACE_EVENT_FORK` = 1：`fork()` 产生的子进程。
- `PTRACE_EVENT_VFORK` = 2：`vfork()` 产生的子进程。
- `PTRACE_EVENT_CLONE` = 3：`clone()` 产生的子线程/进程。
- `PTRACE_EVENT_EXEC` = 4：执行了新的程序映像（`execve`）。
- `PTRACE_EVENT_VFORK_DONE` = 5：`vfork` 结束并恢复父进程。
- `PTRACE_EVENT_EXIT` = 6：将要退出，tracee 在最后时刻停止。
- `PTRACE_EVENT_SECCOMP` = 7：触发了 seccomp 过滤器。
- `PTRACE_EVENT_STOP` = 128：`SEIZE` 模式下的主动或组停止。

> 当出现上述事件停止时，`PTRACE_GETEVENTMSG` 可获取事件相关的附加信息（如子 TID）。

---

## 相关结构

使用 `PTRACE_GETREGS` 得到的寄存器顺序如下：

![user_regs_struct](/posts/ptrace-regs.png)

## 使用建议与注意事项

- 现代代码优先使用：`PTRACE_SEIZE`/`PTRACE_INTERRUPT` 管理生命周期，`PTRACE_GETREGSET`/`SETREGSET` 访问寄存器，`PTRACE_PEEKSIGINFO`/`GETSIGMASK` 管理信号。
- 传统 `ATTACH` 需要 `wait()`/`waitpid()` 与信号握手；`SEIZE` 可无信号附加，随后用 `INTERRUPT` 进入停止态。
- 读/写 tracee 大块内存推荐使用 `process_vm_readv`/`process_vm_writev`（非 `ptrace`），效率更高；`POKE/PEEK` 适合小粒度修改或设断点。
- 跨架构时，不要假定旧接口的寄存器布局；使用 `NT_PRSTATUS`/`NT_FPREGSET` 等 `regset` 类型通过 `iovec` 读写。

---

## 参考资料

- man7.org: ptrace(2) 手册页（现代内核详尽说明）
  - https://man7.org/linux/man-pages/man2/ptrace.2.html
- linux.die.net: ptrace(2) 手册页（概览）
  - https://linux.die.net/man/2/ptrace

> 数值常量与支持范围以目标机器内核版本与头文件为准；若需精确值，请查阅目标系统的 `include/uapi/linux/ptrace.h` 与 `asm/ptrace.h`。

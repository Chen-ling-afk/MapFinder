#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#定义utf-8编码

import time
import argparse
import threading
#导入自定义的模块
from color import *
from mapfind import *
from pyfiglet import Figlet

#写文件
def msg_input(Close=False, msg=None):
    file = open('output.txt', 'a')
    if Close == True:
        file.close()
    else:
        file.write(str(msg) + '\n')

#开始模块
def Start(url, thread=20):
    add_all_list(url)

    print('{:-^50}'.format(''))
    color_print(color='yellow', msg="开始进行whois查询......\n")
    cha_Whois(url)

    print('{:-^50}'.format(''))
    color_print(color="yellow", msg="开始进行子域名收集......\n")
    search_domain(url)

    print('{:-^50}'.format(''))
    color_print(color="yellow", msg="开始收集ip历史解析记录......\n")
    history_ip(url)

    thread_line1 = brute(url, thread)
    thread_line1.start()
    thread_line1.join()

    list = print_all_list()
    msg_input(msg="\n收集结果\n------------------------------------------")
    for i in list:
        msg_input(msg=i)

    thread_line2 = Crawl(thread)
    thread_line3 = port_scan(thread)
    thread_line = [thread_line2, thread_line3]
    for i in thread_line:
        # 开始线程
        i.start()
        # time.sleep(1)
        # 阻塞线程，先后执行
        i.join()
    remove_all_list()
    msg_input(Close=True)
    end()

def main():
    # 定义标志
    ling = Figlet(width=3000)
    ling = ling.renderText("MpFind")
    print("\033[1;35m" + ling + '{:>34}'.format("v_chenling") + "\033[0m")  # 字体加粗，紫色字体
    print("\033[1;35m"+ '{:*^34}'.format("") + "\033[0m")
    # 创建
    parser = argparse.ArgumentParser(prog='python3 MpFind.py')
    # 添加参数
    parser.add_argument('--url', help='Single domain detection')
    parser.add_argument('--file', help='Import domains from files')
    parser.add_argument('--thread', type=int, help='Set the number of threads, default is 20')
    args = parser.parse_args()
    if args.url:
        if args.thread:
            Start(args.url,args.thread)
        else:
            Start(args.url)
    elif args.file:
        file = open(str(args.file),'r')
        domains = []
        for i in file:
            if not i.split():
                continue
            domain = i.rstrip("\n")
            domains.append(domain)
        for j in domains:
            if args.thread:
                Start(j,args.thread)
            else:
                Start(j)

if __name__ == '__main__':
    start = time.time()
    main()
    print("用时: {:.3f}".format(time.time() - start) + "秒!")
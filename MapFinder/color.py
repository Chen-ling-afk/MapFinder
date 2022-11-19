#-*- coding: utf-8 -*-

import sys

#创建颜色类
class color_print():
    #初始化
    def __init__(self,color,msg):
        self.color = color
        self.msg = msg
        #调用颜色打印函数
        self.color_printf(self.color,self.msg)

    #定义打印颜色函数
    def color_printf(self,color,msg):
        colors = {
                  #字体高亮，颜色
                  'black'  : '\033[1;30m',
                  'red'    : '\033[1;31m',
                  'green'  : '\033[1;32m',
                  'yellow' : '\033[1;33m',
                  'blue'   : '\033[1;34m',
                  'purple' : '\033[1;35m', #紫色
                  'cyanine': '\033[1;36m', #青蓝
                  'white'  : '\033[1;37m',
                 }
        print(colors[color] + msg + "\033[0m")


class Color_print(object):
    def Print(self):
        colors = {
            # 字体高亮，颜色
            'black': '\033[1;30m',
            'red': '\033[1;31m',
            'green': '\033[1;32m',
            'yellow': '\033[1;33m',
            'blue': '\033[1;34m',
            'purple': '\033[1;35m',  # 紫色
            'cyanine': '\033[1;36m',  # 青蓝
            'white': '\033[1;37m',
        }
        try:
            print('')
            print(colors[self.color] + self.msg + "\033[0m")
        except:
            print('')
            print("该颜色没有被定义，请更改颜色。")
            pass


if __name__ == '__main__':
    Color = Color_print()
    Color.color = 'yellow'
    Color.msg = 'cheng'
    Color.Print()

    print_color = 'blue'
    print_msg   = 'ling'
    #第一个输入作为要打印的字体颜色，第二个参数作为要打印的数据
    color_print(color=print_color,msg=print_msg)
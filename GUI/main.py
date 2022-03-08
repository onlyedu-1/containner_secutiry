# -*- coding: UTF-8 -*-
import os
from tkinter import *
from tkinter import filedialog

from crawler import crawler
from extract import extract
import time


def file_get():
    outputfile = filedialog.asksaveasfilename(title=u'保存文件')


def show_images():
    r = os.popen('docker images').read()
    text.insert(INSERT, r)


def execute():
    begin = time.time()
    if outputfile.get():
        extract(image.get(), outputfile.get())
    else:
        extract(image.get())
    end = time.time()
    print("耗费时间：" + str(end-begin))
    with open('output.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        text1.insert(INSERT, line)



if __name__ == '__main__':
    root = Tk()
    root.geometry("540x430+292+176")
    root.title("ImageScanner")
    file = open("last_time.txt", 'r+', encoding="utf-8")
    date_str = file.readline()
    image = StringVar()
    outputfile = StringVar()

    label_1 = Label(root, text='当前漏洞数据库的最新更新时间为: ' + date_str, font=('微软雅黑', 15), width=30, height=1, anchor="w")
    label_ = Label(root, text='是否要更新漏洞数据库（更新操作耗时较长）？', font=('微软雅黑', 15), width=40, height=1, anchor="w")
    but_1 = Button(root, text="更新", command=crawler, width=5, height=1)

    label_1.grid(row=1, column=0, columnspan=2, sticky=N + S + W + E, padx=2, pady=2)
    label_.grid(row=2, column=0, columnspan=6, sticky=N + S + W + E, padx=2, pady=2)
    but_1.grid(row=2, column=2, sticky=W, padx=2, pady=2)

    label_2 = Label(root, text='请输入要扫描的镜像：', font=('微软雅黑', 15), width=20, height=1, anchor="w")
    ent_2 = Entry(root, show=None, font=('微软雅黑', 15), textvariable=image, width=20)
    label_ = Label(root, text='扫描结果要保存的位置：', font=('微软雅黑', 15), width=20, height=1, anchor="w")
    ent_ = Entry(root, show=None, font=('微软雅黑', 15), textvariable=outputfile, width=20)
    but_ = Button(root, text="开始扫描", command=execute, width=20)

    label_2.grid(row=4, column=0, columnspan=2, sticky=N + S + W + E, padx=2, pady=2)
    ent_2.grid(row=4, column=2, columnspan=2, sticky=W + E, padx=2, pady=2)
    label_.grid(row=5, column=0, columnspan=6, sticky=N + S + W + E, padx=2, pady=2)
    ent_.grid(row=5, column=2, sticky=W, padx=2, pady=2)
    but_.grid(row=6, column=2, sticky=W, padx=2, pady=2)

    but_3 = Button(root, text="查看当前镜像仓库镜像", command=show_images, width=20)
    label_3 = Label(root, text='反馈：', font=('微软雅黑', 10), width=20, height=1, anchor="w")
    text = Text(root, width=50, height=6, bg='#F0FFF0', font=('微软雅黑', 10))

    but_3.grid(row=8, column=0, sticky=W, padx=2, pady=2)
    label_3.grid(row=9, column=0, columnspan=2, sticky=N + S + W + E, padx=2, pady=2)
    text.grid(row=10, column=0, rowspan=6, columnspan=6, sticky=N + S + W + E, padx=5, pady=5)

    label_4 = Label(root, text='扫描结果：', font=('微软雅黑', 10), width=20, height=1, anchor="w")
    label_4.grid(row=16, column=0, columnspan=2, sticky=N + S + W + E, padx=2, pady=2)
    text1 = Text(root, width=50, height=6, bg='#F0FFF0', font=('微软雅黑', 10))
    text1.grid(row=17, column=0, rowspan=6, columnspan=6, sticky=N + S + W + E, padx=5, pady=5)

    root.mainloop()

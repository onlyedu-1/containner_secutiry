# -*- coding: UTF-8 -*-
import sys
import os
import getopt
import tarfile
import pymysql
import re
import json

file_list = []
layer_list = []
json_list = []
pv_dict = {}
relation = []


def untar(file_name):
    tar = tarfile.open(file_name)
    names = tar.getnames()
    (filepath, filename) = os.path.split(file_name)
    (shortname, extension) = os.path.splitext(filename)
    if filepath != '':
        filepath = filepath + '/'
    if os.path.isdir(filepath + shortname):
        pass
    else:
        os.mkdir(filepath + shortname)
        # 由于解压后是许多文件，预先建立同名文件夹
    for name in names:
        try:
            tar.extract(name, filepath + shortname + "/")
        except:
            # print("替身文件夹" + name)
            pass
    tar.close()


def command(argv):
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print('test.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('test.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg


def process(directory):
    for root, dirs, files in os.walk(directory):  # 遍历文件夹
        for file in files:
            file_list.append(root + '/' + file)
        for dir in dirs:
            for name in os.listdir(root + '/' + dir):
                file_list.append(root + '/' + dir + '/' + name)
    for file in file_list:
        (filepath, filename) = os.path.split(file);
        (shortname, extension) = os.path.splitext(filename);
        if filename == 'layer.tar':
            untar(file)
            layer_list.append(filepath)
        if extension == '.json':
            json_list.append(file)


def find_relation():
    for json_file in json_list:
        if "manifest.json" in json_file:
            with open(json_file, 'r') as f:
                data = json.load(f)
                print(data)
                relation = data[0].get('Layers')  # 最先出现的是父，最后出现的是子
                return relation


def cmd_scan(stri):
    try:
        if 'install' in stri:
            package = ''.join(re.findall('install (.*?) ', stri))
            # version ?
            re.sub(',#', '', package)
            version = ''.join(re.findall('=(.*?)', package))
            package.replace(version, '')
            re.sub('=', '', package)
            pv_dict[package] = version
        elif 'dpkg -i' in stri:
            pass
        elif 'rpm -i' in stri:
            pass
    except:
        pass


def parse(directory):
    """
    1。每个layer.tar解压
    2。SHA128(image_ID).json扫描CMD指令中是否存在安装包行为
        (1) install xxx (apt-get insatll xxx / yum install (-y) xxx)
        (2) dpkg -i 软件名.deb
        (3) rpm -i(vh) 软件名.rpm
    3。在每一个layer的json文件中通过扫描parent字段信息获取父layer信息
    4。从最底层的layer开始扫描，建立字典关系，包：版本
        扫描位置：
        (1) debian: /var/lib/dpkg/status (Package-package, Version-version)
        (2) 非debian: /lib/apk/db/installed (P-package, V-version)
        父layer插入字典时如遇同名包，则覆盖子layer的键值信息
    5。得到该镜像最终的包：版本映射字典
    6。供后续与漏洞数据库进行匹配
    """
    process(directory)
    inputfile = directory
    relation = find_relation()
    for json_file in json_list:
        if 'manifest.json' not in json_file:
            with open(json_file, 'r') as f:
                data = json.load(f)
                try:
                    cmd_scan(' '.join(data.get('container_config').get('Cmd')))
                except:
                    pass
    """
    for layer in relation:
        file = layer[:-10] + '/' + 'json'
        with open(file, 'r') as f:
            data = json.load(f)
            cmd_scan(' '.join(data.get('container_config').get('Cmd')))
    """
    # debian
    try:
        for layer in relation:
            path = inputfile + '/' + layer[:-10] + '/layer'
            if os.path.exists(path + '/var/lib/dpkg/status'):
                with open(path + '/var/lib/dpkg/status', 'r') as f:
                    lines = f.readlines()
                stri = ''
                for line in lines:
                    if 'Package: ' in line:
                        stri = line[9:-2]
                    elif 'Version: ' in line:
                        pv_dict[stri] = line[9:-2]
    except:
        pass
    # 非debian
    # arm
    try:
        for layer in relation:
            path = inputfile + '/' + layer[:-10] + '/layer'
            if os.path.exists(path + '/lib/apk/db/installed'):
                with open(path + '/lib/apk/db/installed', 'r') as f:
                    lines = f.readlines()
                stri = ''
                for line in lines:
                    if 'P:' in line:
                        stri = line[9:-2]
                    elif 'V:' in line:
                        pv_dict[stri] = line[9:-2]
    except:
        pass
    # kali apt安装
    try:
        for layer in relation:
            path = inputfile + '/' + layer[:-10] + '/layer'
            file_paths = []
            if os.path.exists(path + '/var/lib/apt/lists'):
                for root, dirs, files in os.walk(path + '/var/lib/apt/lists'):  # 遍历文件夹
                    for file in files:
                        file_paths.append(root + '/' + file)
                for file_path in file_paths:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                    stri = ''
                    for line in lines:
                        if 'Package: ' in line:
                            stri = line[9:-1]
                        elif 'Version: ' in line:
                            pv_dict[stri] = line[9:-1]
        pass
    except:
        pass


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass


def divide(stri):
    i = 0
    times = -1
    major = ''
    minor = ''
    patch = ''
    flag_minor = False
    while i < len(stri):
        while i < len(stri) and stri[i] != '.':
            i += 1
        if i < len(stri) and stri[i] == '.':
            if times == -1:
                major = stri[:i]
                i += 1
                times = i
            else:
                flag_minor = True
                minor = stri[times:i]
                i += 1
                times = i
                break
    if not flag_minor:
        minor = stri[times:]
    else:
        patch = stri[times:]
    return major, minor, patch


def pick_number(stri):
    i = 0
    while i < len(stri):
        if is_number(stri[i]):
            i += 1
        else:
            break
    return int(stri[:i])


def is_bigger(ver, stri, mode):  # mode为0表示ver需大于str1，mode为1表示ver也可以等于str1
    # str1 / ver形如 x.x.x
    (major, minor, patch) = divide(stri)
    (v_major, v_minor, v_patch) = divide(ver)
    try:
        if int(v_major) < int(major):
            return False
        elif int(v_major) == int(major):
            if int(v_minor) < int(minor):
                return False
            elif int(v_minor) == int(minor):
                number = pick_number(patch)
                v_number = pick_number(v_patch)
                if v_number < number:
                    return False
                elif v_number == number and mode == 0:
                    return False
    except:
        pass
    return True


def is_less(ver, stri, mode):
    (major, minor, patch) = divide(stri)
    (v_major, v_minor, v_patch) = divide(ver)
    try:
        if int(v_major) > int(major):
            return False
        elif int(v_major) == int(major):
            if int(v_minor) > int(minor):
                return False
            elif int(v_minor) == int(minor):
                number = pick_number(patch)
                v_number = pick_number(v_patch)
                if v_number > number:
                    return False
                elif v_number == number and mode == 0:
                    return False
    except:
        pass
    return True


def file_write(result, file, count):
    file.write(str(count) + ':\n')
    count += 1
    for name in result.keys():
        if name == 'description':
            file.write(name + ':\n\t' + result.get(name) + '\n')
        elif name == 'id':
            pass
        else:
            file.write(name + ':' + str(result.get(name)) + '\n')
    file.write('\n\n')
    return count


def compare_version(app, ver, file, results, count):
    if len(re.findall(r'\d+\.\d+[\.\d+]*', ver)) > 0:
        ver = re.findall(r'\d+\.\d+[\.\d+]*', ver)[0]
    current_match = []
    flag_write = False
    for result in results:
        flag = False
        li = re.split("[- :/]", result.get('app'))
        for l in li:
            if app == l and l != li[0]:
                flag = True
        if not flag:
            continue
        stri = result.get('version')
        lis = re.findall(r'\d+\.\d+[\.\d+]*', result.get('app'))
        if len(stri) == 0:
            if len(lis) > 0:
                stri = '[' + lis[0] + ',' + lis[0] + ']'
            else:
                if not flag_write:
                    file.write(app + ': ' + ver + '\n')
                    flag_write = True
                current_match.append(result)
                count = file_write(result, file, count)
                continue
        list = []
        list.extend(re.findall(r'\(.*?\)|\(.*?\]|\[.*?\)|\[.*?\]', stri))
        # 处理数据库中version字段的字符串，以及如何判断ver在这个范围内
        flag1 = False
        flag2 = False
        for scope in list:
            str1 = ''.join(re.findall(r'([\w\.\*]*),', scope))
            str2 = ''.join(re.findall(r',([\w\.\*]*)', scope))
            if str1 == '*':
                flag1 = True
            else:
                if scope[0] == '(':
                    if is_bigger(ver, str1, 0):
                        flag1 = True
                    else:
                        continue
                elif scope[0] == '[':
                    if is_bigger(ver, str1, 1):
                        flag1 = True
                    else:
                        continue
            if str2 == '*':
                flag2 = True
            else:
                if scope[-1] == ')':
                    if is_less(ver, str2, 0):
                        flag2 = True
                    else:
                        continue
                elif scope[-1] == ']':
                    if is_less(ver, str2, 1):
                        flag2 = True
                        break
                    else:
                        continue
        if flag1 and flag2:
            # 将匹配结果写入文件
            if not flag_write:
                file.write(app + ': ' + ver + '\n')
                flag_write = True
            current_match.append(result)
            count = file_write(result, file, count)
    return current_match, count


def compare(file):
    mysql_host = 'localhost'
    mysql_db = 'NVD'
    mysql_user = 'root'
    mysql_password = '_NVD2022'
    mysql_port = 3306
    db = pymysql.connect(host=mysql_host, port=mysql_port, user=mysql_user, password=mysql_password, db=mysql_db,
                         charset='utf8')  # 连接数据库编码注意是utf8，不然中文结果输出会乱码
    cursor = db.cursor(cursor=pymysql.cursors.DictCursor)
    count = 1
    for key in pv_dict.keys():
        if len(key) < 2:
            continue
        sql = 'select * from VULNERABILITIES where app like ' + '\'%' + key + '%\''
        sql = sql.encode('utf-8')
        # print(sql)
        cursor.execute(sql)
        # results查询结果的测试，数据处理
        results = cursor.fetchall()
        print(key + pv_dict[key] + ':\n')
        li, count = compare_version(key, pv_dict.get(key), file, results, count)
        for match in li:
            print(match)
        print('\n\n\n')


def extract(inputfile, outputfile='output.txt'):
    if '/' in inputfile:
        savefile = re.split('/', inputfile)[-1]
    else:
        savefile = inputfile
    os.system('docker save -o ' + savefile + '.tar ' + inputfile)
    untar(savefile + '.tar')
    # parse还未解决
    parse(savefile)
    #print(pv_dict)
    for key in pv_dict.keys():
        if "vim" in key:
            print("match: " + key)
    file = open(outputfile, 'w', encoding='utf-8')
    # compare经过测试
    compare(file)
    file.close()


#extract("linuxkonsult/kali-metasploit")

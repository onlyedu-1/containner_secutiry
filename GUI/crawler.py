# -*- coding:utf-8 -*-
import re
import requests
from bs4 import BeautifulSoup
import pymysql  # Python3的mysql模块，Python2 是mysqldb
import datetime
import time
import urllib3

def crawler():
    urllib3.disable_warnings()
    proxy = {'HTTP': '61.135.155.82:443'}  # 代理ip
    url = 'https://nvd.nist.gov/vuln/full-listing/'
    year_end = str(datetime.date.today())[0:4]
    with open('last_time.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        year_start = line[:4]
        month_start = line[5:8]
    month = 12
    new_url = 'https://nvd.nist.gov/vuln/detail/'
    requests.adapters.DEFAULT_RETRIES = 5
    results = []
    left_dict = {'including': '[', 'excluding': '(', 'none': '*', '': '?'}
    right_dict = {'including': ']', 'excluding': ')', 'none': '*'}
    # NVD记录从1988年开始
    mysql_host = 'localhost'
    mysql_db = 'NVD'
    mysql_user = 'root'
    mysql_password = '_NVD2022'
    mysql_port = 3306
    db = pymysql.connect(host=mysql_host, port=mysql_port, user=mysql_user, password=mysql_password, db=mysql_db,
                         charset='utf8')  # 连接数据库编码注意是utf8，不然中文结果输出会乱码
    cursor = db.cursor()
    file = open("faillist_2.txt", 'w', encoding="utf-8")
    """
    sql_create = "CREATE TABLE VULNERABILITIES (id int PRIMARY KEY AUTO_INCREMENT,cve_id VARCHAR(20),description VARCHAR(200),score VARCHAR(10),app VARCHAR(50),version VARCHAR(200))" \
                 "ENGINE=InnoDB DEFAULT CHARSET=utf8"
    # sql_key = "CREATE UNIQUE INDEX id ON VULNERABILITIES(id)"
    cursor.execute("DROP TABLE IF EXISTS VULNERABILITIES")
    cursor.execute(sql_create)  # 执行SQL语句
    """
    fail_list = []
    # cursor.execute(sql_key)
    # db.close()  # 关闭数据库连
    CVE_ID = []
    for y in range(int(year_start), int(year_end + 1)):
        if y == int(year_end):
            month = int(str(datetime.date.today())[5:7])
        else:
            month = 12
        if y != int(year_start):
            month_start = 1
        for m in range(month_start, month + 1):
            sub_url = url + str(y) + '/' + str(m)
            html = requests.get(sub_url, proxies=proxy, verify=False)
            html = html.content.decode('utf-8')
            CVE_ID_ORI = re.findall(r'CVE-\d{4}-\d+', html)
            for ID in CVE_ID_ORI:
                if ID not in CVE_ID:
                    CVE_ID.append(ID)
    for j in range(len(CVE_ID)):
        new_sub_url = new_url + CVE_ID[j]
        html_detail = requests.get(new_sub_url, proxies=proxy, verify=False)
        html_detail = html_detail.content.decode('utf-8')
        outcome_reg = []
        try:
            soup = BeautifulSoup(html_detail, 'html.parser')
            #time.sleep(3)
            outcome_reg.append(CVE_ID[j])
            description = soup.find(attrs={'data-testid': 'vuln-description'})
            outcome_reg.append(description.string)
            score = soup.find("a", class_="label-danger")
            outcome_reg.append(score.string)
            text = re.findall(r'<input type="hidden" id="cveTreeJsonDataHidden"(.*?)>', html_detail)
            txt = ''.join(text)
            txt = txt.replace('&quot;', '')
            flag = True
            stri = 'id:'
            i = 1
            while flag:
                i += 1
                if stri + str(i) not in txt:
                    flag = False
            count = 0
            for index in range(1, i):
                list = []
                combine_i = stri + str(index)
                combine_iplus = stri + str(index + 1)
                combine = combine_i + '(.*?)' + combine_iplus
                if index == (i - 1):
                    combine = combine_i + '(.*?)containers:[]}]}'
                txt_new = re.findall(combine, txt)
                versions = re.findall(r'dataTestId:.*?rangeId', ''.join(txt_new))
                package = re.findall(r'cpe:2\.3:a:(.*?):\*', ''.join(versions))
                if len(package) == 0:
                    count += 1
                    print("没有软件")
                    continue
                outcome_reg.append(package[0])
                for version in versions:
                    left_op = left_dict.get(''.join(re.findall(r'rangeStartType:(.*?),', version)))
                    if left_op == '?':
                        continue
                    if left_op == '*':
                        left_op = '('
                        left = '*'
                    else:
                        left = ''.join(re.findall(r'rangeStartVersion:(.*?),', version))
                    right_op = right_dict.get(''.join(re.findall(r'rangeEndType:(.*?),', version)))
                    if right_op == '*':
                        right_op = ')'
                        right = '*'
                    else:
                        right = ''.join(re.findall(r'rangeEndVersion:(.*?),', version))
                    str2 = left_op + left + ',' + right + right_op
                    list.append(str2)
                str_list = ','.join(list)
                outcome_reg.append(str_list)
                #print(outcome_reg)
                #print("年：" + str(y) + " 月：" + str(m))
                results.append(outcome_reg)
                str0 = "INSERT "
                str1 = "INTO "
                str2 = "VULNERABILITIES(cve_id,description,score,app,version) "
                str3 = "VALUES ("
                sql = str0 + str1 + str2 + str3
                if len(outcome_reg) != 5:
                    j -= 1
                    continue
                for k in range(len(outcome_reg)):
                    sql = sql + "'" + outcome_reg[k] + "',"
                sql = sql[:-1] + ")"
                sql = sql.encode('utf-8')
                print(sql)
                cursor.execute(sql)
                db.commit()
                for k in range(0, 2):
                    if len(outcome_reg) > 0:
                        outcome_reg.pop()
            if count == (i - 1):
                continue
        except:
            time.sleep(3)  # 有时太频繁会报错。
            file.write(CVE_ID[j] + '\n')
            #print(CVE_ID[j] + "失败")
    db.close()

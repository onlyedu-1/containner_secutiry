import pymysql

mysql_host = 'localhost'
mysql_db = 'NVD'
mysql_user = 'root'
mysql_password = '_NVD2022'
mysql_port = 3306
db = pymysql.connect(host=mysql_host, port=mysql_port, user=mysql_user, password=mysql_password, db=mysql_db,
                         charset='utf8')  # 连接数据库编码注意是utf8，不然中文结果输出会乱码
cursor = db.cursor(cursor=pymysql.cursors.DictCursor)
sql = 'select * from VULNERABILITIES where app like ' + '\'%zlib1%\''
sql = sql.encode('utf-8')
print(sql)
cursor.execute(sql)
# results查询结果的测试，数据处理
results = cursor.fetchall()
for result in results:
    print(result)
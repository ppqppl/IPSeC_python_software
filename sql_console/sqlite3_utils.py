import sqlite3

conn = sqlite3.connect('m300.db')
cursor = conn.cursor()
print("数据库链接成功")
conn.commit()
conn.close()
print("数据库关闭成功")

def connect_db():
    global conn, cursor
    conn = sqlite3.connect("../m300.db")
    cursor = conn.cursor()

def close_db():
    global conn, cursor
    conn.commit()
    conn.close()

def create_table(column_list,column_type,table_name):
    # sql = "CREATE TABLE IF NOT EXISTS " + table_name + " ("
    sql = "CREATE TABLE " + table_name + " ("
    length_list = len(column_list)
    length_type = len(column_type)
    for i in range(length_list):
        sql += " " + column_list[i] + " " + column_type[i]
        sql += " , " if length_list > i + 1 else ""
    sql += " )"
    print(sql)
    try:
        cursor.execute(sql)
        print(cursor.rowcount, "record(s) inserted")
        return "Created table " + table_name + " complete"
    except Exception as e:
        conn.rollback()
        return str(e)

def insert_sql(column_list,column_value,table_name):
    sql = "INSERT INTO  " + table_name + " ( "
    length_condition= len(column_list)
    for i in range(length_condition):
        sql += column_list[i]
        sql += " , " if length_condition > i + 1 else ""
    sql += " ) VALUES ("
    for i in range(length_condition):
        sql += " ? "
        sql += "," if length_condition > i + 1 else ""
    sql += ")"
    print(sql)
    try:
        cursor.execute(sql,(column_value))
        return "Insert data complete" if cursor.rowcount > 0 else "Data aready exist"
    except Exception as e:
        conn.rollback()
        return str(e)

def drop_table_from_database(table_name,database_name):
    sql = "DROP TABLE IF EXISTS " + table_name
    print(sql)
    try:
        cursor.execute(sql)
        return "Drop table " + table_name + " from " + database_name + " complete"
    except Exception as e:
        conn.rollback()
        return str(e)

def delete_from_table(column_list,column_value,table_name):
    sql = "DELETE FROM " + table_name + " WHERE "
    length = len(column_list)
    for i in range(length):
        sql += column_list[i] + " = ?"
        sql += " and " if length > i + 1 else ""
    print(sql)
    cursor.execute( sql,(column_value))
    return "Delete complete!" if cursor.rowcount > 0 else "Delete failed!"

def update_value(column_list,column_value,condition_list,condition_value,table_name):
    length_column = len(column_list)
    length_condition = len(condition_list)
    sql = "UPDATE " + table_name + " SET "
    for i in range(length_column):
        sql += column_list[i] + " = ?"
        sql += " , " if length_column > i + 1 else ""
    sql += " WHERE "
    for i in range(length_condition):
        sql += condition_list[i] + " = ?"
        sql += " and " if length_condition > i + 1 else ""
    print(sql)
    sql_value = column_value + condition_value
    print(sql_value)
    try:
        cursor.execute(sql,(sql_value))
        return "Update complete!" if cursor.rowcount > 0 else "Update failed!"
    except Exception as e:
        conn.rollback()
        return str(e)

def select_all_from_database(entries,database_name):
    sql = "SELECT "
    length = len(entries)
    for i in range(length):
        sql += entries[i]
        sql += " , " if length > i + 1 else ""
    sql += " FROM " + database_name
    print(sql)
    cursor.execute(sql)
    # cursor.execute("select * from pkt")
    return cursor.fetchall()

def select_all_from_table(table_name):
    sql = "SELECT * FROM " + table_name
    cursor.execute(sql)
    return cursor.fetchall()

# 按照条件查询，条件格式为 list
def select_from_table(column_list,column_value,table_name):
    sql = "SELECT * FROM " + table_name + " WHERE "
    length_condition= len(column_list)
    for i in range(length_condition):
        sql += column_list[i] + " = ? "
        sql += "and " if length_condition > i + 1 else ""
    print(sql)
    cursor.execute(sql,(column_value))
    return cursor.fetchall()

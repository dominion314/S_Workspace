import mysql.connector
  
mydb = mysql.connector.connect(
    host="mysql.exoduspoint-fis-prod.shieldfis.com",
    user="root",
    password="L9QXPfffPozn",
    database="shieldcoredb"
)
  
# Create a cursor object
mycursor = mydb.cursor()
  
# Execute the query
query1 = "SELECT  (SELECT COUNT(*) FROM   monitor_system_alarm) AS MSA"
mycursor.execute(query1)
# query2 = "SELECT  (SELECT COUNT(*) FROM   monitor_task_history) AS MTH"
# mycursor.execute()

system_alert = mycursor.fetchall()
  
print("You have {} table from monitor_system_alarm".format(system_alert[-1][-1]))
#print("You have {} table from monitor_system_alarm".format(task_history[-1][-1]))


# SELECT  (SELECT COUNT(*) FROM   monitor_system_alarm) AS MSA,(SELECT COUNT(*) FROM monitor_task_history) AS MTH FROM dual

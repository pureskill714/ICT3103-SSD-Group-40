DBSTATUS=1
ERRCODE=1
i=0

while [[ $DBSTATUS -ne 0 ]] && [[ $i -lt 60 ]] && [[ $ERRCODE -ne 0 ]]; do
	i=$i+1
	DBSTATUS=$(/opt/mssql-tools/bin/sqlcmd -h -1 -t 1 -U sa -P ${MSSQL_SA_PASSWORD} -Q "SET NOCOUNT ON; Select SUM(state) from sys.databases")
	ERRCODE=$?
	sleep 1
done

#if [[ $DBSTATUS -ne 0 ]] OR [[ $ERRCODE -ne 0 ]]; then
#	echo "SQL Server took more than 60 seconds to start up or one or more databases are not in an ONLINE state"
#	exit 1
#fi

# Run the setup script to create the DB and the schema in the DB
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d master -i create_db.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i InitializeHotelDatabase2.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i login_user.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i register_customer.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i check_permission.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i create_booking.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i get_customer.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i get_staff.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i register_staff.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i retrieve_password.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i update_user.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d 3203 -i user_details.sql
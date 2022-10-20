/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P PAssw0rd123q -d master -i InitializeHotelDatabase.sql
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P PAssw0rd123q -d master -i login_user.sql
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P PAssw0rd123q -d master -i register_customer.sql

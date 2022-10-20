#!/bin/bash

/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d master -i InitializeHotelDatabase.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d master -i login_user.sql &&
/opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -d master -i register_customer.sql

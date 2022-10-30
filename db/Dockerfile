# syntax=docker/dockerfile:1.4
FROM mcr.microsoft.com/mssql/server:2019-latest
ENV ACCEPT_EULA Y
WORKDIR /db/config
COPY . /db/config

HEALTHCHECK \
  CMD /opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -Q "SELECT 1" -b -o /dev/null

EXPOSE 1433
USER root
RUN chmod +x entrypoint.sh
RUN chmod +x configure-db.sh
ENTRYPOINT ["./entrypoint.sh"]

# syntax=docker/dockerfile:1.4
FROM mcr.microsoft.com/mssql/server:2019-latest

ENV ACCEPT_EULA Y
ENV MSSQL_SA_PASSWORD PAssw0rd123q

WORKDIR /db/config
COPY . /db/config

EXPOSE 1433

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=10 \
  CMD /opt/mssql-tools/bin/sqlcmd -S 127.0.0.1 -U sa -P ${MSSQL_SA_PASSWORD} -Q "SELECT 1" -b -o /dev/null

RUN ["chmod", "+x", "./docker-entrypoint.sh"]

ENTRYPOINT ["./entrypoint.sh"]

FROM mcr.microsoft.com/mssql/server:2019-latest

ENV ACCEPT_EULA Y
ENV MSSQL_SA_PASSWORD PAssw0rd123q

WORKDIR /db/config
COPY . /db/config

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=10 \
    CMD /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P PAssw0rd123q -Q "SELECT 1" || exit 1

ENTRYPOINT ["./entrypoint.sh"]

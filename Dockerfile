# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src/SecureMcp.Server/SecureMcp.Server.csproj src/SecureMcp.Server/
RUN dotnet restore src/SecureMcp.Server/SecureMcp.Server.csproj
COPY src/ src/
RUN dotnet publish src/SecureMcp.Server/SecureMcp.Server.csproj -c Release -o /app --no-restore \
 && chmod -R a+rX,go-w /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
# Writable folder for the demo SQLite database; the app itself runs as the non-root "app" user.
RUN mkdir /data && chown $APP_UID /data
USER $APP_UID
ENV Urls=http://0.0.0.0:8080 \
    ConnectionStrings__Orders="Data Source=/data/orders.db"
EXPOSE 8080
ENTRYPOINT ["dotnet", "SecureMcp.Server.dll"]

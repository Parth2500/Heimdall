# syntax=docker/dockerfile:1
#
# The Heimdall server image. Base images are pinned by digest; Dependabot moves them.
#
#   docker build -t heimdall .                       the server (default target)
#   docker build -t heimdall-migrate --target migrate .   the migration bundle, run once for each release
#
# The server listens on port 8080 over plain HTTP. TLS ends at the proxy in front (Cloudflare, an ingress).
# Outside Development the server refuses to start until a production key store exists (#34).

# ---- Account pages (Angular) ----
FROM docker.io/library/node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS ui
WORKDIR /repo/ui
COPY ui/package.json ui/pnpm-lock.yaml ui/pnpm-workspace.yaml ./
# pnpm at the version that the packageManager field in package.json names.
RUN npm install --global "$(node -p 'require("./package.json").packageManager')"
# U8: no install scripts from dependencies.
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY ui/ ./
# The account project writes to ../src/Heimdall.Api/wwwroot/account.
RUN pnpm exec ng build account

# ---- Server build ----
FROM mcr.microsoft.com/dotnet/sdk:10.0.403@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
WORKDIR /repo
# Restore first, from the project files only, so a code change does not repeat it.
COPY global.json Directory.Build.props Heimdall.slnx dotnet-tools.json ./
COPY src/Heimdall.Domain/Heimdall.Domain.csproj src/Heimdall.Domain/
COPY src/Heimdall.Application/Heimdall.Application.csproj src/Heimdall.Application/
COPY src/Heimdall.Infrastructure/Heimdall.Infrastructure.csproj src/Heimdall.Infrastructure/
COPY src/Heimdall.Api/Heimdall.Api.csproj src/Heimdall.Api/
RUN dotnet restore src/Heimdall.Api/Heimdall.Api.csproj
COPY src/ src/
COPY --from=ui /repo/src/Heimdall.Api/wwwroot/account src/Heimdall.Api/wwwroot/account
RUN dotnet publish src/Heimdall.Api/Heimdall.Api.csproj --configuration Release --no-restore --output /app

# ---- Migration bundle ----
# A self-contained executable that applies the EF Core migrations. Run it with an owner connection string:
#   docker run --rm heimdall-migrate --connection "<owner connection string>"
FROM build AS migrate-build
RUN dotnet tool restore \
 && dotnet dotnet-ef migrations bundle \
      --project src/Heimdall.Infrastructure --startup-project src/Heimdall.Api \
      --configuration Release --self-contained --target-runtime linux-x64 --output /bundle/efbundle

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:a9298ccc39c6258ae71228479e2f3f8d2ceb6639a9927262a4b0ff7d319a0e7e AS migrate
COPY --from=migrate-build /bundle/efbundle /efbundle
ENTRYPOINT ["/efbundle"]

# ---- Server (default target) ----
# Chiseled: no shell and no package manager, and the app runs as a non-root user. "extra" adds ICU, which password
# normalization (NFKC) needs, and time zone data.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra@sha256:a9298ccc39c6258ae71228479e2f3f8d2ceb6639a9927262a4b0ff7d319a0e7e AS server
WORKDIR /app
COPY --from=build /app ./
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
# The image has no shell or curl, so the platform probes the health endpoints: /health/live and /health/ready.
ENTRYPOINT ["dotnet", "Heimdall.Api.dll"]

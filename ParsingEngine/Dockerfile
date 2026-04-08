# 1. Use the .NET 10 SDK image to build the code
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# 2. Copy and restore
COPY ["ParsingEngine.csproj", "./"]
RUN dotnet restore "ParsingEngine.csproj"

# 3. Copy everything else and build it
COPY . .
RUN dotnet publish "ParsingEngine.csproj" -c Release -o /app/publish

# 4. Use the .NET 10 runtime image to run the app
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://0.0.0.0:5000

# 5. Expose the port and start the app
EXPOSE 5000
ENTRYPOINT ["dotnet", "ParsingEngine.dll", "--urls", "http://0.0.0.0:5000"]
# Switch to cross-platform .NET runtime
FROM mcr.microsoft.com/dotnet/runtime:6.0
#FROM mcr.microsoft.com/dotnet/framework/runtime:4.8-windowsservercore-ltsc2019

# Set the working directory
WORKDIR /app

# Copy your application files
COPY ./PacketsSniffer/bin/Debug/ /app

EXPOSE 5005
# Define the entry point
ENTRYPOINT ["dotnet", "PacketsSniffer.exe"]


#####################


#FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
#WORKDIR /src

# Copy only the project file first to take advantage of Docker layer caching
#COPY ["./Anti.csproj", "./Anti.csproj"]
#RUN dotnet restore "./Anti.csproj"

# Copy everything else
#COPY . .

# Clean any old builds that might cause the framework conflicts
#RUN rm -rf */obj/ */bin/
#RUN rm -rf obj/ bin/

# Build the application
#RUN dotnet build "Anti.csproj" -c Release -o /app/build

#FROM build AS publish
#RUN dotnet publish "Anti.csproj" -c Release -o /app/publish 

#FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
#WORKDIR /app
#COPY --from=publish /app/publish .
#ENTRYPOINT ["dotnet", "Anti.dll"]

FROM mysql:latest

ENV MYSQL_ROOT_PASSWORD=root

COPY ./DB.sql  ./docker-entrypoint-initdb.d/

EXPOSE 80

CMD ["mysqld"]

FROM mysql:5.7

RUN usermod -u 1000 mysql

COPY ./etc/my.cnf /etc/mysql/
#ENTRYPOINT ["/docker-entrypoint.sh"]
FROM php:7.4-fpm

RUN docker-php-ext-install \ 
  bcmath \
  gd \
  opcache \
  pdo_mysql \
  mysqli

ENV PHP_MEMORY_LIMIT 2G
ENV PHP_PORT 9000
ENV PHP_PM dynamic
ENV PHP_PM_MAX_CHILDREN 20
ENV PHP_PM_START_SERVERS 8
ENV PHP_PM_MIN_SPARE_SERVERS 4
ENV PHP_PM_MAX_SPARE_SERVERS 12
ENV APP_MAGE_MODE default

COPY conf/www.conf /usr/local/etc/php-fpm.d/
COPY conf/php.ini /usr/local/etc/php/
COPY conf/php-fpm.conf /usr/local/etc/

RUN usermod -u 1000 www-data
WORKDIR /usr/local/var/www
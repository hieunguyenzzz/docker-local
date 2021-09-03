FROM php:7.2-fpm

RUN docker-php-ext-install \  
  opcache \
  pdo_mysql \
  mysqli


RUN usermod -u 1000 www-data
WORKDIR /usr/local/var/www
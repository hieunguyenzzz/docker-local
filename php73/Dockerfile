FROM php:7.3-fpm
MAINTAINER Mark Shust <mark.shust@mageinferno.com>

RUN apt-get update && apt-get install -y \
  cron \
  libfreetype6-dev \
  libicu-dev \
  libjpeg62-turbo-dev \
  libmcrypt-dev \
  libxslt1-dev \
  zip


RUN curl -sS https://raw.githubusercontent.com/composer/getcomposer.org/master/web/installer | \
  php -- --install-dir=/usr/local/bin --filename=composer

RUN apt-get update
RUN apt-get install -y vim
RUN apt-get install -y git
RUN apt-get install -y zsh
RUN apt-get install -y wget
RUN apt-get install -y libzip-dev
RUN git config --global --add oh-my-zsh.hide-status 1
RUN curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh | bash -s
#RUN pecl install xdebug

RUN docker-php-ext-install \
  bcmath \
  gd \
  intl \
  mbstring \
  opcache \
  pdo_mysql \
  soap \
  xsl \
  zip \
  pcntl \
  sockets \
  mysqli

RUN docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ --with-png-dir=/usr/include/
RUN docker-php-ext-install -j$(nproc) gd

ENV PHP_MEMORY_LIMIT 6G
ENV PHP_PORT 9000
ENV PHP_PM dynamic
ENV PHP_PM_MAX_CHILDREN 10
ENV PHP_PM_START_SERVERS 4
ENV PHP_PM_MIN_SPARE_SERVERS 2
ENV PHP_PM_MAX_SPARE_SERVERS 6
ENV APP_MAGE_MODE default

RUN usermod -u 1000 www-data

COPY conf/www.conf /usr/local/etc/php-fpm.d/
COPY conf/php.ini /usr/local/etc/php/
COPY conf/php-fpm.conf /usr/local/etc/
COPY bin/* /usr/local/bin/
COPY conf/no-debug-non-zts-20180731/xdebug.so /usr/local/lib/php/extensions/no-debug-non-zts-20180731/


WORKDIR /usr/local/var/www
RUN mkdir -p /var/www/.composer
RUN chown -R www-data:www-data /var/www

CMD ["/usr/local/bin/start"]

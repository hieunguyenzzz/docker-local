FROM nginx:1.15.5

RUN mkdir /etc/nginx/servers
RUN mkdir /etc/nginx/includes
RUN mkdir /etc/nginx/ssl

ADD ./servers/ /etc/nginx/servers/
ADD ./includes/ /etc/nginx/includes/
ADD ./ssl/ /etc/nginx/ssl/

COPY ./nginx.conf /etc/nginx/nginx.conf
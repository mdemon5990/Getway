FROM php:8.3-apache
RUN apt-get update && apt-get install -y --no-install-recommends libcurl4-openssl-dev libonig-dev \
    && docker-php-ext-install curl mbstring \
    && a2enmod headers rewrite \
    && sed -ri 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf \
    && sed -ri 's/Listen 80/Listen 10000/' /etc/apache2/ports.conf \
    && sed -ri 's/<VirtualHost \*:80>/<VirtualHost *:10000>/' /etc/apache2/sites-available/000-default.conf \
    && sed -ri 's@CustomLog .+ combined@CustomLog /dev/null combined@' /etc/apache2/sites-available/000-default.conf \
    && printf '\nmax_execution_time=90\nmax_input_time=60\ndefault_socket_timeout=75\nexpose_php=Off\n' > /usr/local/etc/php/conf.d/payment-bridge.ini \
    && rm -rf /var/lib/apt/lists/*
COPY index.php /var/www/html/index.php
COPY .htaccess /var/www/html/.htaccess
RUN chown -R www-data:www-data /var/www/html
EXPOSE 10000
CMD ["apache2-foreground"]

# PHP 5.3.15 as mod_php on CentOS 6.10 / Apache 2.2, mirroring the reference host.
FROM --platform=linux/amd64 centos:6
RUN sed -i -e 's|^mirrorlist=|#mirrorlist=|' \
      -e 's|^#baseurl=http://mirror.centos.org/centos/$releasever|baseurl=http://vault.centos.org/6.10|' \
      /etc/yum.repos.d/CentOS-Base.repo \
 && yum -y install gcc make httpd httpd-devel libxml2-devel tar bzip2 gdb \
 && yum clean all
COPY php-5.3.15.tar.bz2 /usr/src/
RUN cd /usr/src && tar xjf php-5.3.15.tar.bz2 && cd php-5.3.15 \
 && ./configure --with-apxs2=/usr/sbin/apxs --disable-all --enable-session --enable-debug=no \
 && make -j8 && make install \
 && printf 'AddType application/x-httpd-php .php\nDirectoryIndex index.php\n' > /etc/httpd/conf.d/php.conf \
 && sed -i 's/^ServerName.*//; $a ServerName lab' /etc/httpd/conf/httpd.conf
RUN printf '<?php echo "ok ", PHP_VERSION, "\\n";' > /var/www/html/index.php
EXPOSE 80
CMD ["/usr/sbin/httpd", "-DFOREGROUND"]

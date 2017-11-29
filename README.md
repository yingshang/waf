# installtion
dockerfile install
```
from centos:6.8
RUN yum install  -y readline-devel pcre-devel openssl-devel gcc wget lua-devel git gcc gcc-c++  make gmake vim unzip
RUN cd /opt && wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.41.tar.gz && tar zxvf pcre-8.41.tar.gz 
#https://www.kyne.com.au/~mark/software/lua-cjson-manual.html#_installation 
#cjson安装手册
RUN cd /opt && wget https://www.kyne.com.au/~mark/software/download/lua-cjson-2.1.0.tar.gz && tar zxvf lua-cjson-2.1.0.tar.gz && cd lua-cjson-2.1.0 && sed -i 's/\/usr\/local/\/usr\/share\/lua\/5.1/g' Makefile
RUN cd /opt && wget https://openresty.org/download/openresty-1.11.2.5.tar.gz &&  tar zxvf openresty-1.11.2.5.tar.gz &&  cd openresty-1.11.2.5 && ./configure    --prefix=/opt/server/  --with-pcre=/opt/pcre-8.41  --with-pcre-jit && make && make install 
RUN mkdir /data/ && mkdir /data/waf && chmod 777 /data/waf
RUN ln -s /opt/server/nginx/sbin/nginx /usr/local/sbin/nginx
RUN cd /opt/ && wget http://luarocks.github.io/luarocks/releases/luarocks-2.4.3.tar.gz && tar zxvf luarocks-2.4.3.tar.gz && cd luarocks-2.4.3 && ./configure && make build && make install 
RUN luarocks install luafilesystem
```
# nginx.conf
```
worker_processes  1;
events {
	worker_connections  1024;
}

http {
	include       mime.types;
	default_type  application/octet-stream;
	sendfile        on;
	#生产环境设置为on
	lua_code_cache off;
	lua_package_path "/opt/waf/waf/?.lua;;"; 
	lua_shared_dict rules_dict 20m;
	lua_shared_dict white_dict 20m;
	lua_shared_dict black_dict 20m;
	lua_shared_dict config_dict 20m;
	init_by_lua_file  /opt/waf/waf/init.lua;
	server {
		listen       80;
		server_name  localhost;
#error_log /tmp/error.log debug;
		access_by_lua_file /opt/waf/waf/waf.lua;
		log_by_lua_file /opt/waf/waf/log.lua;
		location / {
			proxy_pass   http://192.168.8.89:8888;
		}
	}
}
```
# 实战视频
https://youtu.be/qTkg0qmqMok

# WAF架构图
后续会添加文件上传过滤，防DD，以及一些服务器的漏洞的虚拟补丁。
![](https://github.com/yingshang/waf/blob/master/static/waf%E8%AE%BE%E8%AE%A1%E5%9B%BE.jpg)
# 火焰图
![](https://github.com/yingshang/waf/blob/master/static/flame.svg)
# 性能测试
看99那个，前面的数值应该是环境不稳定造成的。
![](https://github.com/yingshang/waf/blob/master/static/waf.png)

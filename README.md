##nginx_lua_waf

nginx waf是基于[ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)原版的基础上进行修改和二次开发。

原版地址：[https://github.com/loveshell/ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)

由于原版现在已停止更新维护，鉴于现在网络漏洞攻击的手法日新月异，原有规则未能够有效防护部分payload，故而有了这个基于原版的修改和二次开发。

代码很简单，在原版的基础上增加了一些防护规则和添加了对提交json数据包的防护。


###用途：
    	
	防止sql注入，本地包含，部分溢出，fuzzing测试，xss,RCE攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传

###推荐安装:

推荐使用lujit2.1做lua支持

ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。


###使用说明：

nginx安装路径假设为:/usr/local/nginx/conf/

把ngx_lua_waf下载到conf目录下,解压命名为waf

在nginx.conf的http段添加

    lua_package_path "/usr/local/nginx/conf/?.lua";
    lua_shared_dict limit 10m;
    init_by_lua_file  /usr/local/nginx/conf/init.lua;
    access_by_lua_file /usr/local/nginx/conf/waf.lua;

配置config.lua里的waf规则目录(一般在waf/conf/目录下)

        RulePath = "/usr/local/nginx/conf/waf/"

绝对路径如有变动，需对应修改

然后重启nginx即可


###配置文件详细说明：

    	RulePath = "/usr/local/nginx/conf/waf/"
        --规则存放目录
        attacklog = "off"
        --是否开启攻击信息记录，需要配置logdir
        logdir = "/usr/local/nginx/logs/hack/"
        --log存储目录，该目录需要用户自己新建，切需要nginx用户的可写权限
        UrlDeny="on"
        --是否拦截url访问
        Redirect="on"
        --是否拦截后重定向
        CookieMatch = "on"
        --是否拦截cookie攻击
        postMatch = "on" 
        --是否拦截post攻击
        whiteModule = "on" 
        --是否开启URL白名单
        black_fileExt={"php","jsp"}
        --填写不允许上传文件后缀类型
        ipWhitelist={"127.0.0.1"}
        --ip白名单，多个ip用逗号分隔
        ipBlocklist={"1.0.0.1"}
        --ip黑名单，多个ip用逗号分隔
        CCDeny="on"
        --是否开启拦截cc攻击(需要nginx.conf的http段增加lua_shared_dict limit 10m;)
        CCrate = "100/60"
        --设置cc攻击频率，单位为秒.
        --默认1分钟同一个IP只能请求同一个地址100次
        html=[[Please go away~~]]
        --警告内容,可在中括号内自定义
        备注:不要乱动双引号，区分大小写
        
###检查规则是否生效

部署完毕可以尝试如下命令：        
  
        curl http://xxxx/test.php?id=../etc/passwd
        返回"403 Forbidden"字样，说明规则生效。

注意:默认，本机在白名单不过滤，可自行调整config.lua配置

###一些说明：

	过滤规则在wafconf下，可根据需求自行调整，每条规则需换行,或者用|分割
	
		args里面的规则get参数进行过滤的
		url是只在get请求url过滤的规则		
		post是只在post请求过滤的规则		
		whitelist是白名单，里面的url匹配到不做过滤		
		user-agent是对user-agent的过滤规则
	

	默认开启了get和post过滤，需要开启cookie过滤的，编辑waf.lua取消部分--注释即可
	
	日志文件名称格式如下:虚拟主机名_sec.log

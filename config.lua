RulePath = "/usr/local/nginx/conf/wafconf/"
attacklog = "on"
logdir = "/usr/local/nginx/logs/hack/"
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on" 
whiteModule="on" 
black_fileExt={"php","jsp","jspx","phpx","php4","php5","php3","shtml","asp","aspx","asmx","ashx","cdx","cer","war"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1"}
CCDeny="off"
CCrate="300/60"
html=[[
403 Forbidden
]]

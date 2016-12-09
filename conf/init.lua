require 'config'
local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
UrlDeny = optionIsOn(urlMatch)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteurlMatch)
PathInfoFix = optionIsOn(PathInfoFix)
CCDeny = optionIsOn(denycc)
whiteipcheck = optionIsOn(whiteipMatch)
blockipcheck = optionIsOn(blackipMatch)
OnlyCheck = optionIsOn(OnlyCheck) 

function getClientIp()
	IP = ngx.var.remote_addr
	if string.sub(IP,1,7) == "192.168" or string.sub(IP,1,3) == "10." then
		IPx = ngx.req.get_headers()["X-Forwarded-For"]
		if IPx ~= nil then
			if string.match(IPx,'%s') and string.len(IPx)>17 then
				IP=string.match(string.sub(IPx, -17, -1),'%s(%d+.%d+.%d+.%d+)')
			else
				IP=IPx
			end
		end
	end 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
	local clientip=ngx.var.remote_addr
	local xforwardedfor=ngx.req.get_headers()["X-Forwarded-For"]
	if xforwardedfor == nil then
		xforwardedfor = "-"
	end
        local ua = ngx.var.http_user_agent
        if ua == nil then
		ua = "-"
	end
	local servername=ngx.var.host
        local time=ngx.localtime()
        local line = clientip..xforwardedfor.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        local filename = logdir..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(RulePath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')
whiteiprules=read_rule('whiteip')
blockiprules=read_rule('blockip')
denyccrules=read_rule('denycc')


function say_html()
    if OnlyCheck  then
    else
    	ngx.header.content_type = "text/html"
    	ngx.status = ngx.HTTP_FORBIDDEN
    	ngx.say(html)
    	ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
	        log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                if val ~= false then
                    data=table.concat(val, " ")
                end
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end
function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end


function gettoken(data)
    if string.match(data,'+.*+') then
	local str1 = myeval(string.match(data,'(.*)+.*+.*'))
	local str2 = myeval(string.match(data,'.*+(.*)+.*'))
	local str3 = myeval(string.match(data,'.*+.*+(.*)'))
	if str1 ~= nil and str2 ~= nil and str3 ~= nil then
		return str1..str2..str3
	else
		return nil
	end
    elseif string.match(data,'+') then
	local str1 = myeval(string.match(data,'(.*)+'))
	local str2 = myeval(string.match(data,'+(.*)'))
	if str1 ~= nil and str2 ~= nil then
		return str1..str2
	else
		return nil
	end
    else
	return myeval(data)
    end	
end

function myeval(data)
    if data == nil then
	return nil
    end
    local param=""
    if data == "ip" then
	return getClientIp()
    elseif data == "domain" then
	return ngx.var.host
    elseif ngxmatch(data,"^uri","isjo") then
	param = string.match(data,'uri:(.*)')
	if data == "uri" then
		return ngx.var.uri
	elseif ngxmatch(ngx.var.uri,param,"isjo") then
		return param
	else
		return nil
	end
    elseif ngxmatch(data,"^header:","isjo") then
	param = string.match(data,'header:(.*)')
	local str = ngx.req.get_headers()[param]
	if str ~= nil then
		return str
	else
		return nil
	end
    elseif ngxmatch(data,"^GetParam:","isjo") then
	param = string.match(data,'GetParam:(.*)')
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
		if key == param then
			return val
 		end
	end
	return nil
    elseif ngxmatch(data,"^PostParam:","isjo") then
        param = string.match(data,':(.*)')
        local args = ngx.req.get_post_args()
	for key, val in pairs(args) do
                if key == param then
                        return val
                end
        end
	return nil
    elseif ngxmatch(data,"^CookieParam:","isjo") then
	param = string.match(data,':(.*)')
	local cookie = ngx.var.http_cookie
	if param ~=nil and cookie ~= nil then
		local ck = string.match(cookie,param..'=([%w_]+)')
		return ck
	end
    else
	return nil
    end
end

function denycc()
    if CCDeny then
    for _,rule in pairs(denyccrules) do
        if rule ~="" and string.sub(rule,1,1) ~= "#" then
	    local clientip=getClientIp()
            local data = string.match(rule,'(.*)%s+%d+/%d+%s+%d+')
	    local CCrate = string.match(rule,'.*%s+(%d+/%d+)%s+%d+')
	    local bantime = tonumber(string.match(rule,'.*%s+.*%s+(%d+)'))
	    if data ~= nil and CCrate ~=nil and bantime ~=nil then
		local token=gettoken(data)
		if token ~=nil then
			local CCcount=tonumber(string.match(CCrate,'(.*)/'))
        		local CCseconds=tonumber(string.match(CCrate,'/(.*)'))
			local limit = ngx.shared.limit
			local blockiplimit = ngx.shared.blockiplimit
			local blockipreq,_=blockiplimit:get(clientip..data)
        		if 	blockipreq then		
				say_html()  
				return true 
			end
			
			local req,_=limit:get(token)
			if req then
				if req > CCcount then
					log('denycc',token,"-",rule)
					blockiplimit:set(clientip..data,1,bantime) 
					say_html()
					return true
				else
					limit:incr(token,1)
				end
			else
				limit:set(token,1,CCseconds)
			end
		end
            end          
        end
    end
    return false
    end
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if whiteipcheck then
    	local clientip=getClientIp()
    	for _,rule in pairs(whiteiprules) do
        	if rule ~="" and ngxmatch(clientip,rule,"isjo") then
            		return true
        	end
    	end
    	return false
    end
end


function blockip()
    if blockipcheck then
    	local clientip=getClientIp()
    	for _,rule in pairs(blockiprules) do
        	if rule ~="" and ngxmatch(clientip,rule,"isjo") then
	    		log('blockip',clientip,"-",rule)
            		say_html()
            		return true
        	end
    	end
    	return false
    end
end

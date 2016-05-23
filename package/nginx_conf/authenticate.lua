-- Authentication for proxy pass.

local found = "false"
local ngx_vars = ngx.var
local ipaddr = ngx_vars.REMOTE_ADDR
local auth_dic = ngx.shared.authenticated
local auth_id = ""

if ngx_vars.arg_id then
	auth_id = ngx_vars.arg_id
else
	if ngx_vars.HTTP_REFERER then
		auth_id = string.match(ngx_vars.HTTP_REFERER, "id=(%w+)")
	end	
end
local status = auth_dic:get(auth_id)
if status and string.match(status, ipaddr) then
	found = "true"
end
if found == "false" then
	ngx.status = ngx.HTTP_FORBIDDEN
	ngx.exit(ngx.HTTP_FORBIDDEN)
else
	ngx.status = ngx.HTTP_OK
end

local http = require("resty.http")
local cjson = require("cjson")
local httpc = nil
local cert = nil
local key = nil
local ssl = require "ngx.ssl"

local _M = {}

    function _M.http_fail(validation, host)
        _M.tcp_fail(validation, host)

        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access Denied (403) - mTLS Perimeter authentication and/or auhtorization failed!")
        ngx.say("Aspects to consider:")
        
        if validation == nil or validation["outcome"] == nil then
            ngx.say(" - Client certificate authentication failed,")
       		ngx.say(" - No client certificate detected,")
        	ngx.say(" - Client certificate expired,")
        	ngx.say(" - Client certificate authority not trusted,")
		elseif string.find(validation["outcome"], "OK 0001", 0, true) then
        	local srv_roles = "[]";
            if validation["service-roles"] ~= nil then srv_roles = table.concat(validation["service-roles"], ",") end 
                ngx.say(" - mTLS ID detected: 0x"..ngx.var.ssl_client_serial)
                ngx.say(" - mTLS ID subject: "..ngx.var.ssl_client_s_dn)
                ngx.say(" - Roles with this service: "..srv_roles)
            else
 	        ngx.say("Please check the logs for additional informtion")
        end
        
        return 403
    end

    function _M.tcp_fail(validation, host)
        if validation == nil or validation["outcome"] == nil then
            ngx.log(0, 'Access denied on '..host..': No client certificate presented');
        elseif string.find(validation["outcome"], "OK 0001", 0, true) then
        	local srv_roles = "[]";
			if validation["service-roles"] ~= nil then srv_roles = table.concat(validation["service-roles"], ",") end 
            ngx.log(0, 'Access denied for mTLS ID '..ngx.var.ssl_client_serial..', on '..host..': None of the following roles are allowed '..srv_roles);
        else
            ngx.log(0, 'Access denied for mTLS ID '..ngx.var.ssl_client_serial..', on '..host..': '..validation["outcome"]);
        end

        return 1
    end

    -- Populate the client certificate serial number headers
    function _M.populate_mtls_id_header(header)
        local serial = ngx.var.ssl_client_serial
        
        if serial == nil then
        	return
		end 
		
        -- ngx.log(0, 'Setting header '..serial);
        if header == nil or header == "" then
            header = "X-mTLS-ID"
        end

        if serial ~= nil then
            ngx.req.set_header(header, '0x'..serial)
            ngx.req.set_header("X-TLS-Client-Serial", '0x'..serial)
        end
    end


    function _M.populate_mtls_headers(validation, agent_h, org_id_h, org_name_h, org_email_h, roles_h, local_id_h)

        if agent_h == nil or agent_h == "" then agent_h = 'X-mTLS-Agent' end
        if org_id_h == nil or org_id_h == "" then org_id_h = 'X-mTLS-Org-ID' end
        if org_name_h == nil or org_name_h == "" then org_id_h = 'X-mTLS-Org-Name' end
        if org_email_h == nil or org_email_h == "" then org_id_h = 'X-mTLS-Org-Email' end
        if roles_h == nil or roles_h == "" then roles_h = 'X-mTLS-Roles' end
        if local_id_h == nil or local_id_h == "" then local_id_h = 'X-mTLS-Local-ID' end

        if validation == nil then
        		return
		end 

        if validation["local-id"] ~= nil then ngx.req.set_header(agent_h, validation["local-id"]) end
        if validation["organizational-reference"] ~= nil then ngx.req.set_header(org_id_h, validation["organizational-reference"]) end 
        if validation["organizational-name"] ~= nil then ngx.req.set_header(org_name_h, validation["organizational-name"]) end 
        if validation["organizational-email"] ~= nil then ngx.req.set_header(org_email_h, validation["organizational-email"]) end 
        if validation["service-roles"] ~= nil then ngx.req.set_header(roles_h, table.concat(validation["service-roles"], ",")) end 
        
        ngx.req.set_header(agent_h, ngx.var.ssl_client_s_dn)
        
    end

    -- chek if an mTLS ID owner has any of a given list of roles
    function _M.ok(validation) 
        
        if validation == nil or validation["outcome"] == nil or not string.find(validation["outcome"], "OK 0001", 0, true) then
            return false
        else
            return true
        end

    end

    -- chek if an mTLS ID owner has any of a given list of roles
    function _M.is_any_of(validation, roles) 
        if validation == nil then
            return false
	    end 
		
        if validation["outcome"] and string.find(validation["outcome"], "OK 0001", 0, true) then
            if validation ~= nil and validation["service-roles"] ~= nil then
                for _, role in pairs(roles) do
                    for _, assigned_role in pairs(validation["service-roles"]) do
                    		-- ngx.log(0, assigned_role..' == '..role..' - '..tostring(string.lower(assigned_role) == string.lower(role)));
                        if string.lower(assigned_role) == string.lower(role) then
                            -- nothing to do, audit log maybe
                            return true
                        end
                    end
                end
            end
        end        

        return false
    end

    -- chek if an mTLS ID owner has any sort of roles in the service
    function _M.has_roles(validation) 
        if validation == nil then
            return false
	    end 
		
        if validation["outcome"] and string.find(validation["outcome"], "OK 0001", 0, true) then
            if validation ~= nil and #validation["service-roles"] > 0 then
                return true
            end
        end        

        return false
    end


    function _M.validate_mtls_id(service)
        local serial = ngx.var.ssl_client_serial

	   -- ngx.log(0, "Vaidating: "..service.." / ", serial)

        if serial == nil then
            return nil
        end

        -- we cache the response for 5s so that request in the same http page load
        -- don't trigger cascading http local calls
        local cache = ngx.shared.http_validation_cache
        if cache == nil then
            cache =  ngx.shared.tcp_validation_cache
        end

        local validation = cache:get(service..'/0x'..serial)

        if validation == nil then
            local result = _M.make_http_request(81, '/mtls-gw/validate/'..service..'/0x'..serial, 'GET', '')

            validation = cjson.decode(result)

            -- if the response is a profile, we go one level down into the response
            if validation["Identity-Profile"] then
                validation = validation["Identity-Profile"];
            else
                validation = validation["Simple-Response"];
            end
        end

        -- cache the validation directly so as to skip json processing too
        cache:set(service..'/0x'..serial, result, 15)

        return validation
    end


    -- this uses Identity Plus mTLS Gateway Manager to forward the TCP request to Identity Plus.
    -- as such, it is the Gateway Manager who handles the service agent certificate, we do not care about it in this code 
    function _M.make_http_request(port, path, method, body)
        local sock = ngx.socket.tcp()

        -- Set timeout (in milliseconds)
        sock:settimeout(5000)

        -- Connect to the host and port
        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.log(0, "Failed to connect to Validation Service, make sure it is running on 127.0.0.1:"..port.." : ", err)
        end

        _M.send_http_request(sock, "127.0.0.1:"..port, path, method, body)
    
        local body = _M.receive_http_response(sock)

        return body
    end

    -- utility function to make an http request over a tcp socket connection
    function _M.send_http_request(sock, host, path, method, body)
        -- Prepare the HTTP request
        local request = string.format("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", method, path, host, #body, body)

        -- ngx.log(0, "\n-------------- request -----------------\n")
        -- ngx.log(0, "", request)
        -- ngx.log(0, "\n-------------------------------\n")

        -- Send the HTTP request
        local bytes, err = sock:send(request)
        if not bytes then
            ngx.log(0, "failed to send request: ", err)
            return nil, err
        end
    end

    -- utility function to receive a tcp resonse, 
    -- parse it into an http response and return the body
    function _M.receive_http_response(sock)
        -- Receive the HTTP response
        local response_lines = {}
        local content_length = 0
        while true do
            local line, err = sock:receive("*l")
            if not line then
                ngx.log(ngx.ERR, "failed to receive response: ", err)
                return nil, err
            end
            if line == "" then
                break
            end
            table.insert(response_lines, line)
            
            -- Check for Content-Length header
            local key, value = line:match("^(%S+):%s*(%S+)$")
            if key and key:lower() == "content-length" then
                content_length = tonumber(value)
            end
        end

        -- Read the response body exactly as per the Content-Length header
        local response_body = ""
        if content_length > 0 then
            response_body, err = sock:receive(content_length)
            if not response_body then
                ngx.log(ngx.ERR, "failed to receive response body: ", err)
                return nil, err
            end
        end

        -- Close the connection
        -- sock:close()
        sock:setkeepalive(600000)

        -- Concatenate the response headers and body into a single response string
        local response = table.concat(response_lines, "\n") .. "\r\n\r\n" .. response_body

        -- ngx.log(0, "\n-------------- response -----------------\n")
        -- ngx.log(0, "", response)
        -- ngx.log(0, "\n-------------------------------\n")

        -- Parse the response
        local body_start = response:find("\r\n\r\n", 1, true)
        if not body_start then
            ngx.log(0, "invalid HTTP response")
            return nil, "invalid HTTP response"
        end

        local body = response:sub(body_start + 4)
        -- ngx.log(0, "response body: ", body)

        return body
    end


    -- utility function to log pretty-printed map object
    function _M.print_table(t, indent)
        indent = indent or ""
        for k, v in pairs(t) do
            if type(v) == "table" then
                ngx.log(0, indent .. k .. ": ")
                _M.print_table(v, indent .. "  ")
            else
                ngx.log(0, indent .. k .. ": ", v)
            end
        end
    end
    
    -- utility function to send html formatted map object
    function _M.say_table(t)
        indent = indent or ""
        for k, v in pairs(t) do
            if type(v) == "table" then
                ngx.say("<p>" .. k .. ":</p><ul>")
                _M.say_table(v)
                ngx.say("</ul>")
            elseif type(v) == "number" then
                ngx.say("<li>" .. k .. ": "..("%.0f"):format(v).."</li>")
            else
                ngx.say("<li>" .. k .. ": "..v.."</li>")
            end
        end
    end

    -- utility function to send pain-text formatted map object
    function _M.say_table_plain(t, indent)
        indent = indent or ""
        for k, v in pairs(t) do
            if type(v) == "table" then
                ngx.say(indent .. k .. ": ")
                _M.say_table_plain(v, indent .. "  ")
            else
                ngx.say(indent .. k .. ": ", v)
            end
        end
    end

return _M

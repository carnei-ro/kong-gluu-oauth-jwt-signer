local BasePlugin = require "kong.plugins.base_plugin"

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local json                 = require("cjson").new()
json.decode_array_with_array_mt(true)
local http                 = require("resty.http")

local openssl_digest       = require "resty.openssl.digest"
local openssl_pkey         = require "resty.openssl.pkey"
local pl                   = require('pl.pretty')
local ngx_log              = ngx.log
local ngx_ERR              = ngx.ERR
local encode_base64        = require("ngx.base64").encode_base64url
local ngx_b64              = require("ngx.base64")
local table_concat         = table.concat

local read_file            = require("pl.file").read
local os_getenv            = os.getenv

local function load_private_keys()
  local content = os_getenv("KONG_GLUU_OAUTH_JWT_SIGNER_PRIVATE_KEYS")
  if content == nil or err then
      ngx_log(ngx_ERR, "Could not read KONG_GLUU_OAUTH_JWT_SIGNER_PRIVATE_KEYS env var.")
      return nil, tostring(err)
  end

  local pkeys = json.decode(content)
  if not pkeys then
    ngx_log(ngx_ERR, "Could not get 'keys' object from KONG_GLUU_OAUTH_JWT_SIGNER_PRIVATE_KEYS env var" )
    return nil, "Could not get 'keys' object from KONG_GLUU_OAUTH_JWT_SIGNER_PRIVATE_KEYS env var"
  end

  local private_keys={}
  for k,v in pairs(pkeys) do
    private_keys[k]=ngx_b64.decode_base64url(v)
  end

  return private_keys
end

local env_client_id = os_getenv("KONG_GLUU_OAUTH_JWT_SIGNER_CLIENT_ID")
local env_client_secret = os_getenv("KONG_GLUU_OAUTH_JWT_SIGNER_CLIENT_SECRET")

local private_keys, err_pk = load_private_keys()
if err_pk then
  ngx_log(ngx_ERR,   ">>>>>>>>>>> BE CAREFUL: PRIVATE KEYS NOT LOADED CORRECTLY. THIS MAY CAUSE SOME UNEXPECTED 500 RETURNS. <<<<<<<<<<<")
end

local plugin = BasePlugin:extend()

function plugin:new()
    plugin.super.new(self, plugin_name)
end

function plugin:access(conf)
    plugin.super.access(self)

    local uri_args             = ngx.req.get_uri_args()

    local uri                  = uri_args['uri'] or ""
    local scheme               = ngx.var.scheme

    local jwt_validity         = conf['jwt_validity']
    local cookie_name          = conf['cookie_name']
    local cookie_domain        = conf['cookie_domain']
    local secure_cookies       = conf['secure_cookies']
    local same_site            = conf['same_site']
    local http_only_cookies    = conf['http_only_cookies']
    local issuer               = conf['issuer'] or plugin_name
    local cb_uri               = conf['callback_uri'] or "/_oauth"
    local private_key_id       = conf['private_key_id']
    local ssl_verify           = conf['ssl_verify']
    local cb_scheme            = conf['callback_scheme'] or scheme
    local cb_server_name       = ngx.req.get_headers()["Host"]
    local cb_url               = cb_scheme .. "://" .. cb_server_name .. cb_uri
    local redirect_url         = cb_scheme .. "://" .. cb_server_name .. ngx.var.request_uri
    local initial_redirect_url = cb_url .. "?uri=" .. uri
    local scope                = table_concat(conf['scopes'], " ")
    local authorize_url        = conf['gluu_url'] .. '/oxauth/restv1/authorize'
    local access_token_url     = conf['gluu_url'] .. '/oxauth/restv1/token'
    local userinfo_url         = conf['gluu_url'] .. '/oxauth/restv1/userinfo'
    local gluu_host            = conf['gluu_host']
    if gluu_host then
        authorize_url = 'https://' .. gluu_host .. '/oxauth/restv1/authorize'
    end

    local key, client_id, client_secret = nil, nil, nil
    if private_keys[private_key_id] then
        key = private_keys[private_key_id]
    elseif conf.private_keys[private_key_id] then
        key = ngx_b64.decode_base64url(conf.private_keys[private_key_id])
    end
    if conf['client_id'] then
        client_id = conf['client_id']
    elseif env_client_id then
        client_id = env_client_id
    end
    if conf['client_secret'] then
        client_secret = conf['client_secret']
    elseif env_client_secret then
        client_secret = env_client_secret
    end

    if not key then
        kong.response.exit(500, "key " .. private_key_id .. " not found")
    end
    if not client_id then
        kong.response.exit(500, "configure client_id plugin param or env var KONG_GLUU_OAUTH_JWT_SIGNER_CLIENT_ID")
    end
    if not client_secret then
        kong.response.exit(500, "configure client_secret plugin param or env var KONG_GLUU_OAUTH_JWT_SIGNER_CLIENT_SECRET")
    end

    local function sign(claims, key, private_key_id)
        local headers={}
        headers['alg']='RS512'
        headers['typ']='JWT'
        headers['kid']=private_key_id
        local h=encode_base64(json.encode(headers)):gsub("+", "-"):gsub("/", "_")
        local c = encode_base64(json.encode(claims)):gsub("+", "-"):gsub("/", "_")
        local data = h .. '.' .. c

        local pkey = openssl_pkey.new(key)
        local digest = openssl_digest.new("sha512")
        digest:update(data)
        local signature, err = pkey:sign(digest)
        if err then
          return nil, err
        end
        return(data .. ".".. encode_base64(signature):gsub("+", "-"):gsub("/", "_"))
    end

    local function redirect_to_auth()
        return ngx.redirect(authorize_url .."?" .. ngx.encode_args({
            client_id     = client_id,
            scope         = scope,
            response_type = "code",
            redirect_uri  = cb_url,
            state         = redirect_url
        }))
        end

    local function request_access_token(code)
        local request = http.new()

        request:set_timeout(3000)
        local headers = {
            ["Content-type"] = "application/x-www-form-urlencoded"
        }
        if gluu_host then
            headers['host'] = gluu_host
        end

        local res, err = request:request_uri(access_token_url, {
            method = "POST",
            body = ngx.encode_args({
                code          = code,
                client_id     = client_id,
                client_secret = client_secret,
                redirect_uri  = cb_url,
                grant_type    = "authorization_code",
            }),
            headers = headers,
            ssl_verify = ssl_verify,
        })
        if not res then
            return nil, (err or "auth token request failed: " .. (err or "unknown reason"))
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from ".. access_token_url .. ": " .. res.body
        end

        return json.decode(res.body)
    end

    local function request_profile(access_token, id_token)
        local request = http.new()

        request:set_timeout(3000)
        local headers = {}
        if gluu_host then
            headers['host'] = gluu_host
        end

        local res, err = request:request_uri(userinfo_url .. "?" .. ngx.encode_args({
                authorization = id_token,
                access_token  = access_token
            }), {
            method = "GET",
            headers = headers,
            ssl_verify = ssl_verify,
        })
        if not res then
            return nil, "auth info request failed: " .. (err or "unknown reason")
        end

        if res.status ~= 200 then
            return nil, "received " .. res.status .. " from " .. userinfo_url
        end

        return json.decode(res.body)
    end

    local function authorize()
        if redirect_url ~= (cb_url .. "?uri=" .. uri) then
            if uri_args["error"] then
                ngx_log(ngx_ERR, "received " .. uri_args["error"] .. " from " .. authorize_url)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local token, token_err = request_access_token(uri_args["code"])
            if not token then
                ngx_log(ngx_ERR, "got error during access token request: " .. token_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local profile, profile_err = request_profile(token["access_token"], token["id_token"])
            if not profile then
                ngx_log(ngx_ERR, "got error during profile request: " .. profile_err)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

            local claims={}
            claims["sub"] = profile["email"]
            claims["iss"] = issuer
            claims["iat"] = ngx.time()
            claims["exp"] = ngx.time() + jwt_validity
            claims["email_verified"] = profile["email_verified"]
            claims["user"] = profile["email"]:match("([^@]+)@.+")
            claims["domain"] = profile["email"]:match("[^@]+@(.+)")
            claims["name"] = profile["name"]
            claims["family_name"] = profile["family_name"]
            claims["given_name"] = profile["given_name"]
            claims["roles"] = profile["roles"] and profile["roles"] or nil
            claims["provider"] = "gluu"

            for _,userinfo_to_claim in ipairs(conf.userinfo_to_claims) do
                claims[userinfo_to_claim.claim] = profile[userinfo_to_claim.userinfo] and profile[userinfo_to_claim.userinfo] or nil
            end

            local jwt = sign(claims,key,private_key_id)

            local maxAge       = (jwt_validity - 5)
            local cookie_tail  = ";version=1;path=/;Max-Age=" .. maxAge

            if same_site then
                cookie_tail = cookie_tail .. ";SameSite=" .. same_site
            end
            if secure_cookies then
                cookie_tail = cookie_tail .. ";secure"
            end
            if http_only_cookies then
                cookie_tail = cookie_tail .. ";httponly"
            end
            if cookie_domain then
                cookie_tail = cookie_tail .. ";domain=" .. cookie_domain
            end

            ngx.header["Set-Cookie"] = {
              cookie_name .. "=" .. jwt .. cookie_tail
            }

            local m, err = ngx.re.match(uri_args["state"], "uri=(?<uri>.+)")

            if m then
                if conf.jwt_at_payload then
                    return kong.response.exit(conf.jwt_at_payload_http_code, {[conf.jwt_at_payload_key]=jwt}, {
                        ['Set-Cookie']=(cookie_name .. "=" .. jwt .. cookie_tail),
                        ['Location']=m["uri"]
                    })
                else
                    if conf.jwt_at_url_args then
                        return ngx.redirect(m["uri"] .."?" .. ngx.encode_args({[conf.jwt_at_url_args_key]=jwt}))
                    else
                        return ngx.redirect(m["uri"])
                    end
                end
            else
                return ngx.exit(ngx.BAD_REQUEST)
            end
        end

        redirect_to_auth()
    end

    authorize()


end

plugin.PRIORITY = 1000
plugin.VERSION = "0.0-10"

return plugin

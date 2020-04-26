local typedefs = require "kong.db.schema.typedefs"
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

return {
    name = plugin_name,
    fields = {
      {
        config = {
          type = "record",
          fields = {
            { client_id = {
                type = "string",
                required = true
            } },
            { client_secret = {
                type = "string",
                required = true
            } },
            { jwt_validity = {
                type = "number",
                default = 86400,
                required = true
            } },
            { cookie_name = {
                type = "string",
                default = "oauth_jwt",
                required = true
            } },
            { secure_cookies = {
                type = "boolean",
                default = true,
                required = true
            } },
            { http_only_cookies = {
                type = "boolean",
                default = true,
                required = true
            } },
            { issuer = {
                type = "string",
                default = "Kong",
                required = true
            } },
            { callback_uri = {
                type = "string",
                default = "/_oauth",
                required = false
            } },
            { callback_scheme = {
                type = "string",
                required = false
            } },
            { private_key_id = {
                type = "string",
                default = "12345678-1234-1234-1234-123456789ABC",
                required = false
            } },
            { ssl_verify = {
                type = "boolean",
                default = true,
                required = true
            } },
            { gluu_url = {
                type = "string",
                required = true
            } },
            { scopes = {
                type = "array",
                elements = { type = "string" },
                default = { "email", "profile", "openid" },
                required = true
            } }
        },
    },
  },
},
}

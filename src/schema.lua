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
                required = false
            } },
            { client_secret = {
                type = "string",
                required = false
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
            { cookie_domain = {
                type = "string",
                required = false
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
            } },
            { private_keys = {
                type = "map",
                keys = { type = "string" },
                required = false,
                values = {
                    type = "string",
                    required = true,
                }
            } },
            { jwt_at_payload = {
                type = "boolean",
                default = false,
                required = true
            } },
            { jwt_at_payload_http_code = {
                type = "number",
                default = 200,
                required = true
            } },
            { jwt_at_payload_key = {
                type = "string",
                default = "access_token",
                required = true
            } },
            { jwt_at_url_args = {
                type = "boolean",
                default = false,
                required = true
            } },
            { jwt_at_url_args_key = {
                type = "string",
                default = "access_token",
                required = true
            } },
            { userinfo_to_claims = {
                type = "set",
                elements = {
                  type = "record",
                  required = true,
                  fields = {
                    { claim = {
                      type = "string",
                      required = true,
                      not_one_of = { "sub" },
                      err = "'sub' claim cannot be overridden"
                    }, },
                    { userinfo = {
                      type = "string",
                      required = true,
                    }, },
                  },
                },
                required = true,
                default = {},
          } },
        },
    },
  },
},
}

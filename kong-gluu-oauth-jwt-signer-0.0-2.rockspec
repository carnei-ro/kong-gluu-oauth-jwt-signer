package = "kong-gluu-oauth-jwt-signer"
version = "0.0-2"

source = {
 url    = "git@bitbucket.org:leandro-carneiro/kong-gluu-oauth-jwt-signer.git",
 branch = "master"
}

description = {
  summary = "generate JWT when a gluu oauth flow is valid  ",
}

dependencies = {
  "lua ~> 5.1"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.kong-gluu-oauth-jwt-signer.schema"] = "src/schema.lua",
    ["kong.plugins.kong-gluu-oauth-jwt-signer.handler"] = "src/handler.lua",
  }
}
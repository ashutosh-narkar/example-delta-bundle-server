module github.com/open-policy-agent/example-delta-bundle-server

go 1.16

require (
	github.com/go-ldap/ldap/v3 v3.3.0
	github.com/open-policy-agent/opa v0.30.1
)

replace github.com/open-policy-agent/opa => ../opa

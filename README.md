## Delta Bundle Server and LDAP Integration [WIP]

This repo contains an example of running a Delta Bundle Server which integrates with OpenLDAP.

### Steps

#### 1. Start OpenLDAP

```bash
docker run -p 389:389 --name my-openldap-container --env LDAP_ORGANISATION="acme" --env LDAP_DOMAIN="acme.com" --env LDAP_ADMIN_PASSWORD="admin" --detach osixia/openldap:1.5.0
```

#### 2. Start Bundle server

In another terminal start the Bundle server.

```bash
go run server.go
```

#### 3. Run OPA

In another terminal start OPA.

```bash
opa run -s --set services.default.url=http://localhost:8000 --set bundles.default.resource=bundle.tar.gz --set bundles.default.polling.long_polling_timeout_seconds=60
```
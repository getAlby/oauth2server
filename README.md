# Summary
This service consists out of 3 main packages:

- `internal/clients`, which provides CRUD operations for oauth _clients_
- `internal/tokens`, which provides a wrapper around https://github.com/go-oauth2/oauth2. It is linked with the clients package by the same database objects.
- `internal/gateway`, which proxies API requests, it checks the OAuth tokens and forwards the requests to an origin server. It's linked to the tokens package by the `checkTokenFunc`.

Supporting packages

- The middleware package defines some logging middleware and a user authentication middleware, which is used to authenticate the user that wants to CRUD oauth tokens.
- The repository package initializes Postgres databases to be used as datastores. In-memory databases are also implemented in their respective packages (clients/tokens)

The service is supposed to be run together with lndhub.go, but could support multiple backends of any kind.

Deployed on regtest at `https://api.regtest.getalby.com`.
## OAuth2 server
This service is responsible for generating access tokens, so Alby users can authorize 3rd party applications
to access the Alby Wallet API in their name. Possible use-cases include:

- Allow read-only access so another app can analyze your invoices or payments, or have websocket access for settled invoices/payments.
- Allow a 3rd party app to generate invoices for your account (= eg. Lightning Address).
- Allow a 3rd party to fetch your value4value information, for example to inject it in an RSS feed.
- Allow an application to make payments automatically on your behalf, maybe with some monthly budget.

### Local development

1. Run the mock server `go run cmd/mock_server/main.go` . The mock server differs from the production server in that it uses an in-memory datastore, it will auto-create client credentials and tokens, uses a mock middleware for user authentication, and will also spin up its own downstream server. 
2. If you want to create an oauth code/token, you can use the preloaded client credentials `id/secret` and redirect_uri `http://localhost:8080`. You need a valid JWT token which can be encoded using the `JWT_SECRET` from the env. The content of the JWT token should have a payload like `{id: 214, identifier: "B07KQWNvGAiq2kGWU3kz"}` (LNDHub user id and identifier)

```
http -f POST http://localhost:8081/oauth/authorize\?client_id=id\&response_type=code\&redirect_uri=http://localhost:8080\&scope\=account:read%20invoices:create%20invoices:read%20transactions:read%20balance:read%20payments:send\&expires_in\=185715992 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImlkIjoyMTQsImlkZW50aWZpZXIiOiJCMDdLUVdOdkdBaXEya0dXVTNreiJ9LCJleHAiOjE3MTAzMTY3OTYsImlhdCI6MTcxMDMxNjQ5NiwiaXNzIjoiZ2V0YWxieWNvbSIsImlkIjoyMTQsImlkZW50aWZpZXIiOiJCMDdLUVdOdkdBaXEya0dXVTNreiJ9.hhB2C40GAVrIctT2vs19Fff9vQdZR6BYdAmiuoYPs5s'
```

Use the procedure described below to get an access/refresh token pair using the code that is returned in the header of the response.

1. There is also an access/refresh token pair preloaded and logged when the mock server starts up. You can use the access token to make a request to the downstream mock server:

`http localhost:8081/balance Authorization:"Bearer <ACCESS TOKEN (get it from the startup logs)>"`

### Getting started: the hard way
This is for when you want to test using a setup that resembles production: a PG database, an LNDhub downstream server, and existing user credentials. (This section is to be updated later when moving to new auth system)
All examples are using [httpie](https://httpie.io)
- Make a POST request to the oauth server in order to get an access code. This should be made from the browser, as the responds redirects the client back to the client application.
	```
	http -f POST https://api.regtest.getalby.com/oauth/authorize\?client_id=test_client\&response_type=code\&redirect_uri=localhost:8080/client_app\&scope\=balance:read login=$login password=$password expires_in=<optional, token expiry in seconds>
	```
	- `redirect_uri` should be a web or native uri where the client should be redirected once the authorization is complete.
	- You will need a `client_id` and a `client_secret`. For regtest, you can use `test_client` and `test_secret`.
	- `response_type` should always be `code`.
	- For the possible `scope`'s, see below. These should be space-seperated (url-encoded space: `%20`).
	- Other optional form parameters are `code_challenge` and `code_challenge_method`, to be used for pure browser-based and mobile-based apps where the confidentiality of the client secret cannot be guaranteed. See below.
	- `$login` and `$password` should be your LNDHub login and password. When you use the regtest instance, this should be an existing login/password from the regtest LNDhub instance.
  The response should be a `302 Found` with the `Location` header equal to the redirect URL with the code in it:
	`Location: localhost:8080/client_app?code=YOUR_CODE`
  - The `expires_in` parameter (optional) allows you to specify the expiry duration of the token in seconds.
- Fetch an access token and a refresh token using the authorization code obtained in the previous step `oauth/token` by doing a HTTP POST request with form parameters:
	```
	http -a test_client:test_secret 
	-f POST https://api.regtest.getalby.com/oauth/token
	code=YOUR_CODE
	grant_type=authorization_code
	redirect_uri=localhost:8080/client_app
	code_verifier=<optional, code verifier>


	HTTP/1.1 200 OK
	{
    "access_token": "your_access_token",
    "expires_in": 7200,
    "refresh_token": "your_refresh_token",
    "scope": "balance:read",
    "token_type": "Bearer"
	}
	```
	Use the client_id and the client_secret as basic authentication. Use the same redirect_uri as you used in the previous step.
### Public clients
Public clients are only issued a client id, no client secret. Clients that cannot hide the client secret(single page apps, mobile apps) should use the [PKCE extension](https://aaronparecki.com/oauth-2-simplified/#single-page-apps) to protect against code interception attacks.

- Create a random string between 43-128 characters long, then generate the url-safe base64-encoded SHA256 hash of the string. Use the hash as the `code_challenge`, and use `S256` as `code_challenge_method` in the first request:

```
	http -f POST https://api.regtest.getalby.com/oauth/authorize\?client_id=test_client\&response_type=code\&redirect_uri=localhost:8080/client_app\&scope\=balance:read\&code_challenge=<YOUR_S256_HASH>\&code_challenge_method=S256 login=$login password=$password
```
- In the second request:
	- Add the initial random string as the `code_verifier` field.
	- Still use http basic authentication with the client id as the username, but use an empty string as the password.

Optionally you can also leave `code_challenge_method` blank, in which case you don't need to use S256, and you should use the same random string for both `code_hash` and `code_verifier`.

### Example scopes and endpoints:
Based on the configuration of the instance run in production by Alby
| Endpoint | Scope | Description |
|----------|-------|-------------|
| POST `/invoices`  | `invoices:create`  | Create invoices |
| GET `/invoices/incoming`  | `invoices:read`  | Read incoming payment history |
| GET `/invoices/outgoing`  | `transactions:read`  | Read outgoing payment history |
| GET `/invoices/{payment_hash}`  | `invoices:create`  | Get details about a specific invoice by payment hash |
| GET `/balance`  | `balance:read`  | Get account balance |
| GET `/user/value4value`  | `account:read`  | Read user's Lightning Address and keysend information|

### Token Introspection
- To view what all scopes your token has, client id and redirect URL, you can make a get request like the following with your access token:
  ```
  http https://api.regtest.getalby.com/oauth/token/introspect Authorization:"Bearer $your_access_token"

  HTTP/1.1 200 OK
  {
    "client_id": "test_client",
    "redirect_uri": "http://localhost:8080",
    "scopes": {
      "balance:read": "Read your account summary"
    }
  }
  ```

## API Gateway
- Use the access token to make a request to the LNDhub API:
	```
	http https://api.regtest.getalby.com/balance Authorization:"Bearer $your_access_token"
	```

To do:
- budget feature

## Admin API
There is currently no authentication here, so the `/admin/..` routes should not be accesible from outside a trusted network.

| Endpoint | Request Fields | Response Fields | Description |
|----------|-----------------|-------|-------------|
| GET `/admin/clients`  | |(array) id, imageUrl, name, url  | Get all registered clients |
| GET `/admin/clients/{clientId}`  | |id, imageUrl, name, url | Get a specific client by client id|
| POST `/admin/clients`  | name, url (=landing page), domain (= app callback), imageUrl, public (boolean, if true then no client secret will be created) | clientId, clientSecret, name, imageUrl, url | Create a new client|
| PUT `/admin/clients/{clientId}`  |name, imageUrl, url |id, name, imageUrl, url  | Update the metadata of an existing client|
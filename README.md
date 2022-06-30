This service consists out of 2 pieces: an OAuth server issuing tokens and an API Gateway that is secured by these tokens.

Deployed on regtest at `https://api.regtest.getalby.com`.
## OAuth2 server
This service is responsible for generating access tokens, so Alby users can authorize 3rd party applications
to access the Alby Wallet API in their name. Possible use-cases include:

- Allow read-only access so another app can analyze your invoices or payments, or have websocket access for settled invoices/payments.
- Allow a 3rd party app to generate invoices for your account (= eg. Lightning Address).
- Allow a 3rd party to fetch your value4value information, for example to inject it in an RSS feed.
- Allow an application to make payments automatically on your behalf, maybe with some monthly budget.

### Getting started
All examples are using [httpie](https://httpie.io)
- Get an "admin" token for your lndhub account using your lndhub login and password:
	```
	http POST https://lndhub.regtest.getalby.com/auth login=$login password=$password
	```
	Save the `access_token` in the response for the next step.

- Make a GET request to the oauth server in order to get an access code. This should be made from the browser, as the responds redirects the client back to the client application.
	```
	http https://api.regtest.getalby.com/oauth/authorize\?client_id=test_client\&response_type=code\&redirect_uri=localhost:8080/client_app\&scope\=balance:read Authorization:"Bearer $token"
	```
	- `redirect_uri` should be a web or native uri where the client should be redirected once the authorization is complete.
	- You will need a `client_id` and a `client_secret`. For regtest, you can use `test_client` and `test_secret`.
	- `response_type` should always be `code`.
	- For the possible `scope`'s, see below. These should be space-seperated (url-encoded space: `%20`).
	- `$token` should be the admin token obtained in the previous step.
  The response should be a `302 Found` with the `Location` header equal to the redirect URL with the code in it:
	`Location: localhost:8080/client_app?code=YOUR_CODE`
- Fetch an access token and a refresh token using the authorization code obtained in the previous step `oauth/token` by doing a HTTP POST request with form parameters:
	```
	http -a test_client:test_secret 
	-f POST https://api.regtest.getalby.com/oauth/token
	code=YOUR_CODE
	grant_type=authorization_code
	redirect_uri=localhost:8080/client_app


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
### Scopes:
WIP, more to follow
```
var scopes = map[string][]string{
	"invoices:create":   {"/v2/invoices", "Create invoices on your behalf."},
	"invoices:read":     {"/v2/invoices/incoming", "Read your invoice history, get realtime updates on newly paid invoices."},
	"transactions:read": {"/v2/invoices/outgoing", "Read your outgoing transaction history and check payment status."},
	"balance:read":      {"/v2/balance", "Read your balance."},
}
```
## API Gateway
- Use the access token to make a request to the LNDhub API:
	```
	http https://api.regtest.getalby.com/v2/balance Authorization:"Bearer $your_access_token"
	```
	The API documentation can be found at https://lndhub.regtest.getalby.com/swagger/index.html. Be aware that the Host for the OAuth API must be changed to `api.regtest.getalby.com` (LNDhub cannot be accessed directly using tokens issued by the OAuth server).
	Currently, only the scopes/routes listed above can be accessed.

To do:
- refresh tokens
- multiple origin servers for gateway
- more scopes
- budget feature
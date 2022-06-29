# OAuth2 server

This service is responsible for generating access tokens, so Alby users can authorize 3rd party applications
to access the Alby Wallet API in their name. Possible use-cases include:

- Allow read-only access so another app can analyze your invoices or payments, or have websocket access for settled invoices/payments.
- Allow a 3rd party app to generate invoices for your account (= eg. Lightning Address).
- Allow a 3rd party to fetch your value4value information, for example to inject it in an RSS feed.
- Allow an application to make payments automatically on your behalf, maybe with some monthly budget.

There are 2 main endpoints:

- `/oauth/authorize`: First step of the OAuth flow, needs `client_id`, `scope`, `state`, `redirect_uri` and `response_type` as query parameters.
Responds by redirecting the client back to the 3rd party app if the authorization is succesful.	
- `oauth/token`: Second step of the OAuth flow, accepts a POST request:
```
curl --compressed -v https://getalby.com/v1/oauth/tokens \
	-u test_client_1:test_secret \
	-d "grant_type=authorization_code" \
	-d "code=7afb1c55-76e4-4c76-adb7-9d657cb47a27" \
	-d "redirect_uri=https://www.example.com"
```
and responds with an access token and a refresh token.

# Scopes:
WIP
```
var scopes = map[string][]string{
	"invoices:create":   {"/v2/invoices", "Create invoices on your behalf."},
	"invoices:read":     {"/v2/invoices/incoming", "Read your invoice history, get realtime updates on newly paid invoices."},
	"transactions:read": {"/v2/invoices/outgoing", "Read your outgoing transaction history and check payment status."},
	"balance:read":      {"/v2/balance", "Read your balance."},
}
```
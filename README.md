# Koa Stateless CSRF

[![Release](https://github.com/DASPRiD/koa-stateless-csrf/actions/workflows/release.yml/badge.svg)](https://github.com/DASPRiD/koa-stateless-csrf/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/DASPRiD/koa-stateless-csrf/branch/main/graph/badge.svg?token=GBvU1lZb3Q)](https://codecov.io/gh/DASPRiD/koa-stateless-csrf)

Stateless CSRF implementation for Koa based APIs, based on the `nosurf` implementation.

It includes protection against [BREACH attacks](https://breachattack.com/).

## Installation

Run `npm i koa-stateless-csrf`

## Quickstart

To add CSRF protection to your API, simply add the CSRF middleware to your Koa application:

```typescript
import {csrfMiddleware} from 'koa-stateless-csrf';

app.use(csrfMiddleware());
```

This will configure the CSRF middleware with the default cookie name `csrf_token` and default header name
`X-CSRF-Token`. Both can be changed via the middleware options.

In order for frontends to be able to read and send the `X-CSRF-Token` request and response header, you need to configure
CORS accordingly. It is highly recommended to limit the CORS origin for this, so malicious websites cannot read or send
the token.

## Handling CSRF on the frontend

In order for the frontend to retrieve a CSRF token, it can call any endpoint configured after the CSRF middleware. To do
so, send a request with `X-CSRF-Token` header set to `fetch`. The response will have a masked `X-CSRF-Token` response
header with the value to use. This value is valid until the end of the browser session, after which the cookie will
expire and a new token will be generated.

If for whatever reason the CSRF cookie token was deleted or tampered, and thus the token available on the frontend is
not valid anymore, you will receive a 400 error, with a new valid token supplied in the response header.

In order for your frontend to recognize and potentially retry the request, the error emitted by the middleware is a
`http error` with its name set to `CsrfError`. You should forward this information to the frontend.

## Cookie options

Cookies will always be set as `http-only` and default to a path of `/`. This is sufficient for development, but in
production you should set the following options:

```typescript
import {csrfMiddleware} from 'koa-stateless-csrf';

app.use(csrfMiddleware({
    cookieOptions: {
        // If you API lives on the same exact domain as the frontend,
        // use that domain, otherwise use their parent domain
        domain: 'example.com',
        // Only serve the API over HTTPS
        secure: true,
        // Only allow the cookie to be sent from the same root domain
        sameSite: 'strict',
    },
}));
```

import {ServerResponse} from 'http';
import createHttpError from 'http-errors';
import Koa from 'koa';
import {createRequest} from 'node-mocks-http';
import type {RequestMethod, RequestOptions} from 'node-mocks-http';
import {describe, expect, it} from 'vitest';
import {csrfMiddleware} from '../src/index.js';
import {safeMethods} from '../src/middleware.js';

const app = new Koa();

const createContext = (options ?: RequestOptions) => {
    const req = createRequest(options);
    const res = new ServerResponse(req);
    return app.createContext(req, res);
};

const voidNext = async () : Promise<void> => Promise.resolve();

const badOriginError = createHttpError(400, 'The calling origin is not allowed to perform this request');
const badCsrfError = createHttpError(400, 'The CSRF token in the cookie doesn\'t match the one received in a header');

const validHeaderToken = 'qWE6kYdLWfUw5FRBtOJB8614yfnR7/aKZpHYZSPlQ21AKLK9Cn0qDK4uwoxOFmcVPVP10tMfsmJiJSb4XpdI2g==';
const validCookieToken = '6UmILI02c/meypbN+vQm5pArPCsC8EToBLT+nX1yC7f8VVEn43ZPPBgkl2h/9rd4bbkXONhjHri4urNugGLwaA';

describe('Middleware', () => {
    it('should append vary header', async () => {
        const context = createContext();
        const middleware = csrfMiddleware();
        await middleware(context, voidNext);

        expect(context.response.get('Vary')).toEqual('Cookie');
    });

    it('should allow to disable CSRF without origin', async () => {
        const context = createContext({
            method: 'POST',
        });
        const middleware = csrfMiddleware({disableWithoutOrigin: true});

        let nextCalled = false;

        await middleware(context, async () => {
            nextCalled = true;
            return Promise.resolve();
        });

        expect(context.response.get('Vary')).toEqual('Origin, Cookie');
        expect(nextCalled).toBeTruthy();
    });

    it('should keep CSRF active with origin', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                Origin: 'http://localhost',
            },
        });
        const middleware = csrfMiddleware({disableWithoutOrigin: true});

        await expect(async () => {
            await middleware(context, voidNext);
        }).rejects.toThrow(badCsrfError);
        expect(context.response.get('Vary')).toEqual('Origin, Cookie');
    });

    it('should disallow bad origins when enabled', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                'X-CSRF-Token': validHeaderToken,
                'Cookie': `csrf_token=${validCookieToken}`,
                Origin: 'http://bad.actor',
            },
        });
        const middleware = csrfMiddleware({allowedOrigins: ['https://safe.space']});

        await expect(async () => {
            await middleware(context, voidNext);
        }).rejects.toThrow(badOriginError);
        expect(context.response.get('Vary')).toEqual('Origin, Cookie');
    });

    it('should send new token without existing token', async () => {
        const context = createContext({
            headers: {
                'X-CSRF-Token': 'fetch',
            },
        });
        const middleware = csrfMiddleware();
        await middleware(context, voidNext);

        const cookieToken = context.response.get('Set-Cookie')[0].split(';')[0].split('=')[1];
        const responseToken = context.response.get('X-CSRF-Token');

        expect(cookieToken).toBeDefined();
        expect(cookieToken).not.toEqual('');
        expect(responseToken).not.toEqual('');
        expect(cookieToken).not.toEqual(responseToken);
    });

    for (const safeMethod of safeMethods) {
        it(`should not check ${safeMethod} request`, async () => {
            const context = createContext({
                method: safeMethod as RequestMethod,
            });
            const middleware = csrfMiddleware();
            let nextCalled = false;

            await middleware(context, async () => {
                nextCalled = true;
                return Promise.resolve();
            });

            expect(nextCalled).toBeTruthy();
        });
    }

    it('should not return token by default', async () => {
        const context = createContext();
        const middleware = csrfMiddleware();
        await middleware(context, voidNext);

        expect(context.response.get('X-CSRF-Token')).toEqual('');
    });

    it('should fail without CSRF token in header', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                'Cookie': `csrf_token=${validCookieToken}`,
            },
        });
        const middleware = csrfMiddleware();

        await expect(async () => {
            await middleware(context, voidNext);
        }).rejects.toThrow(badCsrfError);

        expect(context.response.get('X-CSRF-Token')).not.toEqual('');
    });

    it('should fail without CSRF token in cookie', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                'X-CSRF-Token': validHeaderToken,
            },
        });
        const middleware = csrfMiddleware();

        await expect(async () => {
            await middleware(context, voidNext);
        }).rejects.toThrow(badCsrfError);

        expect(context.response.get('X-CSRF-Token')).not.toEqual('');
    });

    it('should succeed with matching CSRF token', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                'X-CSRF-Token': validHeaderToken,
                'Cookie': `csrf_token=${validCookieToken}`,
            },
        });
        const middleware = csrfMiddleware();

        await middleware(context, voidNext);
    });

    it('should allow changing cookie and header name', async () => {
        const context = createContext({
            method: 'POST',
            headers: {
                'X-My-CSRF-Token': validHeaderToken,
                'Cookie': `my_csrf_token=${validCookieToken}`,
            },
        });
        const middleware = csrfMiddleware({
            headerName: 'X-My-CSRF-Token',
            cookieName: 'my_csrf_token',
        });

        await middleware(context, voidNext);
    });

    it('should allow changing cookie options', async () => {
        const context = createContext();
        const middleware = csrfMiddleware({
            cookieOptions: {
                sameSite: 'strict',
                domain: 'example.com',
            },
        });
        await middleware(context, voidNext);

        const cookieToken = context.response.get('Set-Cookie')[0];

        expect(cookieToken).toContain('domain=example.com');
        expect(cookieToken).toContain('samesite=strict');
        expect(cookieToken).toContain('httponly');
        expect(cookieToken).toContain('path=/');
    });
});

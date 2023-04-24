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

const signingKeys = ['test'] as const;
const voidNext = async () : Promise<void> => Promise.resolve();

const badCsrfError = createHttpError(400, 'The CSRF token in the cookie doesn\'t match the one received in a header');
const tamperedCsrfError = createHttpError(400, 'The CSRF token in the cookie has been tampered');

const validHeaderToken = 'qWE6kYdLWfUw5FRBtOJB8614yfnR7/aKZpHYZSPlQ21AKLK9Cn0qDK4uwoxOFmcVPVP10tMfsmJiJSb4XpdI2g==';
const validCookieToken = '6UmILI02c/meypbN+vQm5pArPCsC8EToBLT+nX1yC7f8VVEn43ZPPBgkl2h/9rd4bbkXONhjHri4urNugGLwaA';

describe('Middleware', () => {
    it('should append vary header', async () => {
        const context = createContext();
        const middleware = csrfMiddleware({signingKeys});
        await middleware(context, voidNext);

        expect(context.response.get('Vary')).toEqual('Cookie');
    });

    it('should send new token without existing token', async () => {
        const context = createContext({
            headers: {
                'X-CSRF-Token': 'fetch',
            },
        });
        const middleware = csrfMiddleware({signingKeys});
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
            const middleware = csrfMiddleware({signingKeys});
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
        const middleware = csrfMiddleware({signingKeys});
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
        const middleware = csrfMiddleware({signingKeys});

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
        const middleware = csrfMiddleware({signingKeys});

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
        const middleware = csrfMiddleware({signingKeys});

        await middleware(context, voidNext);
    });

    it('should report tampered CSRF token', async () => {
        const tamperedToken = '0' + validCookieToken;

        const context = createContext({
            method: 'POST',
            headers: {
                'X-CSRF-Token': validHeaderToken,
                'Cookie': `csrf_token=${tamperedToken}`,
            },
        });
        const middleware = csrfMiddleware({signingKeys});

        await expect(async () => {
            await middleware(context, voidNext);
        }).rejects.toThrow(tamperedCsrfError);
    });
});

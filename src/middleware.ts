import type {SetOption as CookieOptions} from 'cookies';
import type {Context, Middleware} from 'koa';
import {maskToken} from './crypto.js';
import {generateToken, tokenLength, verifyToken} from './token.js';

export type CsrfOptions = {
    cookieName ?: string;
    headerName ?: string;
    cookieOptions ?: CookieOptions;
    disableWithoutOrigin ?: boolean;
    allowedOrigins ?: string[];
};

export const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

const badOriginError = (context : Context) : never => {
    context.throw(
        400,
        'The calling origin is not allowed to perform this request',
        {name: 'CsrfError'}
    );
};

const badCsrfError = (context : Context) : never => {
    context.throw(
        400,
        'The CSRF token in the cookie doesn\'t match the one received in a header',
        {name: 'CsrfError'}
    );
};

export const csrfMiddleware = (options ?: CsrfOptions) : Middleware => {
    const cookieName = options?.cookieName ?? 'csrf_token';
    const headerName = options?.headerName ?? 'X-CSRF-Token';

    const extractToken = (context : Context) : Buffer | 'fetch' | null => {
        const sentToken = context.get(headerName);

        if (!sentToken) {
            return null;
        }

        if (sentToken === 'fetch') {
            return 'fetch';
        }

        return Buffer.from(sentToken, 'base64');
    };

    const setTokenResponse = (context : Context, token : Buffer) => {
        context.set(headerName, maskToken(token).toString('base64'));
    };

    const setTokenCookie = (context : Context, token : Buffer) => {
        context.cookies.set(
            cookieName,
            token.toString('base64'),
            {
                path: '/',
                ...options?.cookieOptions,
                httpOnly: true,
                signed: false,
            }
        );
    };

    const regenerateToken = (context : Context) => {
        const token = generateToken();
        setTokenCookie(context, token);
        return token;
    };

    const readCookieToken = (context : Context) : [Buffer, boolean] => {
        const cookieToken = Buffer.from(context.cookies.get(cookieName) ?? '', 'base64');
        let realToken = cookieToken.subarray(0, tokenLength);
        let regenerated = false;

        if (realToken.length !== tokenLength) {
            realToken = regenerateToken(context);
            regenerated = true;
        }

        return [realToken, regenerated];
    };

    return async (context, next) => {
        if (options?.disableWithoutOrigin || options?.allowedOrigins) {
            context.vary('Origin');
        }

        context.vary('Cookie');

        const origin = context.get('Origin');

        if (!origin && options?.disableWithoutOrigin) {
            return next();
        }

        if (options?.allowedOrigins && !options.allowedOrigins.includes(origin)) {
            return badOriginError(context);
        }

        const sentToken = extractToken(context);

        if (sentToken === 'fetch') {
            const [realToken] = readCookieToken(context);
            setTokenResponse(context, realToken);
        }

        if (safeMethods.has(context.method)) {
            return next();
        }

        const [realToken, realTokenRegenerated] = readCookieToken(context);

        if (realTokenRegenerated) {
            // The token has just been regenerated, so we can skip any tests.
            setTokenResponse(context, realToken);
            return badCsrfError(context);
        }

        if (!Buffer.isBuffer(sentToken) || !verifyToken(realToken, sentToken)) {
            setTokenResponse(context, realToken);
            return badCsrfError(context);
        }

        return next();
    };
};

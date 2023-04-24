import {randomBytes, timingSafeEqual} from 'crypto';
import {unmaskToken} from './crypto.js';

export const tokenLength = 32;

export const generateToken = () : Buffer => {
    return randomBytes(tokenLength);
};

const tokensEqual = (realToken : Buffer, sentToken : Buffer) : boolean => {
    return realToken.length === tokenLength
        && sentToken.length === tokenLength
        && timingSafeEqual(realToken, sentToken);
};

export const verifyToken = (realToken : Buffer, sentToken : Buffer) : boolean => {
    if (realToken.length === tokenLength && sentToken.length === tokenLength * 2) {
        return tokensEqual(realToken, unmaskToken(sentToken));
    }

    return false;
};

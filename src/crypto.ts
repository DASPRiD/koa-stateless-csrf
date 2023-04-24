import {randomBytes} from 'crypto';
import {tokenLength} from './token.js';

export const oneTimePad = (data : Buffer, key : Buffer) : void => {
    const length = data.length;

    if (length !== key.length) {
        throw new Error('Lengths of slices are not equal');
    }

    for (let i = 0; i < length; ++i) {
        data[i] ^= key[i];
    }
};

export const maskToken = (data : Buffer) : Buffer => {
    if (data.length !== tokenLength) {
        throw new Error('Invalid token length');
    }

    const result = Buffer.allocUnsafe(tokenLength * 2);
    data.copy(result);

    const key = randomBytes(tokenLength);
    key.copy(result, tokenLength);

    oneTimePad(result.subarray(0, tokenLength), key);

    return result;
};

export const unmaskToken = (data : Buffer) : Buffer => {
    if (data.length !== tokenLength * 2) {
        throw new Error('Invalid token length');
    }

    const token = data.subarray(0, tokenLength);
    const key = data.subarray(tokenLength);
    oneTimePad(token, key);

    return token;
};

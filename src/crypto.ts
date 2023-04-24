import {createHmac, randomBytes} from 'crypto';
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

export const signToken = (data : Buffer, key : string) : Buffer => {
    const signature = createHmac('sha256', key).update(data).digest();
    const result = Buffer.allocUnsafe(data.length + signature.length);
    data.copy(result);
    signature.copy(result, tokenLength);

    return result;
};

export const verifyTokenSignature = (data : Buffer, signature : Buffer, keys : readonly string[]) : boolean => {
    for (const key of keys) {
        const keySignature = createHmac('sha256', key).update(data).digest();

        if (signature.equals(keySignature)) {
            return true;
        }
    }

    return false;
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

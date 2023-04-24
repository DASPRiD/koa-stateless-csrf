import {describe, it, expect} from 'vitest';
import {maskToken, oneTimePad, signToken, unmaskToken, verifyTokenSignature} from '../src/crypto.js';
import {tokenLength} from '../src/token.js';

describe('Crypto', () => {
    describe('Signature', () => {
        it('should successfully verify a signed token', () => {
            const token = Buffer.alloc(tokenLength, 0);
            const signedToken = signToken(token, 'test');

            const extractedToken = signedToken.slice(0, tokenLength);
            const signature = signedToken.slice(tokenLength);

            expect(signature.length).toBeGreaterThan(0);
            expect(verifyTokenSignature(extractedToken, signature, ['test'])).toBeTruthy();
        });

        it('should successfully verify a signed token with an older key', () => {
            const token = Buffer.alloc(tokenLength, 0);
            const signedToken = signToken(token, 'old');

            const extractedToken = signedToken.slice(0, tokenLength);
            const signature = signedToken.slice(tokenLength);

            expect(signature.length).toBeGreaterThan(0);
            expect(verifyTokenSignature(extractedToken, signature, ['test', 'old'])).toBeTruthy();
        });

        it('should fail with invalid signature', () => {
            const token = Buffer.alloc(tokenLength, 0);
            const signedToken = signToken(token, 'invalid');

            const extractedToken = signedToken.slice(0, tokenLength);
            const signature = signedToken.slice(tokenLength);

            expect(signature.length).toBeGreaterThan(0);
            expect(verifyTokenSignature(extractedToken, signature, ['test'])).toBeFalsy();
        });
    });

    describe('OTP', () => {
        it('should throw error on length mismatch', () => {
            const data = Buffer.from('a');
            const key = Buffer.from('bc');

            expect(() => {
                oneTimePad(data, key);
            }).toThrowError('Lengths of slices are not equal');
        });

        it('should mask correctly', () => {
            const data = Buffer.from('a very secret message', 'ascii');
            const key = Buffer.from('even more secret key!', 'ascii');
            const expected = Buffer.from('0456130b52144f0100430100175208115318041e44', 'hex');

            oneTimePad(data, key);

            expect(data).toEqual(expected);
        });

        it('should unmask correctly', () => {
            const original = Buffer.from('a very secret message', 'ascii');
            const data = Buffer.allocUnsafe(original.length);
            original.copy(data);

            const key = Buffer.from('even more secret key!', 'ascii');

            oneTimePad(data, key);
            oneTimePad(data, key);

            expect(data).toEqual(original);
        });
    });

    describe('Masking', () => {
        it('should mask token correctly', () => {
            const token = Buffer.from('12345678901234567890123456789012', 'ascii');
            const fullToken = maskToken(token);

            expect(fullToken.length).toEqual(tokenLength * 2);

            const encodedToken = fullToken.slice(0, tokenLength);
            const key = fullToken.slice(tokenLength);

            oneTimePad(encodedToken, key);

            expect(encodedToken).toEqual(token);
        });

        it('should fail masking with invalid data length', () => {
            expect(() => {
                maskToken(Buffer.alloc(64, 0));
            }).toThrowError('Invalid token length');
        });

        it('should unmask token correctly', () => {
            const token = Buffer.from('12345678901234567890123456789012', 'ascii');
            const fullToken = maskToken(token);
            const unmaskedToken = unmaskToken(fullToken);

            expect(unmaskedToken).toEqual(token);
        });

        it('should fail unmasking with invalid data length', () => {
            expect(() => {
                unmaskToken(Buffer.alloc(32, 0));
            }).toThrowError('Invalid token length');
        });
    });
});

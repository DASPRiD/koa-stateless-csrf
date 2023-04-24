import {describe, expect, it} from 'vitest';
import {generateToken, tokenLength, verifyToken} from '../src/token.js';

describe('Token', () => {
    it('should generate a valid token', () => {
        const token = generateToken();
        expect(token.length).toEqual(tokenLength);
    });

    it('should test length correctly', () => {
        const realToken = Buffer.alloc(32, 0);
        const invalidSentToken = Buffer.alloc(33, 0);
        const validSentToken = Buffer.alloc(64, 0);

        expect(verifyToken(realToken, invalidSentToken)).toBeFalsy();
        expect(verifyToken(realToken, validSentToken)).toBeTruthy();
    });

    it('should verify masked token correctly', () => {
        const realToken = Buffer.from('qwertyuiopasdfghjklzxcvbnm123456', 'ascii');
        const validSentToken = Buffer.from('qwertyuiopasdfghjklzxcvbnm123456' + '\0'.repeat(32), 'ascii');
        const invalidSentToken = Buffer.from('qwertyuiopasdfghjklzxcvbnm1234560' + '\0'.repeat(31), 'ascii');

        expect(verifyToken(realToken, validSentToken)).toBeTruthy();
        expect(verifyToken(realToken, invalidSentToken)).toBeFalsy();
    });
});

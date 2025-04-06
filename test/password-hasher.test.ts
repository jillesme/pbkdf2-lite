import { describe, it, expect, beforeEach, vi } from 'vitest';
import PBKDF2Lite, { hashPassword, verifyPassword } from '../src/password-hasher';

// Also test the index exports
import indexDefault, { PBKDF2Lite as IndexPBKDF2Lite, hashPassword as indexHashPassword, verifyPassword as indexVerifyPassword } from '../src/index';

// Mock the crypto API
const mockCrypto = {
  getRandomValues: vi.fn((buffer: Uint8Array) => {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = i % 256;
    }
    return buffer;
  }),
  subtle: {
    importKey: vi.fn(() => Promise.resolve('mockKeyMaterial')),
    deriveBits: vi.fn(() => Promise.resolve(new Uint8Array([1, 2, 3, 4, 5]).buffer))
  }
};

// Replace global crypto with our mock in node environment
// (only needed for unit tests - in actual browser/worker environments crypto is available)
vi.stubGlobal('crypto', mockCrypto);

// Test the index exports
describe('Index exports', () => {
  it('should export the PBKDF2Lite class as default and named export', () => {
    expect(indexDefault).toBe(PBKDF2Lite);
    expect(IndexPBKDF2Lite).toBe(PBKDF2Lite);
  });

  it('should export utility functions', () => {
    expect(indexHashPassword).toBe(hashPassword);
    expect(indexVerifyPassword).toBe(verifyPassword);
  });
});

describe('PBKDF2Lite', () => {
  describe('Constructor', () => {
    it('should use default values when no options are provided', () => {
      const hasher = new PBKDF2Lite();
      expect(hasher['iterations']).toBe(60000);
      expect(hasher['saltLength']).toBe(16);
      expect(hasher['keyLength']).toBe(256);
      expect(hasher['hashFunction']).toBe('SHA-256');
      expect(hasher['algorithmId']).toBe('PBKDF2-SHA256');
    });

    it('should use provided iteration count', () => {
      const hasher = new PBKDF2Lite(100000);
      expect(hasher['iterations']).toBe(100000);
    });

    it('should use provided options', () => {
      const hasher = new PBKDF2Lite(80000, {
        saltLength: 32,
        keyLength: 512,
        hashFunction: 'SHA-512',
        algorithmId: 'PBKDF2-Custom'
      });
      expect(hasher['iterations']).toBe(80000);
      expect(hasher['saltLength']).toBe(32);
      expect(hasher['keyLength']).toBe(512);
      expect(hasher['hashFunction']).toBe('SHA-512');
      expect(hasher['algorithmId']).toBe('PBKDF2-Custom');
    });
  });

  describe('getIterationsFromHash', () => {
    let hasher: PBKDF2Lite;

    beforeEach(() => {
      hasher = new PBKDF2Lite();
    });

    it('should extract iterations from a valid hash string', () => {
      const hash = 'PBKDF2-SHA256$75000$abcdef$123456';
      expect(hasher.getIterationsFromHash(hash)).toBe(75000);
    });

    it('should return null for an invalid hash format', () => {
      expect(hasher.getIterationsFromHash('invalid-hash')).toBeNull();
      expect(hasher.getIterationsFromHash('PBKDF2-SHA256$invalid$abcdef$123456')).toBeNull();
      expect(hasher.getIterationsFromHash('PBKDF2-SHA256$-1$abcdef$123456')).toBeNull();
      expect(hasher.getIterationsFromHash('PBKDF2-SHA256$0$abcdef$123456')).toBeNull();
    });
  });

  describe('hash', () => {
    let hasher: PBKDF2Lite;

    beforeEach(() => {
      hasher = new PBKDF2Lite();
      mockCrypto.getRandomValues.mockClear();
      mockCrypto.subtle.importKey.mockClear();
      mockCrypto.subtle.deriveBits.mockClear();
    });

    it('should generate a hash in the correct format', async () => {
      const password = 'test-password';
      const hash = await hasher.hash(password);
      
      // Hash should be in the format: algorithm$iterations$salt$hash
      const parts = hash.split('$');
      expect(parts.length).toBe(4);
      expect(parts[0]).toBe('PBKDF2-SHA256');
      expect(parts[1]).toBe('60000');
      expect(parts[2].length).toBe(32); // 16 bytes salt = 32 hex chars
      expect(parts[3].length).toBe(10); // Our mock returns 5 bytes = 10 hex chars
      
      // Verify the functions were called with expected parameters
      expect(mockCrypto.getRandomValues).toHaveBeenCalledOnce();
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
        {
          name: 'PBKDF2',
          salt: expect.any(Uint8Array),
          iterations: 60000,
          hash: 'SHA-256'
        },
        'mockKeyMaterial',
        256
      );
    });
  });

  describe('verify', () => {
    let hasher: PBKDF2Lite;

    beforeEach(() => {
      hasher = new PBKDF2Lite();
      mockCrypto.subtle.importKey.mockClear();
      mockCrypto.subtle.deriveBits.mockClear();
    });

    it('should return true for matching password and hash', async () => {
      const storedHash = 'PBKDF2-SHA256$60000$000102030405060708090a0b0c0d0e0f$0102030405';
      const password = 'test-password';
      
      const result = await hasher.verify(storedHash, password);
      
      expect(result).toBe(true);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledOnce();
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
        {
          name: 'PBKDF2',
          salt: expect.any(Uint8Array),
          iterations: 60000,
          hash: 'SHA-256'
        },
        'mockKeyMaterial',
        256
      );
    });

    it('should return false for invalid hash format', async () => {
      const result = await hasher.verify('invalid-hash', 'password');
      expect(result).toBe(false);
    });

    it('should return false for algorithm mismatch', async () => {
      const result = await hasher.verify('DIFFERENT-ALGO$60000$salt$hash', 'password');
      expect(result).toBe(false);
    });

    it('should return false for invalid iterations', async () => {
      const result = await hasher.verify('PBKDF2-SHA256$invalid$salt$hash', 'password');
      expect(result).toBe(false);
    });
  });

  describe('Legacy functions', () => {
    beforeEach(() => {
      mockCrypto.getRandomValues.mockClear();
      mockCrypto.subtle.importKey.mockClear();
      mockCrypto.subtle.deriveBits.mockClear();
    });

    it('hashPassword should create a hash using default settings', async () => {
      const hash = await hashPassword('password');
      
      expect(hash).toContain('PBKDF2-SHA256$60000$');
      expect(mockCrypto.getRandomValues).toHaveBeenCalledOnce();
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledOnce();
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledOnce();
    });

    it('verifyPassword should verify a hash using default settings', async () => {
      const result = await verifyPassword('PBKDF2-SHA256$60000$000102030405060708090a0b0c0d0e0f$0102030405', 'password');
      
      expect(result).toBe(true);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledOnce();
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledOnce();
    });
  });
}); 
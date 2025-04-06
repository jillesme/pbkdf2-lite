# pbkdf2-lite

A lightweight PBKDF2 password hasher optimized for edge runtimes like Cloudflare Workers. Uses the native Web Crypto API for optimal performance in resource-constrained environments.

## Features

- 🔒 Secure password hashing using PBKDF2 with SHA-256
- 🚀 Optimized for edge runtimes (Cloudflare Workers, Deno Deploy, etc.)
- 🧪 Configurable iteration count for security/performance tradeoffs
- 📦 Zero dependencies, minimal size
- 🔄 Uses native Web Crypto API for performance

## Installation

```bash
npm install pbkdf2-lite
# or
yarn add pbkdf2-lite
# or
pnpm add pbkdf2-lite
```

## Usage

### Basic Usage

```typescript
import PBKDF2Lite from 'pbkdf2-lite';

// Create a hasher with default settings (60,000 iterations)
const hasher = new PBKDF2Lite();

// Hash a password
const hashedPassword = await hasher.hash('mySecurePassword');
// => "PBKDF2-SHA256$60000$f1a28703fb9...1b2c3"

// Verify a password
const isMatch = await hasher.verify(hashedPassword, 'mySecurePassword');
// => true
```

### Configuring Iteration Count

The iteration count is the most critical security parameter. Higher values improve security but increase CPU usage:

```typescript
// For extremely constrained environments (e.g., 10ms CPU limit)
const lightHasher = new PBKDF2Lite(20000);

// For better security when you have more CPU time available
const strongHasher = new PBKDF2Lite(100000);
```

### Advanced Configuration

You can customize all parameters:

```typescript
const customHasher = new PBKDF2Lite(60000, {
  saltLength: 32,           // Salt length in bytes (default: 16)
  keyLength: 512,           // Output key length in bits (default: 256)
  hashFunction: 'SHA-512',  // Hash function (default: 'SHA-256')
  algorithmId: 'PBKDF2-Custom' // ID stored in hash string (default: 'PBKDF2-SHA256')
});
```

## Hash Format

The generated hash string has the format:

```
ALGORITHM$ITERATIONS$SALT$HASH
```

For example:
```
PBKDF2-SHA256$60000$a1b2c3d4e5f6....$a1b2c3d4e5f6....
```

## Performance Considerations

The iteration count is the primary factor affecting performance. Choose a value that:

1. Provides adequate security (higher is better)
2. Stays within your runtime's CPU time limits

For Cloudflare Workers **Free Tier** with a 10ms CPU time limit, values between 20,000-80,000 are typical, depending on your specific needs.

## Changing Iterations Over Time

As computing power increases, you may need to increase the iteration count to maintain security. When changing iterations:

### How It Works

1. **Existing hashes remain unchanged** - Previously stored password hashes will continue to use their original iteration count
2. **Automatic detection** - The verification process automatically detects the iteration count from the stored hash
3. **Transparent upgrades** - You can implement progressive upgrades by:
   - Verifying with the old iteration count
   - If successful, re-hashing with the new iteration count
   - Storing the updated hash

### Example: Progressive Upgrade

```typescript
// Create hashers with old and new iteration counts
const oldHasher = new PBKDF2Lite(60000);
const newHasher = new PBKDF2Lite(100000);

async function verifyAndUpgrade(storedHash, password) {
  // Verify with automatically detected iterations from hash
  const isValid = await oldHasher.verify(storedHash, password);
  
  if (isValid) {
    // Get iterations from the hash using the helper method
    const storedIterations = oldHasher.getIterationsFromHash(storedHash);
    
    // If using old iterations, upgrade the hash
    if (storedIterations !== null && storedIterations < 100000) {
      // Create new hash with higher iterations
      return await newHasher.hash(password);
    }
  }
  
  return isValid;
}
```

This approach ensures:
- Backward compatibility with existing hashes
- Gradual security improvements as users authenticate
- No disruption to your authentication system

## License

MIT 
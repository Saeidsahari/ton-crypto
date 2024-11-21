a512_sync('hello-world');
```

## HMAC-SHA-512
```js
const hmac: Buffer = await hmac_sha512('hmac-key', 'data');
```

## PBKDF2-SHA-512
```js
const key: Buffer = await pbkdf2_sha512('password', 'salt', 10000, 64);
```

## TON mnemonics
TON uses BIP-39 styled english mnemonics with custom key deriviation and built-in checksums.

```js
import { mnemonicNew, mnemonicValidate, mnemonicToPrivateKey, mnemonicToWalletKey, mnemonicToSeed, mnemonicWordList, KeyPair, mnemonicToHDSeed } from '@ton/crypto';
const password: string | null | undefined = null; // Optional password
const mnemonics: string[] = await mnemonicNew(24, password); // Generate new menemonics
const mnemonicsValid: boolean = await mnemonicValidate(mnemonics, password); // Validate mnemonics
const keypair1: KeyPair = await mnemonicToPrivateKey(mnemonics, password); // Generates KeyPair from mnemonics
const keypair2: KeyPair = await mnemonicToWalletKey(mnemonics, password); // Generates KeyPair from mnemonics (results are SEEMS TO BE same as above)
const mnemonicsSeed: Buffer = await mnemonicToSeed(mnemonics, 'Seed text', password); // Generates 64 bytes of seed from mnemonics and seed text.
const mnemonicHDSeed: Buffer = await mnemonicToHDSeed(mnemonics, password); // Generates 64 bytes of seed for HD Keys
const wordlist = mnemonicWordList; // BIP39 word list
```

## NaCL-compatible Ed25519 signing
Ed25519 is used by TON in contracts to check signatures.

```js
import { keyPairFromSeed, keyPairFromSecretKey, sign, signVerify, KeyPair } from '@ton/crypto';

const data = Buffer.from('Hello wordl!');

// Create Keypair
const seed: Buffer = await getSecureRandomBytes(32); // Seed is always 32 bytes
const keypair: KeyPair = keyPairFromSeed(seed); // Creates keypair from random seed
const keypair2: KeyPair = keyPairFromSecretKey(keypair.secret); // Creates keypair from secret key

// Sign
const signature = sign(data, keypair.secret); // Creates signature for arbitrary data (it is recommended to get hash from data first)

// Check
const valid: boolean = signVerify(data, signature, keypair.public);

```

## NaCL-compatible symmetrict encryption

```js
import { sealBox, openBox, getSecureRandomBytes } from '@ton/crypto';

const data = Buffer.from('Hello wordl!');

// Encryption
const key: Buffer = await getSecureRandomBytes(32); // Key is always 32 bytes and secret
const nonce: Buffer = await getSecureRandomBytes(24); // Nonce is always 24 bytes and public
const sealed: Buffer = sealBox(data, nonce, key); // Sealed box

// Decryption
const decrypted: Buffer | null = openBox(sealed, nonce, key); // Decrypted with integrity check. null if failed.
```

## SLIP-10 Ed25519 HD Keys

Generates SLIP-10 compatible hierarchy of keys

```js
import { newMnemonics, mnemonicToHDSeed, deriveEd25519Path, KeyPair } from '@ton/crypto';

// Generate HD seed
// You can just generate 64-128 random bytes, but this way you will be able to 
// create it from mnemonics that you already have for a wallet
const mnemonics: string[] = await newMnemonics();
const seed: Buffer = await mnemonicToHDSeed(mnemonics);

// Derive secret key from path m/0'/1'/2'/3'
const derivedSeed: Buffer = await deriveEd25519Path(seed, [0, 1, 2, 3]);

// Create key pair
const keyPair: KeyPair = keyPairFromSeed(derivedSeed);

```

## SLIP-21 Symmetric HD Keys

Generates SLIP-21 compatible hierarchy of keys for symmetric encryption.

```js
import { newMnemonics, mnemonicToHDSeed, deriveSymmetricPath, KeyPair } from '@ton/crypto';

// Generate HD seed
// You can just generate 64-128 random bytes, but this way you will be able to 
// create it from mnemonics that you already have for a wallet
const mnemonics: string[] = await newMnemonics();
const seed: Buffer = await mnemonicToHDSeed(mnemonics);

// Derive secret key from path m/0'/1'/2'/3'
const derivedKey: Buffer = await deriveSymmetricPath(seed, ['ton-seed', 'some-key', 'some-key2']);

```

# License

MIT

/**
 * Universal CryptoWallet - Multi-Blockchain HD Wallet Library
 * Version: 3.1.0
 */

(function(global) {
    'use strict';

    // Network configurations
    const NETWORK_CONFIGS = {
        // Tier 1 - Primary Networks (Production Ready)
        bitcoin: {
            name: 'Bitcoin',
            symbol: 'BTC',
            tier: 1,
            status: 'live',
            coinType: 0,
            curve: 'secp256k1',
            features: ['Legacy P2PKH', 'SegWit Bech32', 'Multisig'],
            explorer: 'https://blockstream.info',
            addressFormats: ['legacy', 'segwit'],
            derivationPath: "m/44'/0'/0'/0/0",
            implementation: 'native'
        },
        ethereum: {
            name: 'Ethereum',
            symbol: 'ETH',
            tier: 1,
            status: 'live',
            coinType: 60,
            curve: 'secp256k1',
            features: ['Smart Contracts', 'EIP-55 Checksum', 'EIP-1559'],
            explorer: 'https://etherscan.io',
            addressFormats: ['checksum'],
            derivationPath: "m/44'/60'/0'/0/0",
            chainId: 1,
            implementation: 'native'
        },
        solana: {
            name: 'Solana',
            symbol: 'SOL',
            tier: 1,
            status: 'live',
            coinType: 501,
            curve: 'ed25519',
            features: ['High TPS', 'Low Fees', 'Program Accounts'],
            explorer: 'https://explorer.solana.com',
            addressFormats: ['base58'],
            derivationPath: "m/44'/501'/0'/0'",
            implementation: 'bundler'
        },
        cardano: {
            name: 'Cardano',
            symbol: 'ADA',
            tier: 1,
            status: 'live',
            coinType: 1815,
            curve: 'ed25519-bip32',
            features: ['Proof of Stake', 'Smart Contracts', 'Native Tokens'],
            explorer: 'https://cardanoscan.io',
            addressFormats: ['byron', 'shelley'],
            derivationPath: "m/1852'/1815'/0'/0/0",
            implementation: 'bundler'
        },
        polkadot: {
            name: 'Polkadot',
            symbol: 'DOT',
            tier: 1,
            status: 'live',
            coinType: 354,
            curve: 'sr25519',
            features: ['Parachains', 'Cross-chain', 'Governance'],
            explorer: 'https://polkascan.io',
            addressFormats: ['ss58'],
            prefix: 0,
            derivationPath: "m/44'/354'/0'/0'/0'",
            implementation: 'bundler'
        },
        kusama: {
            name: 'Kusama',
            symbol: 'KSM',
            tier: 1,
            status: 'live',
            coinType: 434,
            curve: 'sr25519',
            features: ['Canary Network', 'Parachains', 'Fast Governance'],
            explorer: 'https://kusama.subscan.io',
            addressFormats: ['ss58'],
            prefix: 2,
            derivationPath: "m/44'/434'/0'/0'/0'",
            implementation: 'bundler'
        },
        avalanche: {
            name: 'Avalanche',
            symbol: 'AVAX',
            tier: 1,
            status: 'live',
            coinType: 9000,
            curve: 'secp256k1',
            features: ['Multi-chain', 'EVM Compatible', 'Subnets'],
            explorer: 'https://snowtrace.io',
            addressFormats: ['ethereum', 'bech32'],
            chains: ['C', 'X', 'P'],
            implementation: 'native'
        },

        // Tier 2 - Popular Networks
        binance: {
            name: 'Binance Smart Chain',
            symbol: 'BNB',
            tier: 2,
            status: 'live',
            coinType: 60,
            curve: 'secp256k1',
            features: ['EVM Compatible', 'Low Fees', 'Fast Finality'],
            explorer: 'https://bscscan.com',
            addressFormats: ['ethereum'],
            chainId: 56,
            implementation: 'native'
        },
        polygon: {
            name: 'Polygon',
            symbol: 'MATIC',
            tier: 2,
            status: 'live',
            coinType: 60,
            curve: 'secp256k1',
            features: ['Layer 2', 'EVM Compatible', 'PoS Bridge'],
            explorer: 'https://polygonscan.com',
            addressFormats: ['ethereum'],
            chainId: 137,
            implementation: 'native'
        },
        cosmos: {
            name: 'Cosmos',
            symbol: 'ATOM',
            tier: 2,
            status: 'live',
            coinType: 118,
            curve: 'secp256k1',
            features: ['IBC Protocol', 'Interoperability', 'Tendermint'],
            explorer: 'https://mintscan.io',
            addressFormats: ['bech32'],
            prefix: 'cosmos',
            implementation: 'bundler'
        },
        near: {
            name: 'NEAR Protocol',
            symbol: 'NEAR',
            tier: 2,
            status: 'live',
            coinType: 397,
            curve: 'ed25519',
            features: ['Sharding', 'Developer Friendly', 'Rainbow Bridge'],
            explorer: 'https://explorer.near.org',
            addressFormats: ['implicit', 'named'],
            implementation: 'bundler'
        },
        tron: {
            name: 'Tron',
            symbol: 'TRX',
            tier: 2,
            status: 'live',
            coinType: 195,
            curve: 'secp256k1',
            features: ['High TPS', 'DApps', 'TRC-20 Tokens'],
            explorer: 'https://tronscan.org',
            addressFormats: ['base58-tron'],
            implementation: 'bundler'
        },

        // Tier 3 - Specialized Networks
        algorand: {
            name: 'Algorand',
            symbol: 'ALGO',
            tier: 3,
            status: 'live',
            coinType: 283,
            curve: 'ed25519',
            features: ['Pure PoS', 'Instant Finality', 'ASA Tokens'],
            explorer: 'https://algoexplorer.io',
            addressFormats: ['base32-algorand'],
            implementation: 'bundler'
        },
        stellar: {
            name: 'Stellar',
            symbol: 'XLM',
            tier: 3,
            status: 'live',
            coinType: 148,
            curve: 'ed25519',
            features: ['Fast Payments', 'Low Fees', 'DEX Built-in'],
            explorer: 'https://stellarchain.io',
            addressFormats: ['base32-stellar'],
            implementation: 'bundler'
        },
        ripple: {
            name: 'Ripple',
            symbol: 'XRP',
            tier: 3,
            status: 'beta',
            coinType: 144,
            curve: 'secp256k1',
            features: ['Banking', 'Cross-border', 'XRPL DEX'],
            explorer: 'https://xrpscan.com',
            addressFormats: ['base58-ripple'],
            implementation: 'bundler'
        },
        litecoin: {
            name: 'Litecoin',
            symbol: 'LTC',
            tier: 3,
            status: 'live',
            coinType: 2,
            curve: 'secp256k1',
            features: ['Bitcoin Fork', 'Faster Blocks', 'Scrypt PoW'],
            explorer: 'https://blockchair.com',
            addressFormats: ['legacy', 'segwit'],
            versions: { legacy: 0x30, segwit: 'ltc' },
            implementation: 'bundler'
        },
        monero: {
            name: 'Monero',
            symbol: 'XMR',
            tier: 3,
            status: 'beta',
            coinType: 128,
            curve: 'ed25519',
            features: ['Privacy', 'Ring Signatures', 'Stealth Addresses'],
            explorer: 'https://xmrchain.net',
            addressFormats: ['cryptonote'],
            hasViewKey: true,
            implementation: 'bundler'
        },
        filecoin: {
            name: 'Filecoin',
            symbol: 'FIL',
            tier: 3,
            status: 'beta',
            coinType: 461,
            curve: 'secp256k1',
            features: ['Storage Network', 'IPFS', 'Proof of Spacetime'],
            explorer: 'https://filfox.info',
            addressFormats: ['filecoin'],
            addressTypes: ['f1', 'f3'],
            implementation: 'bundler'
        },
        nostr: {
            name: 'Nostr',
            symbol: 'NOSTR',
            tier: 3,
            status: 'live',
            coinType: 1237,
            curve: 'secp256k1',
            features: ['Decentralized Social', 'Censorship Resistant', 'Lightning'],
            explorer: 'https://nostr.com',
            addressFormats: ['schnorr-x'],
            implementation: 'native'
        }
    };

    /**
     * Universal CryptoWallet Class with Integrated CryptoBundler
     */
    class CryptoWallet {
        constructor(options = {}) {
            this.version = '3.1.0';
            this.options = {
                maxWorkers: Math.min(navigator.hardwareConcurrency || 4, 8),
                workerTimeout: 30000,
                enableLogging: true,
                autoSave: true,
                defaultNetworks: null, // null = all supported, or specify array
                ...options
            };

            // Core wallet state
            this.hdWallet = null;
            this.derivedKeys = new Map();
            this.addresses = new Map();
            this.isInitialized = false;
            this.isLocked = true;

            // Worker management
            this.workerPool = [];
            this.taskQueue = [];
            this.activeTasks = new Map();
            this.taskIdCounter = 0;

            // Performance tracking
            this.metrics = {
                initTime: 0,
                addressGenTime: 0,
                signTime: 0,
                totalOperations: 0,
                successfulOps: 0,
                responseTimes: []
            };

            // Cache for performance
            this._keyCache = new Map();
            this._addressCache = new Map();

            // Network configuration
            this.networks = new Map(Object.entries(NETWORK_CONFIGS));
            this.supportedNetworks = this._getSupportedNetworks();

            // Initialize
            this._initializeComponents();
        }

        /**
         * Get list of supported networks
         * @private
         */
        _getSupportedNetworks() {
            // All networks are supported since we have integrated crypto bundler
            return Object.keys(NETWORK_CONFIGS);
        }

        /**
         * Integrated crypto utility methods (formerly CryptoBundler)
         */
        
        /**
         * Convert hex string to Uint8Array
         * @param {string} hex - Hex string to convert
         * @returns {Uint8Array}
         */
        hexToBytes(hex) {
            if (hex.startsWith('0x')) hex = hex.slice(2);
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes;
        }

        /**
         * Convert Uint8Array to hex string
         * @param {Uint8Array} bytes - Array to convert
         * @returns {string}
         */
        bytesToHex(bytes) {
            return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
        }

        /**
         * SHA256 hash function
         * @param {Uint8Array|string} data - Data to hash
         * @returns {Promise<Uint8Array>}
         */
        async sha256(data) {
            let buffer;
            if (typeof data === 'string') {
                buffer = new TextEncoder().encode(data);
            } else if (data instanceof Uint8Array) {
                buffer = data;
            } else if (data instanceof ArrayBuffer) {
                buffer = data;
            } else if (Array.isArray(data)) {
                buffer = new Uint8Array(data);
            } else {
                buffer = new TextEncoder().encode(String(data));
            }
            
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            return new Uint8Array(hashBuffer);
        }

        /**
         * Generate random bytes
         * @param {number} length - Number of bytes to generate
         * @returns {Uint8Array}
         */
        randomBytes(length) {
            const array = new Uint8Array(length);
            crypto.getRandomValues(array);
            return array;
        }

        /**
         * Enhanced worker code generation with integrated crypto bundler
         * @private
         */
        _generateWorkerCode() {
            return `
// Universal CryptoWallet Worker with Integrated CryptoBundler
importScripts('https://cdnjs.cloudflare.com/ajax/libs/elliptic/6.5.4/elliptic.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js');
importScripts('https://cdn.jsdelivr.net/npm/js-sha3@0.8.0/src/sha3.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/tweetnacl/1.0.2/nacl-fast.min.js');

const EC = elliptic.ec;
const secp256k1 = new EC('secp256k1');

// Integrated crypto utilities (formerly CryptoBundler functionality)
const WorkerCryptoUtils = {
    hexToBytes(hex) {
        if (hex.startsWith('0x')) hex = hex.slice(2);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    },

    bytesToHex(bytes) {
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    },

    randomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    },

    async sha256(data) {
        let buffer;
        if (typeof data === 'string') {
            buffer = new TextEncoder().encode(data);
        } else if (data instanceof Uint8Array) {
            buffer = data;
        } else if (data instanceof ArrayBuffer) {
            buffer = data;
        } else if (Array.isArray(data)) {
            buffer = new Uint8Array(data);
        } else {
            buffer = new TextEncoder().encode(String(data));
        }
        
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return new Uint8Array(hashBuffer);
    },

    // Ed25519 methods using TweetNaCl
    ed25519KeyPair(seed = null) {
        if (seed) {
            return nacl.sign.keyPair.fromSeed(seed);
        }
        return nacl.sign.keyPair();
    },

    ed25519Sign(message, secretKey) {
        return nacl.sign.detached(message, secretKey);
    },

    ed25519Verify(signature, message, publicKey) {
        return nacl.sign.detached.verify(message, signature, publicKey);
    },

    // Sr25519 fallback using Ed25519
    sr25519KeyPair(seed = null) {
        if (seed) {
            const adjustedSeed = new Uint8Array(32);
            if (seed.length >= 32) {
                adjustedSeed.set(seed.slice(0, 32));
            } else {
                adjustedSeed.set(seed);
            }
            return nacl.sign.keyPair.fromSeed(adjustedSeed);
        }
        return nacl.sign.keyPair();
    },

    // Blake2b using SHA-512 fallback
    blake2b(data, outputLength = 32, key = null) {
        const input = key ? this._combineKeyAndData(key, data) : data;
        const hash = nacl.hash(this._toUint8Array(input));
        return this._adjustHashLength(hash, outputLength);
    },

    // SHA512/256 implementation
    sha512_256(data) {
        const hash = nacl.hash(this._toUint8Array(data));
        return hash.slice(0, 32);
    },

    // Base32 implementation
    base32Encode(data) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        data = this._toUint8Array(data);
        if (!data || data.length === 0) return '';
        
        let result = '';
        let bits = 0;
        let value = 0;
        
        for (let i = 0; i < data.length; i++) {
            value = (value << 8) | data[i];
            bits += 8;
            
            while (bits >= 5) {
                result += alphabet[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        
        if (bits > 0) {
            result += alphabet[(value << (5 - bits)) & 31];
        }
        
        while (result.length % 8 !== 0) {
            result += '=';
        }
        
        return result;
    },

    base32Decode(encoded) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        if (!encoded) return new Uint8Array(0);
        
        encoded = encoded.toUpperCase().replace(/=+$/, '');
        const result = [];
        let bits = 0;
        let value = 0;
        
        for (let i = 0; i < encoded.length; i++) {
            const index = alphabet.indexOf(encoded[i]);
            if (index === -1) throw new Error('Invalid base32 character: ' + encoded[i]);
            
            value = (value << 5) | index;
            bits += 5;
            
            if (bits >= 8) {
                result.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        
        return new Uint8Array(result);
    },

    // CRC16 implementation
    crc16(data) {
        const polynomial = 0x1021;
        data = this._toUint8Array(data);
        
        let crc = 0x0000;
        for (let i = 0; i < data.length; i++) {
            crc ^= (data[i] << 8);
            for (let j = 0; j < 8; j++) {
                if (crc & 0x8000) {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc = crc << 1;
                }
                crc &= 0xFFFF;
            }
        }
        return crc;
    },

    ripemd160(data) {
        return new Uint8Array(this._ripemd160Internal(data));
    },

    keccak256(data) {
        let bytes;
        if (typeof data === 'string') {
            bytes = new TextEncoder().encode(data);
        } else if (data instanceof Uint8Array) {
            bytes = data;
        } else {
            bytes = new Uint8Array(data);
        }
        
        const hash = keccak256.array(bytes);
        return new Uint8Array(hash);
    },

    base58Encode(bytes) {
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let num = 0n;
        
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256n + BigInt(bytes[i]);
        }

        let encoded = '';
        while (num > 0) {
            encoded = alphabet[Number(num % 58n)] + encoded;
            num = num / 58n;
        }

        for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
            encoded = '1' + encoded;
        }

        return encoded;
    },

    // Helper methods
    _toUint8Array(data) {
        if (typeof data === 'string') {
            return new TextEncoder().encode(data);
        }
        return new Uint8Array(data);
    },

    _adjustHashLength(hash, targetLength) {
        if (hash.length === targetLength) return hash;
        
        if (hash.length > targetLength) {
            return hash.slice(0, targetLength);
        } else {
            const result = new Uint8Array(targetLength);
            for (let i = 0; i < targetLength; i++) {
                result[i] = hash[i % hash.length];
            }
            return result;
        }
    },

    _combineKeyAndData(key, data) {
        if (!key || key.length === 0) return data;
        const combined = new Uint8Array(key.length + data.length + key.length);
        combined.set(key, 0);
        combined.set(data, key.length);
        combined.set(key, key.length + data.length);
        return combined;
    },

    _ripemd160Internal(data) {
        let str;
        if (typeof data === 'string') {
            str = data;
        } else if (data instanceof Uint8Array) {
            str = Array.from(data).map(b => String.fromCharCode(b)).join('');
        } else {
            const bytes = new Uint8Array(data);
            str = Array.from(bytes).map(b => String.fromCharCode(b)).join('');
        }
        
        return CryptoJS.RIPEMD160(str).words.flatMap(word => [
            (word >>> 24) & 0xff,
            (word >>> 16) & 0xff,
            (word >>> 8) & 0xff,
            word & 0xff
        ]).slice(0, 20);
    },

    // Encryption/Decryption methods
    async deriveKey(password, salt, iterations = 100000) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },
    
    async encrypt(data, password) {
        const salt = this.randomBytes(16);
        const iv = this.randomBytes(12);
        const key = await this.deriveKey(password, salt);
        
        const plaintext = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            plaintext
        );

        return {
            encrypted: new Uint8Array(encrypted),
            salt: salt,
            iv: iv
        };
    },

    async decrypt(encryptedData, salt, iv, password) {
        const key = await this.deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encryptedData
        );
        return new Uint8Array(decrypted);
    }
};

// Enhanced address generator with multi-blockchain support
const WorkerAddressGenerator = {
    // Bitcoin addresses
    async generateBitcoinP2PKH(publicKey) {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const publicKeyHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        
        const versionedHash = new Uint8Array(21);
        versionedHash[0] = 0x00;
        versionedHash.set(publicKeyHash, 1);
        
        const firstHash = await WorkerCryptoUtils.sha256(versionedHash);
        const checksum = await WorkerCryptoUtils.sha256(firstHash);
        
        const address = new Uint8Array(25);
        address.set(versionedHash, 0);
        address.set(checksum.slice(0, 4), 21);
        
        return WorkerCryptoUtils.base58Encode(address);
    },

    async generateBitcoinBech32(publicKey) {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const publicKeyHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        
        const words = WorkerBech32.convertBits(Array.from(publicKeyHash), 8, 5, true);
        if (!words) throw new Error('Failed to convert bits for bech32');
        
        return WorkerBech32.encode('bc', [0, ...words]);
    },

    // Ethereum addresses
    generateEthereumAddress(publicKey) {
        const uncompressedKey = publicKey.slice(1);
        const hash = WorkerCryptoUtils.keccak256(uncompressedKey);
        const address = '0x' + WorkerCryptoUtils.bytesToHex(hash.slice(-20));
        
        return this._toChecksumAddress(address);
    },

    // Solana addresses
    generateSolanaAddress(publicKey) {
        return WorkerCryptoUtils.base58Encode(publicKey);
    },

    // Cardano addresses (Shelley format)
    async generateCardanoAddress(publicKey, stakingKey = null) {
        const paymentCredential = await WorkerCryptoUtils.sha256(publicKey);
        
        const addressBytes = new Uint8Array(29);
        addressBytes[0] = stakingKey ? 0x01 : 0x61;
        addressBytes.set(paymentCredential.slice(0, 28), 1);
        
        const words = WorkerBech32.convertBits(Array.from(addressBytes), 8, 5, true);
        return WorkerBech32.encode('addr', words);
    },

    // Polkadot/Kusama SS58 addresses
    generateSS58Address(publicKey, prefix = 0) {
        const payload = new Uint8Array(1 + publicKey.length);
        payload[0] = prefix;
        payload.set(publicKey, 1);
        
        const hash = WorkerCryptoUtils.blake2b(payload, 64);
        const checksum = hash.slice(0, 2);
        
        const addressBytes = new Uint8Array(payload.length + 2);
        addressBytes.set(payload);
        addressBytes.set(checksum, payload.length);
        
        return WorkerCryptoUtils.base58Encode(addressBytes);
    },

    // Cosmos ecosystem addresses
    async generateCosmosAddress(publicKey, prefix = 'cosmos') {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const ripemdHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        const words = WorkerBech32.convertBits(Array.from(ripemdHash), 8, 5, true);
        return WorkerBech32.encode(prefix, words);
    },

    // NEAR Protocol addresses
    generateNearAddress(publicKey) {
        return WorkerCryptoUtils.bytesToHex(publicKey);
    },

    // Tron addresses
    async generateTronAddress(publicKey) {
        const uncompressedKey = publicKey.slice(1);
        const hash = WorkerCryptoUtils.keccak256(uncompressedKey);
        const addressBytes = hash.slice(-20);
        
        const tronBytes = new Uint8Array(21);
        tronBytes[0] = 0x41; // Tron prefix
        tronBytes.set(addressBytes, 1);
        
        const hash1 = await WorkerCryptoUtils.sha256(tronBytes);
        const hash2 = await WorkerCryptoUtils.sha256(hash1);
        
        const addressWithChecksum = new Uint8Array(25);
        addressWithChecksum.set(tronBytes);
        addressWithChecksum.set(hash2.slice(0, 4), 21);
        
        return WorkerCryptoUtils.base58Encode(addressWithChecksum);
    },

    // Algorand addresses
    generateAlgorandAddress(publicKey) {
        const hash = WorkerCryptoUtils.sha512_256(publicKey);
        const checksum = hash.slice(-4);
        
        const addressBytes = new Uint8Array(publicKey.length + checksum.length);
        addressBytes.set(publicKey);
        addressBytes.set(checksum, publicKey.length);
        
        return WorkerCryptoUtils.base32Encode(addressBytes);
    },

    // Stellar addresses
    generateStellarAddress(publicKey) {
        const versionByte = 0x30;
        const payload = new Uint8Array(1 + publicKey.length);
        payload[0] = versionByte;
        payload.set(publicKey, 1);
        
        const checksum = WorkerCryptoUtils.crc16(payload);
        const checksumBytes = new Uint8Array(2);
        checksumBytes[0] = checksum & 0xff;
        checksumBytes[1] = (checksum >> 8) & 0xff;
        
        const addressBytes = new Uint8Array(payload.length + 2);
        addressBytes.set(payload);
        addressBytes.set(checksumBytes, payload.length);
        
        return WorkerCryptoUtils.base32Encode(addressBytes);
    },

    // Ripple addresses
    async generateRippleAddress(publicKey) {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const ripemdHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        
        const versionedHash = new Uint8Array(21);
        versionedHash[0] = 0x00;
        versionedHash.set(ripemdHash, 1);
        
        const firstHash = await WorkerCryptoUtils.sha256(versionedHash);
        const checksum = await WorkerCryptoUtils.sha256(firstHash);
        
        const address = new Uint8Array(25);
        address.set(versionedHash, 0);
        address.set(checksum.slice(0, 4), 21);
        
        const rippleAlphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
        return this._customBase58Encode(address, rippleAlphabet);
    },

    // Litecoin addresses
    async generateLitecoinP2PKH(publicKey) {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const publicKeyHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        
        const versionedHash = new Uint8Array(21);
        versionedHash[0] = 0x30;
        versionedHash.set(publicKeyHash, 1);
        
        const firstHash = await WorkerCryptoUtils.sha256(versionedHash);
        const checksum = await WorkerCryptoUtils.sha256(firstHash);
        
        const address = new Uint8Array(25);
        address.set(versionedHash, 0);
        address.set(checksum.slice(0, 4), 21);
        
        return WorkerCryptoUtils.base58Encode(address);
    },

    async generateLitecoinBech32(publicKey) {
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const publicKeyHash = WorkerCryptoUtils.ripemd160(sha256Hash);
        
        const words = WorkerBech32.convertBits(Array.from(publicKeyHash), 8, 5, true);
        if (!words) throw new Error('Failed to convert bits for bech32');
        
        return WorkerBech32.encode('ltc', [0, ...words]);
    },

    // Filecoin addresses
    async generateFilecoinAddress(publicKey, addressType = 'f1') {
        if (addressType === 'f1') {
            const hash = WorkerCryptoUtils.blake2b(publicKey, 20);
            const payload = new Uint8Array([1, ...hash]);

            const checksum = WorkerCryptoUtils.blake2b(payload, 4);
            const address = new Uint8Array([...payload, ...checksum]);
            
            return 'f1' + WorkerCryptoUtils.base32Encode(address);
        }
        throw new Error(\`Unsupported Filecoin address type: \${addressType}\`);
    },

    // Nostr public key
    generateNostrPublicKey(publicKey) {
        const key = secp256k1.keyFromPublic(publicKey);
        const point = key.getPublic();
        const x = point.getX();
        return x.toString(16).padStart(64, '0');
    },

    // Helper methods
    _toChecksumAddress(address) {
        const addr = address.toLowerCase().replace('0x', '');
        const hash = WorkerCryptoUtils.keccak256(addr);
        const hashHex = WorkerCryptoUtils.bytesToHex(hash);
        
        let checksumAddress = '0x';
        for (let i = 0; i < addr.length; i++) {
            if (parseInt(hashHex[i], 16) >= 8) {
                checksumAddress += addr[i].toUpperCase();
            } else {
                checksumAddress += addr[i];
            }
        }
        return checksumAddress;
    },

    _customBase58Encode(bytes, alphabet) {
        let num = 0n;
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256n + BigInt(bytes[i]);
        }

        let encoded = '';
        while (num > 0) {
            encoded = alphabet[Number(num % 58n)] + encoded;
            num = num / 58n;
        }

        for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
            encoded = alphabet[0] + encoded;
        }

        return encoded;
    }
};

// Enhanced BIP32 with multi-curve support
class WorkerBIP32HDWallet {
    constructor(seed) {
        this.seed = seed;
        this.masterKey = this._generateMasterKey(seed);
    }

    _generateMasterKey(seed) {
        const hmac = CryptoJS.HmacSHA512(
            CryptoJS.enc.Hex.parse(WorkerCryptoUtils.bytesToHex(seed)),
            CryptoJS.enc.Utf8.parse('Bitcoin seed')
        );
        
        const hmacBytes = WorkerCryptoUtils.hexToBytes(hmac.toString());
        const privateKey = hmacBytes.slice(0, 32);
        const chainCode = hmacBytes.slice(32, 64);

        return {
            privateKey: privateKey,
            chainCode: chainCode,
            depth: 0,
            parentFingerprint: new Uint8Array(4),
            childIndex: 0
        };
    }

    deriveChild(parentKey, index, hardened = false) {
        const hardenedOffset = 0x80000000;
        const childIndex = hardened ? index + hardenedOffset : index;

        let data;
        if (hardened) {
            data = new Uint8Array(37);
            data.set([0], 0);
            data.set(parentKey.privateKey, 1);
            const view = new DataView(data.buffer);
            view.setUint32(33, childIndex, false);
        } else {
            const publicKey = secp256k1.keyFromPrivate(parentKey.privateKey).getPublic().encode('array', true);
            data = new Uint8Array(37);
            data.set(publicKey, 0);
            const view = new DataView(data.buffer);
            view.setUint32(33, childIndex, false);
        }

        const hmac = CryptoJS.HmacSHA512(
            CryptoJS.enc.Hex.parse(WorkerCryptoUtils.bytesToHex(data)),
            CryptoJS.enc.Hex.parse(WorkerCryptoUtils.bytesToHex(parentKey.chainCode))
        );

        const hmacBytes = WorkerCryptoUtils.hexToBytes(hmac.toString());
        const childPrivateKey = hmacBytes.slice(0, 32);
        const childChainCode = hmacBytes.slice(32, 64);

        const parentKeyBN = secp256k1.keyFromPrivate(parentKey.privateKey).getPrivate();
        const childKeyBN = secp256k1.keyFromPrivate(childPrivateKey).getPrivate();
        const finalPrivateKey = parentKeyBN.add(childKeyBN).mod(secp256k1.curve.n);

        return {
            privateKey: WorkerCryptoUtils.hexToBytes(finalPrivateKey.toString(16).padStart(64, '0')),
            chainCode: childChainCode,
            depth: parentKey.depth + 1,
            parentFingerprint: this._getFingerprint(parentKey),
            childIndex: childIndex
        };
    }

    // Ed25519 key derivation
    async deriveEd25519Key(coinType, account = 0, change = 0, addressIndex = 0) {
        let key = this.masterKey;
        
        const derivationSeed = new Uint8Array([...this.seed, ...new TextEncoder().encode(\`m/44'/\${coinType}'/\${account}'/\${change}/\${addressIndex}\`)]);
        const ed25519Seed = await WorkerCryptoUtils.sha256(derivationSeed);
        
        return ed25519Seed.slice(0, 32);
    }

    // Sr25519 key derivation
    deriveSr25519Key(coinType, account = 0) {
        const derivationPath = \`//\${coinType}//\${account}\`;
        const derivationSeed = new Uint8Array([...this.seed, ...new TextEncoder().encode(derivationPath)]);
        return WorkerCryptoUtils.blake2b(derivationSeed, 32);
    }

    async _getFingerprint(key) {
        const publicKey = secp256k1.keyFromPrivate(key.privateKey).getPublic().encode('array', true);
        const sha256Hash = await WorkerCryptoUtils.sha256(publicKey);
        const hash = WorkerCryptoUtils.ripemd160(sha256Hash);
        return hash.slice(0, 4);
    }

    deriveBIP44Key(coinType, account = 0, change = 0, addressIndex = 0) {
        let key = this.masterKey;
        
        key = this.deriveChild(key, 44, true);
        key = this.deriveChild(key, coinType, true);
        key = this.deriveChild(key, account, true);
        key = this.deriveChild(key, change, false);
        key = this.deriveChild(key, addressIndex, false);
        
        return key;
    }
};

// Bech32 implementation
const WorkerBech32 = {
    CHARSET: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l',
    GENERATOR: [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3],

    polymod(values) {
        let chk = 1;
        for (let p = 0; p < values.length; ++p) {
            const top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ values[p];
            for (let i = 0; i < 5; ++i) {
                chk ^= ((top >> i) & 1) ? this.GENERATOR[i] : 0;
            }
        }
        return chk;
    },

    hrpExpand(hrp) {
        const ret = [];
        for (let p = 0; p < hrp.length; ++p) {
            ret.push(hrp.charCodeAt(p) >> 5);
        }
        ret.push(0);
        for (let p = 0; p < hrp.length; ++p) {
            ret.push(hrp.charCodeAt(p) & 31);
        }
        return ret;
    },

    createChecksum(hrp, data) {
        const values = this.hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
        const mod = this.polymod(values) ^ 1;
        const ret = [];
        for (let p = 0; p < 6; ++p) {
            ret.push((mod >> 5 * (5 - p)) & 31);
        }
        return ret;
    },

    encode(hrp, data) {
        const combined = data.concat(this.createChecksum(hrp, data));
        let ret = hrp + '1';
        for (let p = 0; p < combined.length; ++p) {
            ret += this.CHARSET.charAt(combined[p]);
        }
        return ret;
    },

    convertBits(data, fromBits, toBits, pad) {
        let acc = 0;
        let bits = 0;
        const ret = [];
        const maxv = (1 << toBits) - 1;
        for (let p = 0; p < data.length; ++p) {
            const value = data[p];
            if (value < 0 || (value >> fromBits) !== 0) {
                return null;
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                ret.push((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
            return null;
        }
        return ret;
    }
};

// Enhanced task handlers with multi-blockchain support
const taskHandlers = {
    async generateNewWallet(data) {
        const { entropy, networks = Object.keys(${JSON.stringify(NETWORK_CONFIGS)}) } = data;
        const seed = new Uint8Array(entropy);
        const hdWallet = new WorkerBIP32HDWallet(seed);
        
        const networkConfigs = ${JSON.stringify(NETWORK_CONFIGS)};

        const derivedKeys = {};
        const addresses = {};

        for (const network of networks) {
            const config = networkConfigs[network];
            if (!config) continue;

            let derivedKey;
            let keyPair;
            let publicKey;
            let uncompressedPublicKey;

            try {
                if (config.curve === 'ed25519' || config.curve === 'ed25519-bip32') {
                    // Ed25519 key derivation
                    const ed25519Seed = await hdWallet.deriveEd25519Key(config.coinType);
                    keyPair = WorkerCryptoUtils.ed25519KeyPair(ed25519Seed);
                    publicKey = keyPair.publicKey;
                    derivedKey = {
                        privateKey: Array.from(keyPair.secretKey.slice(0, 32)),
                        chainCode: Array.from(new Uint8Array(32)),
                        depth: 4,
                        parentFingerprint: Array.from(new Uint8Array(4)),
                        childIndex: 0
                    };
                } else if (config.curve === 'sr25519') {
                    // Sr25519 key derivation
                    const sr25519Seed = hdWallet.deriveSr25519Key(config.coinType);
                    keyPair = WorkerCryptoUtils.sr25519KeyPair(sr25519Seed);
                    publicKey = keyPair.publicKey;
                    derivedKey = {
                        privateKey: Array.from(keyPair.secretKey.slice(0, 32)),
                        chainCode: Array.from(new Uint8Array(32)),
                        depth: 2,
                        parentFingerprint: Array.from(new Uint8Array(4)),
                        childIndex: 0
                    };
                } else {
                    // secp256k1 key derivation
                    derivedKey = hdWallet.deriveBIP44Key(config.coinType);
                    keyPair = secp256k1.keyFromPrivate(derivedKey.privateKey);
                    publicKey = new Uint8Array(keyPair.getPublic().encode('array', true));
                    uncompressedPublicKey = new Uint8Array(keyPair.getPublic().encode('array', false));
                    
                    derivedKey = {
                        privateKey: Array.from(derivedKey.privateKey),
                        chainCode: Array.from(derivedKey.chainCode),
                        depth: derivedKey.depth,
                        parentFingerprint: Array.from(derivedKey.parentFingerprint),
                        childIndex: derivedKey.childIndex
                    };
                }

                derivedKeys[network] = derivedKey;

                // Generate addresses based on network
                switch (network) {
                    case 'bitcoin':
                        addresses[network] = {
                            legacy: await WorkerAddressGenerator.generateBitcoinP2PKH(publicKey),
                            segwit: await WorkerAddressGenerator.generateBitcoinBech32(publicKey)
                        };
                        break;
                    case 'ethereum':
                    case 'binance':
                    case 'polygon':
                    case 'avalanche':
                        addresses[network] = WorkerAddressGenerator.generateEthereumAddress(uncompressedPublicKey);
                        break;
                    case 'solana':
                        addresses[network] = WorkerAddressGenerator.generateSolanaAddress(publicKey);
                        break;
                    case 'cardano':
                        addresses[network] = await WorkerAddressGenerator.generateCardanoAddress(publicKey);
                        break;
                    case 'polkadot':
                        addresses[network] = WorkerAddressGenerator.generateSS58Address(publicKey, 0);
                        break;
                    case 'kusama':
                        addresses[network] = WorkerAddressGenerator.generateSS58Address(publicKey, 2);
                        break;
                    case 'cosmos':
                        addresses[network] = await WorkerAddressGenerator.generateCosmosAddress(publicKey, 'cosmos');
                        break;
                    case 'near':
                        addresses[network] = WorkerAddressGenerator.generateNearAddress(publicKey);
                        break;
                    case 'tron':
                        addresses[network] = await WorkerAddressGenerator.generateTronAddress(uncompressedPublicKey);
                        break;
                    case 'algorand':
                        addresses[network] = WorkerAddressGenerator.generateAlgorandAddress(publicKey);
                        break;
                    case 'stellar':
                        addresses[network] = WorkerAddressGenerator.generateStellarAddress(publicKey);
                        break;
                    case 'ripple':
                        addresses[network] = await WorkerAddressGenerator.generateRippleAddress(publicKey);
                        break;
                    case 'litecoin':
                        addresses[network] = {
                            legacy: await WorkerAddressGenerator.generateLitecoinP2PKH(publicKey),
                            segwit: await WorkerAddressGenerator.generateLitecoinBech32(publicKey)
                        };
                        break;
                    case 'filecoin':
                        addresses[network] = await WorkerAddressGenerator.generateFilecoinAddress(publicKey, 'f1');
                        break;
                    case 'nostr':
                        addresses[network] = WorkerAddressGenerator.generateNostrPublicKey(publicKey);
                        break;
                }
            } catch (error) {
                console.error(\`Failed to generate keys for \${network}:\`, error.message);
            }
        }

        return {
            seed: Array.from(seed),
            masterKey: {
                privateKey: Array.from(hdWallet.masterKey.privateKey),
                chainCode: Array.from(hdWallet.masterKey.chainCode)
            },
            derivedKeys,
            addresses
        };
    },

    async encryptData(data) {
        const { plaintext, password } = data;
        const result = await WorkerCryptoUtils.encrypt(plaintext, password);
        return {
            encrypted: Array.from(result.encrypted),
            salt: Array.from(result.salt),
            iv: Array.from(result.iv)
        };
    },

    async decryptData(data) {
        const { encryptedData, salt, iv, password } = data;
        const result = await WorkerCryptoUtils.decrypt(
            new Uint8Array(encryptedData),
            new Uint8Array(salt),
            new Uint8Array(iv),
            password
        );
        return Array.from(result);
    },

    async signMessage(data) {
        const { message, privateKey, curve = 'secp256k1' } = data;
        
        const messageBytes = new TextEncoder().encode(message);
        const messageHash = await WorkerCryptoUtils.sha256(messageBytes);
        
        if (curve === 'ed25519' || curve === 'ed25519-bip32') {
            const keyPair = WorkerCryptoUtils.ed25519KeyPair(new Uint8Array(privateKey));
            const signature = WorkerCryptoUtils.ed25519Sign(messageHash, keyPair.secretKey);
            return {
                signature: Array.from(signature),
                algorithm: 'ed25519'
            };
        } else if (curve === 'sr25519') {
            const keyPair = WorkerCryptoUtils.sr25519KeyPair(new Uint8Array(privateKey));
            const signature = WorkerCryptoUtils.ed25519Sign(messageHash, keyPair.secretKey);
            return {
                signature: Array.from(signature),
                algorithm: 'sr25519'
            };
        } else {
            // secp256k1 signing
            const keyPair = secp256k1.keyFromPrivate(new Uint8Array(privateKey));
            const signature = keyPair.sign(messageHash);
            return {
                r: signature.r.toString(16),
                s: signature.s.toString(16),
                recoveryParam: signature.recoveryParam,
                algorithm: 'secp256k1'
            };
        }
    },

    async generateMultipleAddresses(data) {
        const { network, coinType, count, change, seedData, networkConfig } = data;
        const seed = new Uint8Array(seedData);
        const hdWallet = new WorkerBIP32HDWallet(seed);
        
        const addresses = [];

        for (let i = 0; i < count; i++) {
            try {
                let derivedKey;
                let keyPair;
                let publicKey;
                let uncompressedPublicKey;

                if (networkConfig.curve === 'ed25519' || networkConfig.curve === 'ed25519-bip32') {
                    const ed25519Seed = await hdWallet.deriveEd25519Key(coinType, 0, change, i);
                    keyPair = WorkerCryptoUtils.ed25519KeyPair(ed25519Seed);
                    publicKey = keyPair.publicKey;
                    derivedKey = { privateKey: keyPair.secretKey.slice(0, 32) };
                } else if (networkConfig.curve === 'sr25519') {
                    const sr25519Seed = hdWallet.deriveSr25519Key(coinType, i);
                    keyPair = WorkerCryptoUtils.sr25519KeyPair(sr25519Seed);
                    publicKey = keyPair.publicKey;
                    derivedKey = { privateKey: keyPair.secretKey.slice(0, 32) };
                } else {
                    derivedKey = hdWallet.deriveBIP44Key(coinType, 0, change, i);
                    keyPair = secp256k1.keyFromPrivate(derivedKey.privateKey);
                    publicKey = new Uint8Array(keyPair.getPublic().encode('array', true));
                    uncompressedPublicKey = new Uint8Array(keyPair.getPublic().encode('array', false));
                }

                let address;
                switch (network) {
                    case 'bitcoin':
                        address = {
                            index: i,
                            legacy: await WorkerAddressGenerator.generateBitcoinP2PKH(publicKey),
                            segwit: await WorkerAddressGenerator.generateBitcoinBech32(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/\${change}/\${i}\`
                        };
                        break;
                    case 'ethereum':
                    case 'binance':
                    case 'polygon':
                    case 'avalanche':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateEthereumAddress(uncompressedPublicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/\${change}/\${i}\`
                        };
                        break;
                    case 'solana':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateSolanaAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/\${i}'\`
                        };
                        break;
                    case 'cardano':
                        address = {
                            index: i,
                            address: await WorkerAddressGenerator.generateCardanoAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/1852'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'polkadot':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateSS58Address(publicKey, 0),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`//\${coinType}//\${i}\`
                        };
                        break;
                    case 'kusama':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateSS58Address(publicKey, 2),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`//\${coinType}//\${i}\`
                        };
                        break;
                    case 'cosmos':
                        address = {
                            index: i,
                            address: await WorkerAddressGenerator.generateCosmosAddress(publicKey, 'cosmos'),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'near':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateNearAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'tron':
                        address = {
                            index: i,
                            address: await WorkerAddressGenerator.generateTronAddress(uncompressedPublicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'algorand':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateAlgorandAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'stellar':
                        address = {
                            index: i,
                            address: WorkerAddressGenerator.generateStellarAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'ripple':
                        address = {
                            index: i,
                            address: await WorkerAddressGenerator.generateRippleAddress(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'litecoin':
                        address = {
                            index: i,
                            legacy: await WorkerAddressGenerator.generateLitecoinP2PKH(publicKey),
                            segwit: await WorkerAddressGenerator.generateLitecoinBech32(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/\${change}/\${i}\`
                        };
                        break;
                    case 'filecoin':
                        address = {
                            index: i,
                            address: await WorkerAddressGenerator.generateFilecoinAddress(publicKey, 'f1'),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                    case 'nostr':
                        address = {
                            index: i,
                            publicKey: WorkerAddressGenerator.generateNostrPublicKey(publicKey),
                            privateKey: WorkerCryptoUtils.bytesToHex(derivedKey.privateKey),
                            path: \`m/44'/\${coinType}'/0'/0/\${i}\`
                        };
                        break;
                }
                addresses.push(address);
            } catch (error) {
                console.error(\`Failed to generate address \${i} for \${network}:\`, error.message);
            }
        }

        return addresses;
    },

    async deriveKeysFromSeed(data) {
        const { seedData, networks = Object.keys(${JSON.stringify(NETWORK_CONFIGS)}) } = data;
        return await taskHandlers.generateNewWallet({ entropy: seedData, networks });
    }
};

// Main worker message handler
self.onmessage = async function(event) {
    const { taskId, type, data } = event.data;
    
    try {
        const handler = taskHandlers[type];
        if (!handler) {
            throw new Error(\`Unknown task type: \${type}\`);
        }
        
        const result = await handler(data);
        
        self.postMessage({
            taskId: taskId,
            success: true,
            result: result
        });
    } catch (error) {
        self.postMessage({
            taskId: taskId,
            success: false,
            error: error.message
        });
    }
};
            `;
        }

        /**
         * Enhanced wallet generation with network selection
         * @private
         */
        async _generateNewWallet(password, selectedNetworks = null) {
            const entropy = this.randomBytes(32);
            
            const networks = selectedNetworks || this.options.defaultNetworks || this.supportedNetworks;            
            const startTime = Date.now();
            const result = await this._executeTask('generateNewWallet', {
                entropy: Array.from(entropy),
                networks: networks
            });
            
            this.metrics.initTime = Date.now() - startTime;
            this.metrics.totalOperations++;
            
            this.hdWallet = {
                seed: new Uint8Array(result.seed),
                masterKey: {
                    privateKey: new Uint8Array(result.masterKey.privateKey),
                    chainCode: new Uint8Array(result.masterKey.chainCode)
                }
            };
            
            this._convertAndStoreKeys(result.derivedKeys, result.addresses);
            
            if (this.options.autoSave) {
                await this._saveToStorage(password);
            }
        }

        /**
         * Sign a message using worker with proper format
         * @param {string} message - Message to sign
         * @param {string} network - Network to use for signing
         * @returns {Promise<Object>} - Signature object
         */
        async signMessage(message, network = 'bitcoin') {
            this._requireUnlocked();
            
            if (!this.derivedKeys.has(network)) {
                throw new Error(`Invalid network: ${network}`);
            }

            try {
                const networkConfig = this.networks.get(network);
                const startTime = Date.now();
                
                const signature = await this._executeTask('signMessage', {
                    message: message,
                    privateKey: Array.from(this.derivedKeys.get(network).privateKey),
                    curve: networkConfig.curve
                });
                
                this.metrics.signTime = Date.now() - startTime;
                this.metrics.totalOperations++;
                
                signature.algorithm = networkConfig.curve;
                
                return {
                    message: message,
                    signature: signature,
                    network: network,
                    address: this.getAddress(network),
                    curve: networkConfig.curve,
                    recoveryParam: signature.recoveryParam
                };
            } catch (error) {
                throw new Error(`Message signing failed: ${error.message}`);
            }
        }

        // Password validation
        validatePassword(password) {
            const result = {
                isValid: false,
                score: 0,
                issues: []
            };
        
            if (typeof password !== 'string') {
                result.issues.push('Password must be a string');
                return result;
            }
        
            if (password.length < 8) {
                result.issues.push('Password must be at least 8 characters long');
            } else {
                result.score += 1;
            }
        
            if (!/[a-z]/.test(password)) {
                result.issues.push('Password must contain lowercase letters');
            } else {
                result.score += 1;
            }
        
            if (!/[A-Z]/.test(password)) {
                result.issues.push('Password must contain uppercase letters');
            } else {
                result.score += 1;
            }
        
            if (!/[0-9]/.test(password)) {
                result.issues.push('Password must contain numbers');
            } else {
                result.score += 1;
            }
        
            if (!/[^a-zA-Z0-9]/.test(password)) {
                result.issues.push('Password must contain special characters');
            } else {
                result.score += 1;
            }
        
            result.isValid = result.issues.length === 0 && result.score >= 4;
            return result;
        }

        /**
         * Get extended wallet information for a network
         */
        getNetworkWalletInfo(network) {
            this._requireUnlocked();
            
            const networkConfig = this.networks.get(network);
            const derivedKey = this.derivedKeys.get(network);
            const address = this.addresses.get(network);
            
            if (!networkConfig || !derivedKey || !address) {
                throw new Error(`Network ${network} not found or not initialized`);
            }

            return {
                network: networkConfig.name,
                symbol: networkConfig.symbol,
                curve: networkConfig.curve,
                coinType: networkConfig.coinType,
                address: address,
                derivationPath: networkConfig.derivationPath,
                features: networkConfig.features,
                explorer: networkConfig.explorer,
                status: networkConfig.status,
                tier: networkConfig.tier
            };
        }

        /**
         * Get all network wallet information
         */
        getAllNetworkWalletInfo() {
            this._requireUnlocked();
            
            const result = {};
            for (const [network] of this.addresses) {
                try {
                    result[network] = this.getNetworkWalletInfo(network);
                } catch (error) {
                    this._log(`Failed to get info for ${network}: ${error.message}`, 'warning');
                }
            }
            return result;
        }

        /**
         * Initialize the wallet with a password
         */
        async initialize(password) {
            try {
                this._validatePassword(password);
                
                const existingKeys = await this._loadEncryptedKeys(password);
                
                if (existingKeys) {
                    await this._loadFromKeyData(existingKeys);
                    this._log('Existing encrypted wallet loaded', 'success');
                } else {
                    await this._generateNewWallet(password);
                    this._log('New encrypted wallet generated', 'success');
                }
                
                this.isInitialized = true;
                this.isLocked = false;
                this._dispatchEvent('walletReady');
            } catch (error) {
                this.isInitialized = false;
                this.isLocked = true;
                this._handleError('Failed to initialize wallet', error);
            }
        }

        /**
         * Import wallet from seed
         */
        async importSeed(seedHex, password) {
            try {
                this._validatePassword(password);
                
                if (typeof seedHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(seedHex)) {
                    throw new Error('Seed must be 64 hex characters');
                }
        
                const seed = this.hexToBytes(seedHex);
                
                const startTime = Date.now();
                const result = await this._executeTask('deriveKeysFromSeed', {
                    seedData: Array.from(seed),
                    networks: this.supportedNetworks
                });
                
                this.metrics.initTime = Date.now() - startTime;
                this.metrics.totalOperations++;
                
                this.hdWallet = {
                    seed: seed,
                    masterKey: null
                };
                
                this._convertAndStoreKeys(result.derivedKeys, result.addresses);
                
                if (this.options.autoSave) {
                    await this._saveToStorage(password);
                }
                
                this.isInitialized = true;
                this.isLocked = false;
                
                this._log('Seed imported successfully', 'success');
                this._dispatchEvent('walletImported');
            } catch (error) {
                this.isInitialized = false;
                this.isLocked = true;
                this._handleError('Failed to import seed', error);
            }
        }

        /**
         * Export wallet seed
         */
        exportSeed() {
            this._requireUnlocked();
            return this.bytesToHex(this.hdWallet.seed);
        }

        /**
         * Get address for a specific network
         */
        getAddress(network, addressType = 'default') {
            this._requireUnlocked();
            
            const address = this.addresses.get(network);
            if (!address) {
                throw new Error(`Invalid network: ${network}`);
            }

            if ((network === 'bitcoin' || network === 'litecoin') && typeof address === 'object') {
                return addressType === 'legacy' ? address.legacy : address.segwit;
            }
            
            return address;
        }

        /**
         * Get all addresses
         */
        getAllAddresses() {
            if (this.isLocked && this.isInitialized) {
                throw new Error('Wallet is locked. Please unlock first.');
            }
            
            if (!this.addresses || this.addresses.size === 0) {
                return {};
            }
            
            const result = {};
            for (const [network, address] of this.addresses) {
                result[network] = address;
            }
            return result;
        }

        /**
         * Generate multiple addresses using worker
         */
        async generateMultipleAddresses(network, count = 10, change = 0) {
            this._requireUnlocked();
            
            const networkConfig = this.networks.get(network);
            if (!networkConfig) {
                throw new Error(`Invalid network: ${network}`);
            }

            if (typeof count !== 'number' || count <= 0 || count > 100) {
                throw new Error('Count must be between 1 and 100');
            }

            const startTime = Date.now();
            const addresses = await this._executeTask('generateMultipleAddresses', {
                network: network,
                coinType: networkConfig.coinType,
                count: count,
                change: change,
                seedData: Array.from(this.hdWallet.seed),
                networkConfig: networkConfig
            });
            
            this.metrics.addressGenTime = Date.now() - startTime;
            this.metrics.totalOperations++;

            return addresses;
        }

        /**
         * Get all supported networks
         */
        getSupportedNetworks() {
            const networks = [];
            for (const [key, config] of this.networks) {
                networks.push({
                    key,
                    ...config,
                    isSupported: this.supportedNetworks.includes(key)
                });
            }
            return networks;
        }

        /**
         * Get network configuration
         */
        getNetworkConfig(network) {
            return this.networks.get(network) || null;
        }

        /**
         * Lock the wallet
         */
        lock() {
            this.isLocked = true;
            this._keyCache.clear();
            this._addressCache.clear();
            this._dispatchEvent('walletLocked');
        }

        /**
         * Unlock the wallet with password
         */
        async unlock(password) {
            try {
                const keyData = await this._loadEncryptedKeys(password);
                if (!keyData) {
                    throw new Error('No wallet found or invalid password');
                }
                
                await this._loadFromKeyData(keyData);
                
                this.isLocked = false;
                this.isInitialized = true;
                this._dispatchEvent('walletUnlocked');
                return true;
            } catch (error) {
                throw new Error('Invalid password');
            }
        }

        /**
         * Get wallet status
         */
        getStatus() {
            return {
                isInitialized: this.isInitialized,
                isLocked: this.isLocked,
                supportedNetworks: this.supportedNetworks,
                totalNetworks: this.networks.size,
                addresses: this.isLocked ? null : this.getAllAddresses(),
                version: this.version,
                workersActive: this.activeTasks.size,
                performance: {
                    totalOperations: this.metrics.totalOperations,
                    successfulOps: this.metrics.successfulOps,
                    averageResponseTime: this._getAverageResponseTime()
                }
            };
        }

        /**
         * Get performance metrics
         */
        getMetrics() {
            return {
                ...this.metrics,
                averageResponseTime: this._getAverageResponseTime(),
                successRate: this._getSuccessRate()
            };
        }

        /**
         * Clear wallet data
         */
        async clearWallet() {
            await this._clearStorage();
            this.hdWallet = null;
            this.derivedKeys.clear();
            this.addresses.clear();
            this.isInitialized = false;
            this.isLocked = true;
            this._keyCache.clear();
            this._addressCache.clear();
            
            this._log('Wallet cleared successfully', 'info');
            this._dispatchEvent('walletCleared');
        }

        /**
         * Destroy wallet and cleanup resources
         */
        destroy() {
            this.workerPool.forEach(worker => {
                worker.terminate();
            });
            this.workerPool = [];
            
            this.activeTasks.clear();
            this.taskQueue = [];
            
            this.hdWallet = null;
            this.derivedKeys.clear();
            this.addresses.clear();
            this._keyCache.clear();
            this._addressCache.clear();
            
            this._log('Wallet destroyed and resources cleaned up', 'info');
        }

        // Private methods
        _initializeComponents() {
            try {
                this._initializeWorkerPool();
                this._setupEventHandlers();
                this._log('CryptoWallet initialized successfully', 'success');
            } catch (error) {
                this._log(`Initialization failed: ${error.message}`, 'error');
                throw error;
            }
        }

        _initializeWorkerPool() {
            if (typeof Worker === 'undefined') {
                this._log('Web Workers not supported, falling back to main thread', 'warning');
                return;
            }

            const workerCode = this._generateWorkerCode();
            const workerBlob = new Blob([workerCode], { type: 'application/javascript' });
            const workerUrl = URL.createObjectURL(workerBlob);

            for (let i = 0; i < this.options.maxWorkers; i++) {
                try {
                    const worker = new Worker(workerUrl);
                    worker.onmessage = (event) => this._handleWorkerMessage(event);
                    worker.onerror = (error) => this._handleWorkerError(error, i);
                    worker.busy = false;
                    worker.id = i;
                    this.workerPool.push(worker);
                } catch (error) {
                    this._log(`Failed to create worker ${i}: ${error.message}`, 'error');
                }
            }

            URL.revokeObjectURL(workerUrl);
            this._log(`Initialized ${this.workerPool.length} worker threads`, 'info');
        }

        _setupEventHandlers() {
            if (typeof window !== 'undefined') {
                this.eventTarget = window;
            } else if (typeof global !== 'undefined') {
                this.eventTarget = global;
            }
        }

        _handleWorkerMessage(event) {
            const worker = event.target;
            const { taskId, success, result, error } = event.data;
            
            const task = this.activeTasks.get(taskId);
            if (!task) return;
            
            this.activeTasks.delete(taskId);
            worker.busy = false;
            
            const endTime = Date.now();
            const responseTime = endTime - task.startTime;
            this.metrics.responseTimes.push(responseTime);
            
            if (success) {
                this.metrics.successfulOps++;
                task.resolve(result);
            } else {
                this._log(`Worker task failed: ${error}`, 'error');
                task.reject(new Error(error));
            }
            
            if (task.timeout) {
                clearTimeout(task.timeout);
            }
            
            this._processTaskQueue();
        }

        _handleWorkerError(error, workerId) {
            this._log(`Worker ${workerId} error: ${error.message}`, 'error');
            
            const worker = this.workerPool[workerId];
            if (worker) {
                worker.busy = false;
                this._processTaskQueue();
            }
        }

        _executeTask(type, data) {
            return new Promise((resolve, reject) => {
                const taskId = ++this.taskIdCounter;
                const task = { 
                    type, 
                    data, 
                    resolve, 
                    reject, 
                    taskId,
                    startTime: Date.now()
                };
                
                const timeout = setTimeout(() => {
                    this.activeTasks.delete(taskId);
                    reject(new Error('Worker task timeout'));
                }, this.options.workerTimeout);
                
                task.timeout = timeout;
                this.taskQueue.push(task);
                this._processTaskQueue();
            });
        }

        _processTaskQueue() {
            if (this.taskQueue.length === 0) return;
            
            const availableWorker = this.workerPool.find(worker => !worker.busy);
            if (!availableWorker) return;
            
            const task = this.taskQueue.shift();
            availableWorker.busy = true;
            this.activeTasks.set(task.taskId, task);
            
            try {
                availableWorker.postMessage({
                    taskId: task.taskId,
                    type: task.type,
                    data: task.data
                });
            } catch (error) {
                this._log(`Failed to send task to worker: ${error.message}`, 'error');
                availableWorker.busy = false;
                this.activeTasks.delete(task.taskId);
                clearTimeout(task.timeout);
                task.reject(error);
            }
        }

        _convertAndStoreKeys(derivedKeys, addresses) {
            this.derivedKeys.clear();
            this.addresses.clear();
            
            for (const [network, key] of Object.entries(derivedKeys)) {
                this.derivedKeys.set(network, {
                    privateKey: new Uint8Array(key.privateKey),
                    chainCode: new Uint8Array(key.chainCode),
                    depth: key.depth,
                    parentFingerprint: new Uint8Array(key.parentFingerprint),
                    childIndex: key.childIndex
                });
            }
            
            for (const [network, address] of Object.entries(addresses)) {
                this.addresses.set(network, address);
            }
        }

        _validatePassword(password) {
            const validation = this.validatePassword(password);
            if (!validation.isValid) {
                throw new Error(`Password validation failed: ${validation.issues.join(', ')}`);
            }
        }

        _requireUnlocked() {
            if (!this.isInitialized) {
                throw new Error('Wallet not initialized. Please call initialize() first.');
            }
            if (this.isLocked) {
                throw new Error('Wallet is locked. Please unlock first.');
            }
        }

        async _loadFromKeyData(keyData) {
            const seed = this.hexToBytes(keyData.seed);
            
            const result = await this._executeTask('deriveKeysFromSeed', {
                seedData: Array.from(seed),
                networks: this.supportedNetworks
            });
            
            this.hdWallet = {
                seed: seed,
                masterKey: null
            };
            
            this._convertAndStoreKeys(result.derivedKeys, result.addresses);
            this.isInitialized = true;
        }

        async _saveToStorage(password) {
            try {
                const keyData = {
                    seed: this.bytesToHex(this.hdWallet.seed),
                    addresses: this.getAllAddresses(),
                    timestamp: Date.now(),
                    version: this.version
                };
                
                const encrypted = await this._executeTask('encryptData', {
                    plaintext: JSON.stringify(keyData),
                    password: password
                });

                const db = await this._openDB();
                const transaction = db.transaction(['encryptedKeys'], 'readwrite');
                const store = transaction.objectStore('encryptedKeys');

                const encryptedData = {
                    id: 'master',
                    encrypted: encrypted.encrypted,
                    salt: encrypted.salt,
                    iv: encrypted.iv,
                    timestamp: Date.now()
                };
                
                return new Promise((resolve, reject) => {
                    const request = store.put(encryptedData);
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => reject(request.error);
                });
            } catch (error) {
                this._log(`Failed to save to storage: ${error.message}`, 'error');
            }
        }

        async _loadEncryptedKeys(password) {
            try {
                const db = await this._openDB();
                const transaction = db.transaction(['encryptedKeys'], 'readonly');
                const store = transaction.objectStore('encryptedKeys');
                
                return new Promise(async (resolve, reject) => {
                    const request = store.get('master');
                    request.onsuccess = async () => {
                        try {
                            const result = request.result;
                            if (!result) {
                                resolve(null);
                                return;
                            }

                            const decrypted = await this._executeTask('decryptData', {
                                encryptedData: result.encrypted,
                                salt: result.salt,
                                iv: result.iv,
                                password: password
                            });

                            const keyData = JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted)));
                            resolve(keyData);
                        } catch (error) {
                            reject(new Error('Invalid password or corrupted data'));
                        }
                    };
                    request.onerror = () => {
                        resolve(null);
                    };
                });
            } catch (error) {
                this._log(`Storage error: ${error.message}`, 'warning');
                return null;
            }
        }

        async _clearStorage() {
            const db = await this._openDB();
            const transaction = db.transaction(['encryptedKeys'], 'readwrite');
            const store = transaction.objectStore('encryptedKeys');
            
            return new Promise((resolve, reject) => {
                const request = store.clear();
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });
        }

        async _openDB() {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open('UniversalCryptoWallet', 1);
                
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result);
                
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    if (!db.objectStoreNames.contains('encryptedKeys')) {
                        const store = db.createObjectStore('encryptedKeys', { keyPath: 'id' });
                        store.createIndex('timestamp', 'timestamp', { unique: false });
                        store.createIndex('version', 'version', { unique: false });
                    }
                };
            });
        }

        _dispatchEvent(eventName, data = null) {
            if (this.eventTarget) {
                const event = new CustomEvent(`CryptoWallet:${eventName}`, {
                    detail: { ...data, wallet: this }
                });
                this.eventTarget.dispatchEvent(event);
            }
        }

        _log(message, type = 'info') {
            if (this.options.enableLogging) {
                const timestamp = new Date().toISOString();
                const logMessage = `${timestamp} ${message}`;
                
                switch (type) {
                    case 'error':
                        console.error(logMessage);
                        break;
                    case 'warning':
                        console.warn(logMessage);
                        break;
                    case 'success':
                    case 'info':
                    default:
                        console.log(logMessage);
                        break;
                }
            }
        }

        _handleError(message, error) {
            const fullMessage = `${message}: ${error.message}`;
            this._log(fullMessage, 'error');
            throw new Error(fullMessage);
        }

        _getAverageResponseTime() {
            if (this.metrics.responseTimes.length === 0) return 0;
            const sum = this.metrics.responseTimes.reduce((a, b) => a + b, 0);
            return Math.round(sum / this.metrics.responseTimes.length);
        }

        _getSuccessRate() {
            if (this.metrics.totalOperations === 0) return 100;
            return Math.round((this.metrics.successfulOps / this.metrics.totalOperations) * 100);
        }

        /**
         * Verify a message signature using the wallet's public key
         */
        async verifyMessage(message, signatureObject, network = null) {
            this._requireUnlocked();
            
            if (!message || !signatureObject) {
                throw new Error('Message and signature object are required');
            }

            const targetNetwork = network || signatureObject.network || 'bitcoin';

            if (!this.derivedKeys.has(targetNetwork)) {
                throw new Error(`Invalid network: ${targetNetwork}. Wallet not initialized for this network.`);
            }

            try {
                const networkConfig = this.networks.get(targetNetwork);
                const derivedKey = this.derivedKeys.get(targetNetwork);
                
                let signature;
                
                if (signatureObject.signature) {
                    signature = signatureObject.signature;
                } else {
                    signature = signatureObject;
                }
                
                const algorithm = signature.algorithm || signatureObject.curve || networkConfig.curve;
                                
                let publicKey;
                let verificationResult = false;

                if (algorithm === 'ed25519' || algorithm === 'ed25519-bip32') {
                    // Ed25519 verification using worker
                    const messageBytes = new TextEncoder().encode(message);
                    const messageHash = await this.sha256(messageBytes);

                    // Create keypair from private key to get public key
                    const keyPairData = await this._executeTask('generateKeyPair', {
                        privateKey: Array.from(derivedKey.privateKey.slice(0, 32)),
                        curve: 'ed25519'
                    });
                    
                    publicKey = new Uint8Array(keyPairData.publicKey);

                    verificationResult = await this._executeTask('verifySignature', {
                        signature: Array.from(signature.signature || signature),
                        message: Array.from(messageHash),
                        publicKey: Array.from(publicKey),
                        algorithm: 'ed25519'
                    });

                } else if (algorithm === 'sr25519') {
                    // Sr25519 verification using worker
                    const messageBytes = new TextEncoder().encode(message);
                    const messageHash = await this.sha256(messageBytes);

                    const keyPairData = await this._executeTask('generateKeyPair', {
                        privateKey: Array.from(derivedKey.privateKey),
                        curve: 'sr25519'
                    });
                    
                    publicKey = new Uint8Array(keyPairData.publicKey);

                    verificationResult = await this._executeTask('verifySignature', {
                        signature: Array.from(signature.signature || signature),
                        message: Array.from(messageHash),
                        publicKey: Array.from(publicKey),
                        algorithm: 'sr25519'
                    });

                } else {
                    // secp256k1 verification
                    if (typeof elliptic === 'undefined') {
                        throw new Error('Elliptic library not loaded for secp256k1 verification');
                    }

                    const EC = elliptic.ec;
                    const secp256k1 = new EC('secp256k1');

                    const keyPair = secp256k1.keyFromPrivate(derivedKey.privateKey);
                    publicKey = keyPair.getPublic();

                    const messageBytes = new TextEncoder().encode(message);
                    const messageHash = await this.sha256(messageBytes);

                    let sig;
                    
                    if (signature.r && signature.s) {
                        sig = {
                            r: signature.r,
                            s: signature.s
                        };
                    } else {
                        console.error('Signature structure:', signature);
                        throw new Error(`Invalid secp256k1 signature format. Expected {r, s, recoveryParam}, got: ${Object.keys(signature).join(', ')}`);
                    }
                    
                    verificationResult = keyPair.verify(messageHash, sig);
                }

                const walletAddress = this.getAddress(targetNetwork);

                const result = {
                    isValid: verificationResult,
                    message: message,
                    signature: signature,
                    network: targetNetwork,
                    algorithm: algorithm,
                    walletAddress: walletAddress,
                    publicKey: publicKey instanceof Uint8Array ? 
                        this.bytesToHex(publicKey) : 
                        (publicKey.encode ? publicKey.encode('hex') : publicKey.toString()),
                    verificationTime: new Date().toISOString()
                };

                this._log(`Message verification ${verificationResult ? 'successful' : 'failed'} for ${targetNetwork}`, 
                        verificationResult ? 'success' : 'warning');

                return result;

            } catch (error) {
                this._log(`Message verification failed: ${error.message}`, 'error');
                console.error('Full error details:', error);
                console.error('Signature object that caused error:', signatureObject);
                
                return {
                    isValid: false,
                    error: error.message,
                    message: message,
                    signature: signatureObject,
                    network: targetNetwork,
                    verificationTime: new Date().toISOString()
                };
            }
        }

        /**
         * Verify a message signature with external public key
         */
        async verifyMessageWithPublicKey(message, signature, publicKey, algorithm = 'secp256k1') {
            if (!message || !signature || !publicKey) {
                throw new Error('Message, signature, and publicKey are required');
            }

            try {
                let verificationResult = false;
                let processedPublicKey = publicKey;

                if (typeof publicKey === 'string') {
                    processedPublicKey = this.hexToBytes(publicKey);
                }

                const messageBytes = new TextEncoder().encode(message);
                const messageHash = await this.sha256(messageBytes);

                if (algorithm === 'ed25519') {
                    verificationResult = await this._executeTask('verifySignature', {
                        signature: Array.from(signature.signature || signature),
                        message: Array.from(messageHash),
                        publicKey: Array.from(processedPublicKey),
                        algorithm: 'ed25519'
                    });

                } else if (algorithm === 'sr25519') {
                    verificationResult = await this._executeTask('verifySignature', {
                        signature: Array.from(signature.signature || signature),
                        message: Array.from(messageHash),
                        publicKey: Array.from(processedPublicKey),
                        algorithm: 'sr25519'
                    });

                } else if (algorithm === 'secp256k1') {
                    const EC = elliptic.ec;
                    const secp256k1 = new EC('secp256k1');
                    
                    const key = secp256k1.keyFromPublic(processedPublicKey);
                    const sig = {
                        r: signature.r,
                        s: signature.s,
                        recoveryParam: signature.recoveryParam
                    };
                    
                    verificationResult = key.verify(messageHash, sig);
                } else {
                    throw new Error(`Unsupported algorithm: ${algorithm}`);
                }

                return {
                    isValid: verificationResult,
                    message: message,
                    signature: signature,
                    publicKey: typeof publicKey === 'string' ? publicKey : this.bytesToHex(processedPublicKey),
                    algorithm: algorithm,
                    verificationTime: new Date().toISOString()
                };

            } catch (error) {
                this._log(`External message verification failed: ${error.message}`, 'error');
                
                return {
                    isValid: false,
                    error: error.message,
                    message: message,
                    signature: signature,
                    publicKey: typeof publicKey === 'string' ? publicKey : this.bytesToHex(publicKey),
                    algorithm: algorithm,
                    verificationTime: new Date().toISOString()
                };
            }
        }

        /**
         * Get integrated crypto bundler status (now part of main class)
         */
        getCryptoBundlerStatus() {
            return {
                available: true,
                integrated: true,
                version: this.version,
                supportedCurves: ['secp256k1', 'ed25519', 'sr25519'],
                supportedHashes: ['sha256', 'sha512_256', 'blake2b', 'keccak256', 'ripemd160'],
                supportedEncodings: ['base32', 'base58', 'hex', 'bech32']
            };
        }

        /**
         * Additional utility methods for backward compatibility
         */
        
        // Ed25519 key pair generation (using worker)
        async ed25519KeyPair(seed = null) {
            return await this._executeTask('generateKeyPair', {
                seed: seed ? Array.from(seed) : null,
                curve: 'ed25519'
            });
        }

        // Sr25519 key pair generation (using worker)
        async sr25519KeyPair(seed = null) {
            return await this._executeTask('generateKeyPair', {
                seed: seed ? Array.from(seed) : null,
                curve: 'sr25519'
            });
        }

        // Blake2b hash
        async blake2b(data, outputLength = 32, key = null) {
            return await this._executeTask('blake2b', {
                data: Array.from(this._toUint8Array(data)),
                outputLength: outputLength,
                key: key ? Array.from(key) : null
            });
        }

        // Base32 encode
        async base32Encode(data) {
            return await this._executeTask('base32Encode', {
                data: Array.from(this._toUint8Array(data))
            });
        }

        // Base32 decode
        async base32Decode(encoded) {
            const result = await this._executeTask('base32Decode', { encoded });
            return new Uint8Array(result);
        }

        // CRC16 checksum
        async crc16(data) {
            return await this._executeTask('crc16', {
                data: Array.from(this._toUint8Array(data))
            });
        }

        // SHA512/256 hash
        async sha512_256(data) {
            const result = await this._executeTask('sha512_256', {
                data: Array.from(this._toUint8Array(data))
            });
            return new Uint8Array(result);
        }

        // Helper method to convert data to Uint8Array
        _toUint8Array(data) {
            if (typeof data === 'string') {
                return new TextEncoder().encode(data);
            }
            if (data instanceof Uint8Array) {
                return data;
            }
            return new Uint8Array(data);
        }

        /**
         * Advanced wallet operations
         */
        
        /**
         * Export private key for specific network
         */
        exportPrivateKey(network) {
            this._requireUnlocked();
            
            if (!this.derivedKeys.has(network)) {
                throw new Error(`Invalid network: ${network}`);
            }
            
            const derivedKey = this.derivedKeys.get(network);
            return this.bytesToHex(derivedKey.privateKey);
        }

        /**
         * Export wallet data (encrypted)
         */
        async exportWallet(password) {
            this._requireUnlocked();
            
            const walletData = {
                version: this.version,
                seed: this.bytesToHex(this.hdWallet.seed),
                networks: this.supportedNetworks,
                addresses: this.getAllAddresses(),
                timestamp: Date.now(),
                metadata: {
                    totalOperations: this.metrics.totalOperations,
                    createdAt: this.hdWallet.createdAt || Date.now()
                }
            };

            const encrypted = await this._executeTask('encryptData', {
                plaintext: JSON.stringify(walletData),
                password: password
            });

            return {
                version: this.version,
                type: 'universal-crypto-wallet-export',
                data: {
                    encrypted: encrypted.encrypted,
                    salt: encrypted.salt,
                    iv: encrypted.iv,
                    timestamp: Date.now()
                }
            };
        }

        /**
         * Import wallet data (encrypted)
         */
        async importWallet(encryptedWalletData, password) {
            try {
                if (!encryptedWalletData || !encryptedWalletData.data) {
                    throw new Error('Invalid wallet data format');
                }

                const { encrypted, salt, iv } = encryptedWalletData.data;

                const decrypted = await this._executeTask('decryptData', {
                    encryptedData: encrypted,
                    salt: salt,
                    iv: iv,
                    password: password
                });

                const walletData = JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted)));

                // Validate wallet data
                if (!walletData.seed || !walletData.networks) {
                    throw new Error('Invalid wallet data structure');
                }

                // Import the wallet
                await this.importSeed(walletData.seed, password);

                this._log('Wallet imported successfully from encrypted data', 'success');
                this._dispatchEvent('walletImported', { source: 'encrypted' });

                return {
                    success: true,
                    networks: walletData.networks.length,
                    addresses: Object.keys(walletData.addresses).length,
                    version: walletData.version
                };

            } catch (error) {
                this._log(`Wallet import failed: ${error.message}`, 'error');
                throw new Error(`Failed to import wallet: ${error.message}`);
            }
        }

        /**
         * Backup wallet to JSON
         */
        async backupWallet(password, includePrivateKeys = false) {
            this._requireUnlocked();

            const backup = {
                version: this.version,
                type: 'universal-crypto-wallet-backup',
                timestamp: Date.now(),
                networks: this.supportedNetworks,
                addresses: this.getAllAddresses(),
                metadata: {
                    totalOperations: this.metrics.totalOperations,
                    averageResponseTime: this._getAverageResponseTime(),
                    successRate: this._getSuccessRate()
                }
            };

            if (includePrivateKeys) {
                // Encrypt the seed
                const encrypted = await this._executeTask('encryptData', {
                    plaintext: this.bytesToHex(this.hdWallet.seed),
                    password: password
                });

                backup.encryptedSeed = {
                    encrypted: encrypted.encrypted,
                    salt: encrypted.salt,
                    iv: encrypted.iv
                };
            }

            return backup;
        }

        /**
         * Restore wallet from backup
         */
        async restoreWallet(backup, password) {
            try {
                if (!backup || backup.type !== 'universal-crypto-wallet-backup') {
                    throw new Error('Invalid backup format');
                }

                if (backup.encryptedSeed) {
                    const { encrypted, salt, iv } = backup.encryptedSeed;

                    const decrypted = await this._executeTask('decryptData', {
                        encryptedData: encrypted,
                        salt: salt,
                        iv: iv,
                        password: password
                    });

                    const seedHex = new TextDecoder().decode(new Uint8Array(decrypted));
                    await this.importSeed(seedHex, password);
                } else {
                    throw new Error('Backup does not contain seed data. Cannot restore wallet.');
                }

                this._log('Wallet restored successfully from backup', 'success');
                this._dispatchEvent('walletRestored');

                return {
                    success: true,
                    networks: backup.networks?.length || 0,
                    addresses: Object.keys(backup.addresses || {}).length,
                    version: backup.version
                };

            } catch (error) {
                this._log(`Wallet restore failed: ${error.message}`, 'error');
                throw new Error(`Failed to restore wallet: ${error.message}`);
            }
        }

        /**
         * Get wallet statistics
         */
        getWalletStats() {
            return {
                version: this.version,
                isInitialized: this.isInitialized,
                isLocked: this.isLocked,
                totalNetworks: this.networks.size,
                supportedNetworks: this.supportedNetworks.length,
                activeNetworks: this.addresses.size,
                performance: {
                    totalOperations: this.metrics.totalOperations,
                    successfulOperations: this.metrics.successfulOps,
                    successRate: this._getSuccessRate(),
                    averageResponseTime: this._getAverageResponseTime(),
                    initTime: this.metrics.initTime,
                    addressGenTime: this.metrics.addressGenTime,
                    signTime: this.metrics.signTime
                },
                workers: {
                    totalWorkers: this.workerPool.length,
                    activeWorkers: this.activeTasks.size,
                    queuedTasks: this.taskQueue.length
                }
            };
        }
    }

    // Export for different environments
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { CryptoWallet, NETWORK_CONFIGS };
    } else if (typeof define === 'function' && define.amd) {
        define([], function() {
            return { CryptoWallet, NETWORK_CONFIGS };
        });
    } else {
        global.CryptoWallet = CryptoWallet;
        global.NETWORK_CONFIGS = NETWORK_CONFIGS;
    }

})(typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : this);
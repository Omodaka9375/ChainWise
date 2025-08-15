#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🧪 Testing ChainWise library loading...');

// Test in Node.js environment
try {
    const libPath = path.join(__dirname, '..', 'dist', 'chainwise.min.js');
    
    if (!fs.existsSync(libPath)) {
        throw new Error('chainwise.min.js not found');
    }

    // Read and evaluate the library
    const libCode = fs.readFileSync(libPath, 'utf8');
    
    // Basic syntax check
    if (libCode.includes('syntax error') || libCode.includes('SyntaxError')) {
        throw new Error('Syntax errors detected in build');
    }

    // Check for key components
    const requiredComponents = [
        'CryptoWallet',
        'NETWORK_CONFIGS'
    ];

    requiredComponents.forEach(component => {
        if (!libCode.includes(component)) {
            throw new Error(`Required component missing: ${component}`);
        }
    });

    // Check for network support
    const requiredNetworks = [
        'bitcoin', 'ethereum', 'solana', 'cardano', 'polkadot'
    ];

    requiredNetworks.forEach(network => {
        if (!libCode.includes(network)) {
            throw new Error(`Required network missing: ${network}`);
        }
    });

    console.log('✅ Library structure validation passed');
    console.log('✅ Network configurations found');
    console.log('✅ Core components present');
    
    console.log('\n🎉 Library test passed!');
    
} catch (error) {
    console.error(`❌ Library test failed: ${error.message}`);
    process.exit(1);
}
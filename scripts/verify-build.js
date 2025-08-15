#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔍 Verifying ChainWise build...');

const distDir = path.join(__dirname, '..', 'dist');
const requiredFiles = [
    'chainwise.min.js'
];

const optionalFiles = [
    'chainwise.js',
    'chainwise.d.ts'
];

let errors = 0;
let warnings = 0;

// Check if dist directory exists
if (!fs.existsSync(distDir)) {
    console.error('❌ dist/ directory not found');
    process.exit(1);
}

// Check required files
requiredFiles.forEach(file => {
    const filePath = path.join(distDir, file);
    if (!fs.existsSync(filePath)) {
        console.error(`❌ Required file missing: ${file}`);
        errors++;
    } else {
        const stats = fs.statSync(filePath);
        const sizeKB = (stats.size / 1024).toFixed(2);
        console.log(`✅ ${file} found (${sizeKB} KB)`);
        
        // Basic content verification
        const content = fs.readFileSync(filePath, 'utf8');
        if (!content.includes('CryptoWallet')) {
            console.error(`❌ ${file} doesn't contain CryptoWallet class`);
            errors++;
        }
        
        if (file.endsWith('.min.js') && content.length < 10000) {
            console.warn(`⚠️  ${file} seems too small (${sizeKB} KB)`);
            warnings++;
        }
    }
});

// Check optional files
optionalFiles.forEach(file => {
    const filePath = path.join(distDir, file);
    if (fs.existsSync(filePath)) {
        const stats = fs.statSync(filePath);
        const sizeKB = (stats.size / 1024).toFixed(2);
        console.log(`📄 ${file} found (${sizeKB} KB)`);
    } else {
        console.log(`ℹ️  Optional file not found: ${file}`);
    }
});

// Check package.json
const packagePath = path.join(__dirname, '..', 'package.json');
if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    console.log(`📦 Package: ${pkg.name}@${pkg.version}`);
    
    // Verify main file exists
    if (pkg.main && !fs.existsSync(path.join(__dirname, '..', pkg.main))) {
        console.error(`❌ Main file not found: ${pkg.main}`);
        errors++;
    }
} else {
    console.error('❌ package.json not found');
    errors++;
}

// Summary
console.log('\n📊 Verification Summary:');
console.log(`✅ Passed: ${requiredFiles.length - errors} of ${requiredFiles.length} required checks`);
if (warnings > 0) {
    console.log(`⚠️  Warnings: ${warnings}`);
}

if (errors > 0) {
    console.error(`❌ Errors: ${errors}`);
    console.error('\n💥 Build verification failed!');
    process.exit(1);
} else {
    console.log('\n🎉 Build verification passed!');
    process.exit(0);
}
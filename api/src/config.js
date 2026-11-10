// Конфігурація застосунку. Значення — з оточення (.env), із запасними значеннями для локального стенду.

import argon2 from "argon2";
import crypto from 'node:crypto';

let privateKey = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n');
let publicKey = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n');

if (!privateKey || !publicKey) {
    if (process.env.NODE_ENV === 'production') {
        throw new Error('RSA JWT keys are required in production');
    }

    console.warn('WARNING: Using temporary RSA JWT keys');

    const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048
    });

    privateKey = keys.privateKey.export({
        type: 'pkcs8',
        format: 'pem'
    });

    publicKey = keys.publicKey.export({
        type: 'spki',
        format: 'pem'
    });
}

let mfaKey = process.env.MFA_ENC_KEY;
if (!mfaKey) {
    if (process.env.NODE_ENV === 'production') {
        throw new Error('MFA encoded key is required in production');
    }
    console.warn('WARNING: Using temporary MFA encoded key');
    mfaKey = crypto.randomBytes(32).toString('base64');
}
export const config = {
    port: Number(process.env.PORT) || 3000,

    jwtPublicKey: publicKey,
    jwtPrivateKey: privateKey,
    jwtExpiresIn: '15m',

    tokenIssuer: "ecomonitor-auth",
    tokenAudience: "ecomonitor-api",
    mfaExpiresIn: "5m",
    mfaIssuer: "ecomonitor-mfa",
    mfaAudience: "ecomonitor-mfa-api",
    otpauthIssuer: "ecomonitor-otpauth",
    argon_options: {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1
    },
    refreshTokenTTL: 604800000,
    refreshTokenFamilyTTL: 2592000000,
    dummy_argon_hash: process.env.DUMMY_ARGON2_HASH,
    importAllowedSources: [
        "127.0.0.1:4100",
    ],
    importBlockedIPv4: [
        ["0.0.0.0", 8],
        ["10.0.0.0", 8],
        ["100.64.0.0", 10],
        ["127.0.0.0", 8],
        ["169.254.0.0", 16],
        ["172.16.0.0", 12],
        ["192.0.0.0", 24],
        ["192.168.0.0", 16],
        ["198.18.0.0", 15],
        ["224.0.0.0", 4],
        ["240.0.0.0", 4],
    ],
    importBlockedIPv6: [
        ["::", 128],
        ["::1", 128],
        ["fc00::", 7],
        ["fe80::", 10],
        ["ff00::", 8],
        ["2001:db8::", 32],
        ["::ffff:0:0", 96],
    ],
    maxImportRows: 1000,
    loginRateLimits: {
        windowMs: 15 * 60 * 1000,
        limit: 5,
        lockUserMs: 15 * 60 * 1000
    },
    telemetryRateLimits: {
        windowMs: 60 * 1000,
        limit: 60,
    },
    mfaRateLmits: {
        windowsMs: 15 * 60 * 1000,
        limit: 5
    },
    mfaEncodedKey: mfaKey
};

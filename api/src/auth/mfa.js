import crypto from "node:crypto";
import {config} from "../config.js";
import jwt from "jsonwebtoken";

const KEY = Buffer.from(config.mfaEncodedKey, "base64");

if (KEY.length !== 32 || KEY.toString("base64") !== config.mfaEncodedKey) {
    throw new Error("MFA_ENC_KEY must be a valid Base64-encoded 32-byte key");
}

export function encryptTotpSecret(secret) {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);

    const encrypted = Buffer.concat([
        cipher.update(secret, "utf8"),
        cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return [
        "v1",
        iv.toString("base64"),
        tag.toString("base64"),
        encrypted.toString("base64"),
    ].join(":");
}

export function decryptTotpSecret(value) {
    const [version, ivText, tagText, encryptedText] = value.split(":");

    if (version !== "v1" || !ivText || !tagText || !encryptedText) {
        throw new Error("Invalid encrypted TOTP secret");
    }

    const iv = Buffer.from(ivText, "base64");
    const tag = Buffer.from(tagText, "base64");
    const encrypted = Buffer.from(encryptedText, "base64");

    if (iv.length !== 12 || tag.length !== 16) {
        throw new Error("Invalid TOTP encryption parameters");
    }

    const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
    ]).toString("utf8");
}


export function issueMfaToken(user) {
    return jwt.sign(
        {
            sub: user.username
        },
        config.jwtPrivateKey,
        {
            algorithm: 'RS256',
            expiresIn: config.mfaExpiresIn,
            audience: config.mfaAudience,
            issuer: config.mfaIssuer,
            jwtid: crypto.randomUUID()
        }
    );
}

export function verifyMfaToken(token) {
    try {
        return jwt.verify(token, config.jwtPublicKey, {
            algorithms: ['RS256'],
            audience: config.mfaAudience,
            issuer: config.mfaIssuer,
        });
    } catch {
        return null;
    }
}
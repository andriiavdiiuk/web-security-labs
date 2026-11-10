import jwt from "jsonwebtoken";
import {config} from "../config.js";
import crypto from "node:crypto";
import {RefreshToken} from "../models/index.js";
import {sha256} from "../lib/hash.js";

// Видача токена доступу після успішного входу.
export function issueAccessToken(user) {
    return jwt.sign(
        {
            sub: user.username,
            role: user.role,
            issuer: config.tokenIssuer,
            audience: config.tokenAudience,
        },
        config.jwtPrivateKey,
        {
            algorithm: 'RS256',
            expiresIn: config.jwtExpiresIn,
            issuer: config.tokenIssuer,
            audience: config.tokenAudience,
            jwtid: crypto.randomUUID()
        }
    );
}

// Розбір токена з запиту. Повертає payload або null.
export function readToken(token) {
    try {
        return jwt.verify(token, config.jwtPublicKey, {
            algorithms: ['RS256'],
            issuer: config.tokenIssuer,
            audience: config.tokenAudience
        });
    } catch {
        return null;
    }
}

function logReuse(familyId, userId) {
    console.warn(JSON.stringify({
        event: "refresh_token_reuse",
        familyId,
        userId,
        timestamp: new Date().toISOString()
    }));
}

export async function issueRefreshToken(userId) {
    const now = Date.now();
    const familyId = crypto.randomUUID();
    const familyExpiresAt = new Date(now + config.refreshTokenFamilyTTL);

    return createNextToken(userId, familyId, familyExpiresAt);
}

async function createNextToken(userId, familyId, familyExpiresAt) {
    const now = Date.now();
    const token = crypto.randomBytes(48).toString("base64url");

    const expiresAt = new Date(
        Math.min(now + config.refreshTokenTTL, familyExpiresAt.getTime())
    );

    await RefreshToken.create({
        tokenHash: sha256(token),
        familyId,
        userId,
        usedAt: null,
        revokedAt: null,
        expiresAt,
        familyExpiresAt
    });

    return token;
}

export async function rotateRefreshToken(token) {
    const now = new Date();
    const tokenHash = sha256(token);

    const record = await RefreshToken.findOne({
        tokenHash: tokenHash
    });

    if (!record) {
        return { ok: false, reason: "invalid_refresh_token" };
    }

    if (record.usedAt || record.revokedAt) {
        logReuse(record.familyId, record.userId);

        await RefreshToken.updateMany({
            familyId: record.familyId
        }, {
            revokedAt: now
        });

        return { ok: false, reason: "refresh_token_reuse" };
    }

    if (record.expiresAt <= now || record.familyExpiresAt <= now) {
        return { ok: false, reason: "refresh_token_expired" };
    }

    const consumed = await RefreshToken.findOneAndUpdate({
        tokenHash,
        usedAt: null,
        revokedAt: null,
        expiresAt: { $gt: now },
        familyExpiresAt: { $gt: now }
    }, {
        $set: { usedAt: now }
    });

    if (!consumed) {
        return { ok: false, reason: "refresh_token_already_used" };
    }

    const nextToken = await createNextToken(
        record.userId,
        record.familyId,
        record.familyExpiresAt
    );

    return {
        ok: true,
        userId: record.userId,
        refreshToken: nextToken
    };
}

export async function revokeRefreshFamily(token) {
    if (!token) return;

    await RefreshToken.updateMany({
        tokenHash: sha256(token),
        revokedAt: null
    }, {
        revokedAt: new Date()
    });
}
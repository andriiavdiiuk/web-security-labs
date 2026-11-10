import {Router} from "express";
import {User} from "../models/index.js";
import {verifyPassword} from "../lib/verifyPassword.js";
import {issueAccessToken, issueRefreshToken, revokeRefreshFamily, rotateRefreshToken} from "../auth/tokens.js";
import {requireAuth} from "../auth/requireAuth.js";
import argon2 from "argon2";
import {loginLimiter, mfaLimiter} from "../lib/rateLimiter.js";
import {config} from "../config.js";
import {generateSecret, generateURI, verify} from "otplib";
import {decryptTotpSecret, encryptTotpSecret, issueMfaToken} from "../auth/mfa.js";

export const auth = Router();

const ACCESS_COOKIE = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
};

const REFRESH_COOKIE = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth"
};

function setSessionCookies(res, accessToken, refreshToken) {
    res.cookie("accessToken", accessToken, {
        sameSite: "lax",
        httpOnly: true,
        secure: true,
        path: "/",
    });

    res.cookie("refreshToken", refreshToken, {
        sameSite: "strict",
        httpOnly: true,
        secure: true,
        path: "/auth"
    })
}

function clearSessionCookies(res) {
    res.clearCookie("accessToken", ACCESS_COOKIE);
    res.clearCookie("refreshToken", REFRESH_COOKIE);
}

// POST /auth/login  { username, password }
auth.post("/login", loginLimiter, async (req, res) => {
    const {username, password} = req.body || {};

    const user = await User.findOne({username});

    if (!user) {
        return res.status(401).json({error: "invalid_credentials"});
    }

    const valid = await verifyPassword(user, password);

    const now = new Date();

    if (user.lockedUntil && user.lockedUntil > now) {
        return res.status(401).json({error: "invalid_credentials"});
    }

    if (!valid) {
        user.failedLogins += 1;

        if (user.failedLogins >= 10) {
            user.lockedUntil = new Date(Date.now() + config.loginRateLimits.lockUserMs);
        }

        await user.save();
        return res.status(401).json({error: "invalid_credentials"});
    }
    if (user.mfaEnabled) {
        return res.json({
            mfaRequired: true,
            mfaToken: issueMfaToken(user),
        });
    }

    user.failedLogins = 0;
    user.lockedUntil = null;
    await user.save();

    const accessToken = issueAccessToken(user);
    const refreshToken = await issueRefreshToken(user.username);

    setSessionCookies(res, accessToken, refreshToken);

    return res.json({
        accessToken,
        refreshToken,
        role: user.role,
        username: user.username
    });
});

// POST /auth/logout
auth.post("/logout", async (req, res) => {
    try {
        await revokeRefreshFamily(req.cookies?.refreshToken);

        clearSessionCookies(res);

        return res.json({ok: true});
    } catch {
        clearSessionCookies(res);

        return res.status(500).json({
            error: "logout_failed"
        });
    }
});

auth.post("/refresh", async (req, res) => {
    try {
        const result = await rotateRefreshToken(req.cookies?.refreshToken);

        if (!result.ok) {
            clearSessionCookies(res);

            return res.status(401).json({
                error: result.reason
            });
        }

        const user = await User.findOne({
            username: result.userId
        });

        if (!user) {
            clearSessionCookies(res);
            return res.status(401).json({
                error: "user_not_found"
            });
        }

        const accessToken = issueAccessToken(user);

        setSessionCookies(res, accessToken, result.refreshToken);

        return res.json({ok: true});
    } catch {
        clearSessionCookies(res);
        return res.status(401).json({
            error: "refresh_failed"
        });
    }
});

// GET /auth/me — дані поточного користувача з токена
auth.get("/me", requireAuth, (req, res) => {
    res.json({
        user: {
            sub: req.user.sub,
            role: req.user.role
        }
    });
});

auth.post("/mfa/setup", requireAuth, async (req, res) => {
    const user = await User.findById(req.dbUser._id);

    if (!user) {
        return res.sendStatus(401);
    }

    if (user.mfaEnabled) {
        return res.sendStatus(409);
    }

    const secret = generateSecret();

    user.totpSecret = encryptTotpSecret(secret);
    await user.save();

    const otpauthUri = generateURI({
        issuer: config.otpauthIssuer,
        label: user.username,
        secret,
    });

    return res.json({otpauthUri});
});

auth.post("/mfa/enable", requireAuth, mfaLimiter, async (req, res) => {
        const {code} = req.body || {};

        if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
            return res.sendStatus(401);
        }

        const user = await User.findById(req.dbUser._id);

        if (!user || user.mfaEnabled || !user.totpSecret) {
            return res.sendStatus(401);
        }

        const secret = decryptTotpSecret(user.totpSecret);

        const result = await verify({
            secret,
            token: code,
            afterTimeStep: user.totpLastStep ?? 0,
        });

        if (!result.valid) {
            return res.sendStatus(401);
        }

        const updated = await User.updateOne(
            {
                _id: user._id,
                mfaEnabled: {$ne: true},
                $or: [
                    {totpLastStep: {$exists: false}},
                    {totpLastStep: null},
                    {totpLastStep: {$lt: result.timeStep}},
                ],
            },
            {
                $set: {
                    mfaEnabled: true,
                    totpLastStep: result.timeStep,
                },
            }
        );

        if (!updated.matchedCount) {
            return res.sendStatus(401);
        }

        return res.json({ok: true, mfaEnabled: true});
    }
);

auth.post("/mfa/verify", mfaLimiter, async (req, res) => {
    const { mfaToken, code } = req.body || {};

    if (typeof mfaToken !== "string" || typeof code !== "string" || !/^\d{6}$/.test(code)) {
        return res.sendStatus(401);
    }

    try {
        const claims = verifyMfaToken(mfaToken);

        const user = await User.findById(claims.sub);

        if (!user || !user.mfaEnabled || !user.totpSecret) {
            return res.sendStatus(401);
        }

        const secret = decryptTotpSecret(user.totpSecret);

        const result = await verify({
            secret,
            token: code,
            afterTimeStep: user.totpLastStep ?? -1,
        });

        if (!result.valid) {
            return res.sendStatus(401);
        }

        const updated = await User.updateOne(
            {
                _id: user._id,
                mfaEnabled: true,
                totpLastStep: { $lt: result.timeStep },
            },
            {
                $set: {
                    totpLastStep: result.timeStep,
                },
            }
        );

        if (!updated.matchedCount) {
            return res.sendStatus(401);
        }

        const accessToken = issueAccessToken(user);
        const refreshToken = await issueRefreshToken(user.username);

        setSessionCookies(res, accessToken, refreshToken);

        return res.json({
            accessToken,
            refreshToken,
            role: user.role,
            username: user.username,
        });

    } catch {
        return res.sendStatus(401);
    }
});
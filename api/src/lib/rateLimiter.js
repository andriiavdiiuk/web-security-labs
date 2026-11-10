import {rateLimit, ipKeyGenerator} from "express-rate-limit";
import {config} from "../config.js";

export const loginLimiter = rateLimit({
    windowMs: config.loginRateLimits.windowMs,
    limit: config.loginRateLimits.limit,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    skipSuccessfulRequests: true,

    keyGenerator: (req) => {
        const ip = ipKeyGenerator(req.ip);
        const username = String(req.body?.username || "")
            .trim()
            .toLowerCase();

        return `${ip}:${username}`;
    },

    handler: (req, res) => {
        res.status(429).json({error: "too_many_attempts"});
    },
});

export const telemetryLimiter = rateLimit({
    windowMs: config.telemetryRateLimits.windowMs,
    limit: config.telemetryRateLimits.limit,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    keyGenerator: (req) => String(req.params.id),

    handler: (req, res) => {
        res.status(429).json({error: "too_many_readings"});
    },
});

export const mfaLimiter = rateLimit({
    windowMs: config.mfaRateLmits.windowsMs,
    limit: config.mfaRateLmits.limit,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skipSuccessfulRequests: true,

    handler: (req, res) => {
        res.status(429).json({error: "too_many_attempts"});
    },
});
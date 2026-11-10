import argon2 from "argon2";
import {User} from "../models/index.js";
import {config} from "../config.js";
import {sha256} from "./hash.js";
import {timingSafeEqual} from "node:crypto";

async function saveUser(user) {
    await User.findOneAndUpdate(
        {username: user.username},
        {
            $set: {passwordHash: user.passwordHash},
            $unset: {passwordSha256: ''}
        }
    );
}

async function safeArgon2Verify(hash, password) {
    if (!hash || typeof hash !== 'string') return false;

    try {
        return await argon2.verify(hash, String(password ?? ''));
    } catch {
        return false;
    }
}

export async function verifyPassword(user, password) {
    const value = String(password ?? '');

    if (!user) {
        await safeArgon2Verify(config.dummy_argon_hash, value);
        return false;
    }

    if (user.passwordSha256) {
        const actual = Buffer.from(sha256(value), 'hex');
        const expected = Buffer.from(user.passwordSha256, 'hex');

        const valid = actual.length === expected.length && timingSafeEqual(actual, expected);

        if (!valid) return false;

        user.passwordHash = await argon2.hash(value, config.argon_options);

        await saveUser(user);
        return true;
    }

    if (user.passwordHash) {
        const valid = await safeArgon2Verify(user.passwordHash, value);

        if (!valid) return false;

        if (argon2.needsRehash(user.passwordHash, config.argon_options)) {
            user.passwordHash = await argon2.hash(value, config.argon_options);
            await saveUser(user);
        }

        return true;
    }


    await safeArgon2Verify(config.dummy_argon_hash, value);
    return false;
}
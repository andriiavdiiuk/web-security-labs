import {readToken} from "./tokens.js";
import {User} from "../models/index.js";

// Автентифікація: токен із cookie або заголовка Authorization.
export async function requireAuth(req, res, next) {
    const bearer = (req.get("authorization") || "").replace(/^Bearer /, "");
    const token = req.cookies?.accessToken || bearer;
    const payload = token ? readToken(token) : null;
    if (!payload) return res.status(401).json({error: "unauthorized"});

    const username = payload?.sub;

    if (typeof username !== "string" || !username) {
        return res.sendStatus(401).json({error: "unauthorized"});
    }

    const user = await User.findOne({username},
        {
            username: 1,
            role: 1,
            city: 1,
            fullName: 1,
        }
    );

    if (!user) {
        return res.sendStatus(401);
    }

    req.dbUser = user;
    req.user = payload; // { sub, role, ... }
    next();
}

// Ієрархія ролей: роль включає права перелічених ролей.
export const ROLE_INHERITS = {
    admin: ["admin", "operator", "viewer"],
    operator: ["operator", "viewer"],
    viewer: ["viewer"],
};

// Перевірка ролі: requireRole("admin"), requireRole("operator", "admin") тощо.
export function requireRole(...allowed) {
    return async (req, res, next) => {
        try {
            const user = req.dbUser;

            if (!user || typeof user.role !== "string") {
                return res.sendStatus(403).json({error: "forbidden"});
            }

            if (!Object.hasOwn(ROLE_INHERITS, user.role)) {
                return res.status(403).json({
                    error: "forbidden",
                });
            }

            if (allowed.length === 0) {
                return next();
            }

            const effective = ROLE_INHERITS[user.role];
            if (effective.some(r => allowed.includes(r))) return next();
            return res.status(403).json({error: "forbidden"});
        } catch {
            return res.status(403).json({error: "forbidden"});
        }
    };
}
export function stationScope(req, res, next) {
    const user = req.dbUser;

    switch (user.role) {
        case "admin":
            req.stationScope = {};
            break;

        case "operator":
            req.stationScope = {
                ownerUsername: user.username,
            };
            break;

        case "viewer":
            req.stationScope = user.city
                ? { city: user.city }
                : { stationId: "__DENIED__" };
            break;

        default:
            return res.status(403).json({ error: "forbidden" });
    }

    return next();
}
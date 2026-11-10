import { Router } from "express";
import { Measurement, Station } from "../models/index.js";
import {requireAuth, requireRole} from "../auth/requireAuth.js";
import {stationScope} from "../auth/stationScope.js";
import {config} from "../config.js";
import { BlockList, isIP } from "node:net";

const blockedIPs = new BlockList();

for (const [address, prefix] of config.importBlockedIPv4) {
    blockedIPs.addSubnet(address, prefix, "ipv4");
}

for (const [address, prefix] of config.importBlockedIPv6) {
    blockedIPs.addSubnet(address, prefix, "ipv6");
}

function isBlockedIP(address) {
    const type = isIP(address);

    if (!type) return true;

    return blockedIPs.check(address, type === 4 ? "ipv4" : "ipv6");
}

export async function validateImportUrl(sourceUrl) {
    let url;

    try {
        if (typeof sourceUrl !== "string") {
            return { reason: "invalid_url" };
        }

        url = new URL(sourceUrl);
    } catch {
        return { reason: "invalid_url" };
    }

    if (url.username || url.password) {
        return { reason: "invalid_url" };
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        return { reason: "bad_scheme" };
    }

    const hostname = url.hostname.toLowerCase();
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));

    const hostPort = `${hostname}:${port}`;

    // Explicitly trusted sources are checked first.
    if (config.importAllowedSources?.includes(hostPort)) {
        return { url };
    }

    if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
        return { reason: "blocked_host" };
    }

    const address = hostname.replace(/^\[|]$/g, "");

    if (isIP(address)) {
        if (isBlockedIP(address)) {
            return { reason: "blocked_host" };
        }

        return { url };
    }

    try {
        const addresses = await dns.lookup(address, {
            all: true,
            verbatim: true,
        });

        if (
            !addresses.length ||
            addresses.some(({ address }) => isBlockedIP(address))
        ) {
            return { reason: "blocked_host" };
        }
    } catch {
        return { reason: "blocked_host" };
    }

    return { url };
}

export const importData = Router();
importData.use(requireAuth);
importData.use(stationScope);
// POST /api/stations/:id/import  { sourceUrl }
// Імпорт показників станції із зовнішнього джерела екоданих за вказаною URL.
// Джерело повертає JSON-масив [{ pm25, pm10, no2, ts }, ...].
importData.post("/:id/import",requireRole("admin","operator"), async (req, res) => {
    const { sourceUrl } = req.body || {};

    const station = await Station.findOne({
        stationId: req.params.id,
        ...req.stationScope,
    });

    if (!station) {
        return res.status(404).json({ error: "unknown_station" });
    }

    const validation = await validateImportUrl(sourceUrl);

    if (validation.reason) {
        return res.status(400).json({
            error: validation.reason,
        });
    }

    try {
        const upstream = await fetch(validation.url, {
            signal: AbortSignal.timeout(5000),
            redirect: "manual",
        });

        if (upstream.status !== 200) {
            await upstream.body?.cancel();

            return res.status(502).json({
                error: "upstream_error",
                upstreamStatus: upstream.status,
            });
        }

        const text = await upstream.text();

        let rows;

        try {
            rows = JSON.parse(text);
        } catch {
            return res.status(502).json({
                error: "invalid_upstream_json",
            });
        }

        if (!Array.isArray(rows)) {
            return res.status(502).json({
                error: "invalid_upstream_data",
            });
        }

        if (rows.length > config.maxImportRows) {
            return res.status(400).json({
                error: "too_many_rows",
                maxRows: config.maxImportRows,
            });
        }

        let imported = 0;

        for (const row of rows) {
            await Measurement.create({
                stationId: req.params.id,
                pm25: row.pm25,
                pm10: row.pm10,
                no2: row.no2,
                ts: row.ts ? new Date(row.ts) : new Date(),
            });

            imported++;
        }

        return res.json({
            ok: true,
            imported,
            upstreamStatus: upstream.status,
        });

    } catch {
        return res.status(502).json({
            error: "fetch_failed",
        });
    }
});
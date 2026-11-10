import express, {Router} from "express";
import {Station, Measurement} from "../models/index.js";
import crypto from "node:crypto";
import {stationScope} from "../auth/stationScope.js";
import {sha256} from "../lib/hash.js";
import {requireAuth} from "../auth/requireAuth.js";
import {telemetryLimiter} from "../lib/rateLimiter.js";

export const ingest = Router();
// POST /api/stations/:id/readings — приймання показників від станції моніторингу.
// Станція автентифікується заголовком X-Station-Key.
// Тіло: { pm25, pm10, no2 }
ingest.post("/:id/readings", telemetryLimiter, express.json(), async (req, res) => {
    const key = req.get("x-station-key");

    const station = await Station.findOne({stationId: req.params.id});

    if (!station || !key || !station.secretHash) {
        return res.status(401).json({error: "invalid_station_key"});
    }

    const providedHash = sha256(key);

    if (!crypto.timingSafeEqual(
        Buffer.from(providedHash, "hex"),
        Buffer.from(station.secretHash, "hex")
    )) {
        return res.status(401).json({error: "invalid_station_key"});
    }

    const {pm25, pm10, no2} = req.body || {};
    await Measurement.create({stationId: req.params.id, pm25, pm10, no2, ts: new Date()});
    res.status(202).json({accepted: true});
});

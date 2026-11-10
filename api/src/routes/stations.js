import {Router} from "express";
import {Station, Measurement} from "../models/index.js";
import {requireAuth, requireRole} from "../auth/requireAuth.js";
import {stationScope} from "../auth/stationScope.js";

export const stations = Router();

const stationFields = [
    "stationId",
    "name",
    "city",
    "ownerUsername",
    "latitude",
    "longitude",
    "pm25AlertThreshold",
    "note",
    "noteUpdatedBy",
];

function allowedStationQuery(scope, filter = {}) {
    return {$and: [scope, filter]};
}

function safeStationProjection() {
    return stationFields.join(" ");
}

// Усі маршрути станцій потребують автентифікації.
stations.use(requireAuth);
stations.use(requireRole());
stations.use(stationScope);
// GET /api/stations — список станцій
stations.get("/", async (req, res) => {
    const all = await Station.find(req.stationScope)
        .select(safeStationProjection())
        .lean();

    res.json({stations: all});
});

// GET /api/stations/search?city=...&name=... — пошук станцій.
// Параметри запиту підставляються у фільтр так, як надійшли.
stations.get("/search", async (req, res) => {
    const filter = {};

    if (req.query.city) filter.city = req.query.city;
    if (req.query.name) filter.name = req.query.name;

    const found = await Station.find(
        allowedStationQuery(req.stationScope, filter)
    )
        .select(safeStationProjection())
        .lean();

    res.json({query: req.query, stations: found});
});

// GET /api/stations/:id — одна станція
stations.get("/:id", async (req, res) => {
    const station = await Station.findOne(
        allowedStationQuery(req.stationScope, {
            stationId: req.params.id,
        })
    )
        .select(safeStationProjection())
        .lean();

    if (!station) {
        return res.status(404).json({error: "not_found"});
    }

    res.json({station});
});

// GET /api/stations/:id/measurements — вимірювання станції
stations.get("/:id/measurements", async (req, res) => {
    const station = await Station.findOne(
        allowedStationQuery(req.stationScope, {
            stationId: req.params.id,
        })
    ).select("stationId").lean();

    if (!station) {
        return res.status(404).json({error: "not_found"});
    }

    const data = await Measurement.find({
        stationId: station.stationId,
    }).lean();

    res.json({
        stationId: req.params.id,
        measurements: data,
    });
});

// PATCH /api/stations/:id/threshold  { pm25AlertThreshold } — зміна порогу тривоги PM2.5
stations.patch("/:id/threshold", requireRole("admin"), async (req, res) => {
    const {pm25AlertThreshold} = req.body || {};

if (
        typeof pm25AlertThreshold !== "number" ||
        !Number.isInteger(pm25AlertThreshold) ||
        pm25AlertThreshold < 1 ||
        pm25AlertThreshold > 500
    ) {
        return res.sendStatus(400);
    }

    const r = await Station.updateOne(
        {stationId: req.params.id},
        {$set: {pm25AlertThreshold}}
    );

    if (!r.matchedCount) {
        return res.status(404).json({error: "not_found"});
    }

    res.json({ok: true, matched: r.matchedCount});
});

// PUT /api/stations/:id/note  { note } — текстова примітка оператора до станції.
// Значення зберігається так, як надійшло.
stations.put("/:id/note", requireRole("admin", "operator"), async (req, res) => {
    const note = req.body?.note;

    if (typeof note !== "string" || note.length > 2000) {
        return res.sendStatus(400);
    }
    const r = await Station.updateOne(
        allowedStationQuery(req.stationScope, {stationId: req.params.id,}),
        {
            $set: {
                note,
                noteUpdatedBy: req.dbUser.username,
            },
        }
    );

    if (!r.matchedCount) {
        return res.status(404).json({error: "not_found"});
    }

    res.json({ok: true});
});

// Адміністративні маршрути
export const adminStations = Router();
adminStations.use(requireAuth);
adminStations.use(requireRole("admin"));

// GET /api/admin/stations — перелік ідентифікаторів усіх станцій
adminStations.get("/", async (req, res) => {
    const all = await Station.find({});
    res.json({stations: all.map(s => s.stationId)});
});

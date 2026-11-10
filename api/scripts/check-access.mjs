import process from 'node:process';

const BASE = 'http://127.0.0.1:3000';

const parsedBase = new URL(BASE);
if (!['localhost', '127.0.0.1', '[::1]'].includes(parsedBase.hostname) || !['http:', 'https:'].includes(parsedBase.protocol)) {
    console.error('ERROR: API must use localhost, 127.0.0.1 or [::1]');
    process.exit(1);
}

const users = {
    operator_kyiv: {
        username: process.env.OPERATOR_USER,
        password: process.env.OPERATOR_PASS,
        role: 'operator',
        allowed: ['EW-011', 'EW-012', 'EW-017']
    },
    operator_kr: {
        username: process.env.OPERATOR_KR_USER,
        password: process.env.OPERATOR_KR_PASS,
        role: 'operator',
        allowed: ['EW-031']
    }, viewer: {
        username: process.env.VIEWER_USER,
        password: process.env.VIEWER_PASS,
        role: 'viewer',
        allowed: ['EW-011', 'EW-012', 'EW-017']
    }, auditor: {
        username: process.env.AUDITOR_USER,
        password: process.env.AUDITOR_PASS,
        role: 'auditor',
        allowed: []
    }, admin: {
        username: process.env.ADMIN_USER,
        password: process.env.ADMIN_PASS,
        role: 'admin',
        allowed: ['EW-011', 'EW-012', 'EW-017', 'EW-031', 'EW-042']
    }
};

const initialThresholds = {
    'EW-011': 35,
    'EW-012': 35,
    'EW-017': 40,
    'EW-031': 50,
    'EW-042': 45
};

const initialNotes = {
    'EW-011': 'Планове обслуговування фільтра кожного понеділка.',
    'EW-012': 'Показники <b>уточнюються</b> після калібрування 12.10.',
    'EW-017': '',
    'EW-031': 'Поряд із промисловою зоною, можливі пікові значення PM10.',
    'EW-042': ''
};
const importBody = {
    sourceUrl: 'http://127.0.0.1:4100/readings.json'
};


const secrets = new Set(['secretHash', 'totpSecret', 'passwordHash', 'passwordSha256']);

let failures = 0;

function hasSecret(value) {
    if (!value || typeof value !== 'object') return false;

    for (const [key, item] of Object.entries(value)) {
        if (secrets.has(key)) return true;
        if (hasSecret(item)) return true;
    }

    return false;
}

async function request(method, path, token, body) {
    const response = await fetch(new URL(path, BASE), {
        method,
        redirect: 'manual',
        headers: {...(token ? {Authorization: `Bearer ${token}`} : {}), ...(body !== undefined ? {'Content-Type': 'application/json'} : {})}, ...(body !== undefined ? {body: JSON.stringify(body)} : {})
    });

    const text = await response.text();

    let data;
    try {
        data = JSON.parse(text);
    } catch {
        data = null;
    }

    return {status: response.status, data, text};
}

async function login(user) {
    const response = await fetch(new URL('/auth/login', BASE), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: user.username, password: user.password}),
        redirect: 'manual'
    });

    const text = await response.text();

    let data;
    try {
        data = JSON.parse(text);
    } catch {
        data = {};
    }

    if (!response.ok) {
        throw new Error(`Login failed for ${user.username}: ${response.status}`);
    }

    let token;

    const cookies = response.headers.getSetCookie?.() || [response.headers.get('set-cookie') || ''];

    for (const cookie of cookies) {
        const match = cookie.match(/(?:^|[,;]\s*)accessToken=([^;,\s]+)/);
        if (match) {
            token = decodeURIComponent(match[1]);
            break;
        }
    }

    token ||= data.accessToken;

    if (!token) {
        throw new Error(`No accessToken for ${user.username}`);
    }

    return token;
}

const checks = [];

function add(user, method, path, expected, body, extra = {}) {
    checks.push({user, method, path, expected: Array.isArray(expected) ? expected : [expected], body, ...extra});
}

add('operator_kyiv', 'GET', '/api/stations', 200, undefined, {exactList: true});
add('operator_kyiv', 'GET', `/api/stations/search?city=${encodeURIComponent('Київ')}`, 200, undefined, {subsetSearch: true});
add('operator_kyiv', 'GET', '/api/stations/EW-011', 200);
add('operator_kyiv', 'GET', '/api/stations/EW-011/measurements', 200);
add('operator_kyiv', 'GET', '/api/stations/EW-012', 200);
add('operator_kyiv', 'GET', '/api/stations/EW-012/measurements', 200);
add('operator_kyiv', 'GET', '/api/stations/EW-017', 200);
add('operator_kyiv', 'GET', '/api/stations/EW-017/measurements', 200);
add('operator_kyiv', 'PATCH', '/api/stations/EW-017/threshold', 403, {pm25AlertThreshold: initialThresholds['EW-017']});
add('operator_kyiv', 'PUT', '/api/stations/EW-017/note', [200, 204], {note: initialNotes['EW-017']});
add('operator_kyiv', 'POST', '/api/stations/EW-017/import', [200, 201, 202], importBody);
add('operator_kyiv', 'GET', '/api/stations/EW-031', [403, 404]);
add('operator_kyiv', 'GET', '/api/stations/EW-031/measurements', [403, 404]);
add('operator_kyiv', 'GET', '/api/stations/EW-042', [403, 404]);
add('operator_kyiv', 'GET', '/api/stations/EW-042/measurements', [403, 404]);
add('operator_kyiv', 'GET', '/api/admin/stations', [403, 404]);

add('operator_kr', 'GET', '/api/stations', 200, undefined, {exactList: true});
add('operator_kr', 'GET', `/api/stations/search?city=${encodeURIComponent('Кривий Ріг')}`, 200, undefined, {subsetSearch: true});
add('operator_kr', 'GET', '/api/stations/EW-031', 200);
add('operator_kr', 'GET', '/api/stations/EW-031/measurements', 200);
add('operator_kr', 'PATCH', '/api/stations/EW-031/threshold', 403, {pm25AlertThreshold: initialThresholds['EW-031']});
add('operator_kr', 'PUT', '/api/stations/EW-031/note', [200, 204], {note: initialNotes['EW-031']});
add('operator_kr', 'POST', '/api/stations/EW-031/import', [200, 201, 202], importBody);
add('operator_kr', 'GET', '/api/stations/EW-011', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-011/measurements', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-012', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-012/measurements', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-017', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-017/measurements', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-042', [403, 404]);
add('operator_kr', 'GET', '/api/stations/EW-042/measurements', [403, 404]);
add('operator_kr', 'GET', '/api/admin/stations', [403, 404]);

add('viewer', 'GET', '/api/stations', 200, undefined, {exactList: true});
add('viewer', 'GET', `/api/stations/search?city=${encodeURIComponent('Київ')}`, 200, undefined, {subsetSearch: true});
add('viewer', 'GET', '/api/stations/EW-011', 200);
add('viewer', 'GET', '/api/stations/EW-011/measurements', 200);
add('viewer', 'GET', '/api/stations/EW-012', 200);
add('viewer', 'GET', '/api/stations/EW-012/measurements', 200);
add('viewer', 'GET', '/api/stations/EW-017', 200);
add('viewer', 'GET', '/api/stations/EW-017/measurements', 200);
add('viewer', 'GET', '/api/stations/EW-031', [403, 404]);
add('viewer', 'GET', '/api/stations/EW-031/measurements', [403, 404]);
add('viewer', 'GET', '/api/stations/EW-042', [403, 404]);
add('viewer', 'GET', '/api/stations/EW-042/measurements', [403, 404]);
add('viewer', 'PATCH', '/api/stations/EW-017/threshold', 403, {pm25AlertThreshold: initialThresholds['EW-017']});
add('viewer', 'PUT', '/api/stations/EW-017/note', 403, {note: initialNotes['EW-017']});
add('viewer', 'POST', '/api/stations/EW-017/import', 403, importBody);
add('viewer', 'GET', '/api/admin/stations', [403, 404]);

add('auditor', 'GET', '/api/stations', [403, 404]);
add('auditor', 'GET', `/api/stations/search?city=${encodeURIComponent('Київ')}`, [403, 404]);
add('auditor', 'GET', '/api/stations/EW-017', [403, 404]);
add('auditor', 'GET', '/api/stations/EW-017/measurements', [403, 404]);
add('auditor', 'PATCH', '/api/stations/EW-017/threshold', [403, 404], {pm25AlertThreshold: initialThresholds['EW-017']});
add('auditor', 'PUT', '/api/stations/EW-017/note', [403, 404], {note: initialNotes['EW-017']});
add('auditor', 'POST', '/api/stations/EW-017/import', [403, 404], importBody);
add('auditor', 'GET', '/api/admin/stations', [403, 404]);

add('admin', 'GET', '/api/stations', 200, undefined, {exactList: true});
add('admin', 'GET', `/api/stations/search?city=${encodeURIComponent('Київ')}`, 200, undefined, {subsetSearch: true});
add('admin', 'GET', `/api/stations/search?city=${encodeURIComponent('Кривий Ріг')}`, 200, undefined, {subsetSearch: true});
add('admin', 'GET', `/api/stations/search?city=${encodeURIComponent('Одеса')}`, 200, undefined, {subsetSearch: true});
add('admin', 'GET', '/api/stations/EW-011', 200);
add('admin', 'GET', '/api/stations/EW-011/measurements', 200);
add('admin', 'GET', '/api/stations/EW-012', 200);
add('admin', 'GET', '/api/stations/EW-012/measurements', 200);
add('admin', 'GET', '/api/stations/EW-017', 200);
add('admin', 'GET', '/api/stations/EW-017/measurements', 200);
add('admin', 'GET', '/api/stations/EW-031', 200);
add('admin', 'GET', '/api/stations/EW-031/measurements', 200);
add('admin', 'GET', '/api/stations/EW-042', 200);
add('admin', 'GET', '/api/stations/EW-042/measurements', 200);
add('admin', 'PATCH', '/api/stations/EW-017/threshold', [200, 204], {pm25AlertThreshold: initialThresholds['EW-017']});
add('admin', 'PUT', '/api/stations/EW-042/note', [200, 204], {note: initialNotes['EW-042']});
add('admin', 'GET', '/api/admin/stations', 200);

const tokens = {};

try {
    for (const [name, user] of Object.entries(users)) {
        if (!user.password) {
            throw new Error(`Set password environment variable for ${name}`);
        }
        tokens[name] = await login(user);
    }
} catch (error) {
    console.error('Authentication error:', error.message);
    process.exit(1);
}

async function runCheck(check) {
    let result;
    let ok = false;
    let received = 'ERROR';

    try {
        result = await request(check.method, check.path, tokens[check.user], check.body);

        received = result.status;

        ok = check.expected.includes(result.status);

        if (ok && hasSecret(result.data)) {
            ok = false;
        }

        if (ok && check.exactList) {
            const ids = (result.data?.stations || []).map(s => s.stationId);
            const expected = users[check.user].allowed;

            ok = ids.length === expected.length && new Set(ids).size === expected.length && expected.every(id => ids.includes(id));
        }

        if (ok && check.subsetSearch) {
            const ids = (result.data?.stations || []).map(s => s.stationId);
            const allowed = users[check.user].allowed;

            ok = ids.every(id => allowed.includes(id));
        }


    } catch (error) {
        received = error.message;
    }

    if (!ok) failures++;

    const expectedText = check.expected.join('/');

    const displayPath = decodeURIComponent(check.path);

    console.log(
        `${ok ? 'PASS' : 'FAIL'} ${check.user} ${check.method} ${displayPath} → ${received} (очікувано ${expectedText})`
    );
}

for (const check of checks) {
    await runCheck(check);
}

console.log(`Кількість невідповідностей: ${failures}`);

process.exit(failures === 0 ? 0 : 1);
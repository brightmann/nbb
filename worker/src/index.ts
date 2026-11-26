import { Hono, type Context, type Next } from 'hono';
import { cors } from 'hono/cors';
import { sign, verify } from 'hono/jwt';
import { neon } from '@neondatabase/serverless';
import readingTime from 'reading-time';

type Env = {
  DATABASE_URL: string;
  JWT_ACCESS_SECRET: string;
  JWT_REFRESH_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_CALLBACK_URL: string;
  FRONT_GOOGLE_CALLBACK_URL?: string;
  OSS_ID?: string;
  OSS_NAME?: string;
  OSS_KEY?: string;
  OSS_REGION?: string;
};
type Vars = { user: Row; sql: Sql };
type Row = Record<string, any>;
type Sql = (text: string, params?: unknown[]) => Promise<Row[]>;

const app = new Hono<{ Bindings: Env; Variables: Vars }>();

// Same as Nest's app.enableCors(): allow every origin.
app.use('*', cors());

app.use('*', async (c, next) => {
  c.set('sql', makeSql(c.env.DATABASE_URL));
  await next();
});

// ---------- helpers ----------
// Columns are `timestamp without time zone` holding UTC (Prisma convention). The driver
// parses them in the runtime's local zone, so rebuild each Date from its local fields as UTC.
// On Workers (UTC) this is a no-op; it keeps `wrangler dev` on a laptop correct too.
function fixDate(v: unknown): unknown {
  if (v instanceof Date) {
    return new Date(Date.UTC(v.getFullYear(), v.getMonth(), v.getDate(), v.getHours(), v.getMinutes(), v.getSeconds(), v.getMilliseconds()));
  }
  return v;
}

function makeSql(url: string): Sql {
  const raw = neon(url) as unknown as Sql;
  return async (text, params) => {
    const rows = await raw(text, params);
    for (const r of rows) for (const k of Object.keys(r)) r[k] = fixDate(r[k]);
    return rows;
  };
}

const NOW = "(now() AT TIME ZONE 'utc')";

function cuid(): string {
  const rand = crypto.getRandomValues(new Uint8Array(12));
  const tail = Array.from(rand, (b) => b.toString(36).padStart(2, '0')).join('');
  return 'c' + Date.now().toString(36) + tail.slice(0, 16);
}

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

app.onError((err, c) => {
  const status = err instanceof HttpError ? err.status : 500;
  if (status === 500) console.error('unhandled error', err);
  return c.json(
    {
      statusCode: status,
      message: status === 500 ? 'Internal server error' : err.message,
      timestamp: new Date().toISOString(),
      path: new URL(c.req.url).pathname,
    },
    status as 400
  );
});

async function body<T = Row>(c: Context): Promise<T> {
  try {
    return (await c.req.json()) as T;
  } catch {
    return {} as T;
  }
}

function pick(obj: Row, keys: string[]): Row {
  const out: Row = {};
  for (const k of keys) if (obj && obj[k] !== undefined) out[k] = obj[k];
  return out;
}

async function insert(sql: Sql, table: string, data: Row): Promise<Row> {
  const cols = ['id', ...Object.keys(data), 'createdAt', 'updatedAt'];
  const vals = [cuid(), ...Object.values(data)];
  const ph = vals.map((_, i) => `$${i + 1}`);
  const text = `INSERT INTO "${table}" (${cols.map((x) => `"${x}"`).join(',')}) VALUES (${ph.join(',')}, ${NOW}, ${NOW}) RETURNING *`;
  const rows = (await sql(text, vals)) as Row[];
  return rows[0];
}

async function update(sql: Sql, table: string, id: string, data: Row): Promise<Row> {
  const keys = Object.keys(data);
  const sets = keys.map((k, i) => `"${k}"=$${i + 1}`);
  sets.push(`"updatedAt"=${NOW}`);
  const text = `UPDATE "${table}" SET ${sets.join(',')} WHERE id=$${keys.length + 1} RETURNING *`;
  const rows = (await sql(text, [...keys.map((k) => data[k]), id])) as Row[];
  if (!rows.length) throw new HttpError(404, 'Record to update not found.');
  return rows[0];
}

async function findById(sql: Sql, table: string, id: string): Promise<Row | null> {
  const rows = (await sql(`SELECT * FROM "${table}" WHERE id=$1`, [id])) as Row[];
  return rows[0] ?? null;
}

async function remove(sql: Sql, table: string, id: string): Promise<Row> {
  const rows = (await sql(`DELETE FROM "${table}" WHERE id=$1 RETURNING *`, [id])) as Row[];
  if (!rows.length) throw new HttpError(404, 'Record to delete does not exist.');
  return rows[0];
}

function asIds(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : [];
}

// ---------- auth ----------
const guard = async (c: Context<{ Bindings: Env; Variables: Vars }>, next: Next) => {
  const h = c.req.header('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) throw new HttpError(401, 'Unauthorized');
  let payload: Row;
  try {
    payload = (await verify(m[1], c.env.JWT_ACCESS_SECRET, 'HS256')) as Row;
  } catch {
    throw new HttpError(401, 'Unauthorized');
  }
  const user = payload.userId ? await findById(c.get('sql'), 'User', String(payload.userId)) : null;
  if (!user) throw new HttpError(401, 'Unauthorized');
  c.set('user', user);
  await next();
};

// Optional auth: true only for a valid token whose user has role ADMIN. Never throws.
async function isAdmin(c: Context<{ Bindings: Env; Variables: Vars }>): Promise<boolean> {
  const m = /^Bearer\s+(.+)$/i.exec(c.req.header('Authorization') || '');
  if (!m) return false;
  try {
    const payload = (await verify(m[1], c.env.JWT_ACCESS_SECRET, 'HS256')) as Row;
    const user = payload.userId ? await findById(c.get('sql'), 'User', String(payload.userId)) : null;
    return !!user && user.role === 'ADMIN';
  } catch {
    return false;
  }
}

// Write routes: valid token AND role ADMIN. Others get 403.
const adminGuard = async (c: Context<{ Bindings: Env; Variables: Vars }>, next: Next) => {
  await guard(c, async () => {
    if (c.get('user')?.role !== 'ADMIN') throw new HttpError(403, 'Forbidden');
    await next();
  });
};

async function makeTokens(env: Env, userId: string) {
  const now = Math.floor(Date.now() / 1000);
  return {
    accessToken: await sign({ userId, iat: now, exp: now + 30 * 86400 }, env.JWT_ACCESS_SECRET, 'HS256'),
    refreshToken: await sign({ userId, iat: now, exp: now + 7 * 86400 }, env.JWT_REFRESH_SECRET, 'HS256'),
  };
}

app.post('/auth/google', async (c) => {
  const code = c.req.query('code') ?? '';
  const client = c.req.query('client');
  const redirectUri = client === 'front' ? c.env.FRONT_GOOGLE_CALLBACK_URL : c.env.GOOGLE_CALLBACK_URL;
  const sql = c.get('sql');
  let profile: Row;
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri ?? '',
      }),
    });
    const tokenJson = (await tokenRes.json()) as Row;
    if (!tokenRes.ok || !tokenJson.access_token) {
      throw new Error(tokenJson.error_description || tokenJson.error || `Google token error ${tokenRes.status}`);
    }
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    if (!profileRes.ok) throw new Error(`Google userinfo error ${profileRes.status}`);
    profile = (await profileRes.json()) as Row;
  } catch (e: any) {
    throw new HttpError(401, e?.message || 'Unauthorized');
  }
  let user = ((await sql(`SELECT * FROM "User" WHERE "googleId"=$1 LIMIT 1`, [profile.id])) as Row[])[0];
  if (!user) {
    // The very first user becomes ADMIN, everyone after is USER (decided atomically in SQL).
    const rows = (await sql(
      `INSERT INTO "User" (id,email,firstname,avatar,lastname,"googleId",role,"createdAt","updatedAt")
       VALUES ($1,$2,$3,$4,$5,$6, (CASE WHEN EXISTS (SELECT 1 FROM "User") THEN 'USER' ELSE 'ADMIN' END)::"Role", ${NOW}, ${NOW})
       RETURNING *`,
      [cuid(), profile.email, profile.given_name ?? null, profile.picture ?? null, profile.family_name ?? null, profile.id]
    )) as Row[];
    user = rows[0];
  }
  return c.json({ user, ...(await makeTokens(c.env, user.id)) }, 201);
});

app.get('/auth/me', guard, (c) => c.json(c.get('user')));

// ---------- app ----------
app.get('/', (c) => c.text('nbb'));
app.get('/api', (c) => c.text('nbb api (cloudflare workers)'));
app.get('/api-json', (c) => c.json({ openapi: '3.0.0', info: { title: 'nbb', version: '1.5' }, paths: {} }));

app.get('/dashboard', adminGuard, async (c) => {
  const sql = c.get('sql');
  const [post, photo, project] = await Promise.all([
    sql(`SELECT count(*)::int AS n FROM "Post"`),
    sql(`SELECT count(*)::int AS n FROM "Photo"`),
    sql(`SELECT count(*)::int AS n FROM "Project"`),
  ]);
  return c.json({ post: post[0].n, photo: photo[0].n, project: project[0].n });
});

// Tencent COS temporary key (same signing as src/oss/sts.js)
app.get('/ossKey', adminGuard, async (c) => {
  const secretId = c.env.OSS_ID ?? '';
  const secretKey = c.env.OSS_KEY ?? '';
  const bucket = c.env.OSS_NAME ?? '';
  const region = c.env.OSS_REGION ?? '';
  const allowPrefix = '*';
  const shortBucket = bucket.substring(0, bucket.lastIndexOf('-'));
  const appId = bucket.substring(1 + bucket.lastIndexOf('-'));
  const policy = {
    version: '2.0',
    statement: [
      {
        action: [
          'name/cos:PutObject',
          'name/cos:PostObject',
          'name/cos:InitiateMultipartUpload',
          'name/cos:ListMultipartUploads',
          'name/cos:ListParts',
          'name/cos:UploadPart',
          'name/cos:CompleteMultipartUpload',
        ],
        effect: 'allow',
        principal: { qcs: ['*'] },
        resource: [`qcs::cos:${region}:uid/${appId}:prefix//${appId}/${shortBucket}/${allowPrefix}`],
      },
    ],
  };
  const host = 'sts.tencentcloudapi.com';
  const durationSeconds = 1800;
  const params: Record<string, string | number> = {
    SecretId: secretId,
    Timestamp: Math.floor(Date.now() / 1000),
    Nonce: Math.round(Math.random() * 10000 + 10000),
    Action: 'GetFederationToken',
    DurationSeconds: durationSeconds,
    Version: '2018-08-13',
    Region: region,
    Policy: encodeURIComponent(JSON.stringify(policy)),
    Signature: '',
    RoleSessionName: '',
    RoleArn: '',
    Name: 'cos-sts-nodejs',
  };
  const str = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k] || ''}`)
    .join('&');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secretKey), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`POST${host}/?${str}`));
  params.Signature = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const form = new FormData();
  for (const k of Object.keys(params)) form.append(k, String(params[k]));
  const res = await fetch(`https://${host}/`, { method: 'POST', body: form, headers: { Host: host } });
  const json = (await res.json()) as Row;
  const r = json?.Response;
  if (!r) throw new HttpError(500, 'Empty response');
  if (r.Error) throw new HttpError(500, r.Error.Message || 'COS error');
  r.startTime = r.ExpiredTime - durationSeconds;
  const compat = (d: any): any => {
    const o: Row = {};
    for (const k of Object.keys(d)) {
      const nk = k === 'Token' ? 'sessionToken' : k.charAt(0).toLowerCase() + k.slice(1);
      o[nk] = d[k] && typeof d[k] === 'object' ? compat(d[k]) : d[k];
    }
    return o;
  };
  return c.json(compat(r));
});

// ---------- posts ----------
const POST_KEYS = ['title', 'content', 'authorId', 'categoryId', 'cover', 'html', 'toc', 'published'];
const CAT_COLS = `c.id AS "cat_id", c."createdAt" AS "cat_createdAt", c."updatedAt" AS "cat_updatedAt", c.name AS "cat_name"`;

function withCategory(r: Row): Row {
  const out: Row = {};
  const category: Row = {};
  for (const k of Object.keys(r)) {
    if (k.startsWith('cat_')) category[k.slice(4)] = r[k];
    else out[k] = r[k];
  }
  out.category = category.id ? category : null;
  return out;
}

const POST_SELECT = `SELECT p.*, ${CAT_COLS} FROM "Post" p LEFT JOIN "Category" c ON c.id = p."categoryId"`;

app.post('/posts', adminGuard, async (c) => {
  const sql = c.get('sql');
  const dto = await body(c);
  const data = pick(dto, POST_KEYS);
  data.readingTime = readingTime(String(dto.content ?? '')).minutes.toFixed(0);
  const row = await insert(sql, 'Post', data);
  const full = (await sql(`${POST_SELECT} WHERE p.id=$1`, [row.id])) as Row[];
  return c.json(withCategory(full[0]), 201);
});

app.get('/posts', async (c) => {
  const sql = c.get('sql');
  const search = c.req.query('search');
  const pub = (await isAdmin(c)) ? '' : 'p.published = true';
  const rows = (search
    ? await sql(`${POST_SELECT} WHERE p.content ILIKE $1${pub ? ' AND ' + pub : ''} ORDER BY p."createdAt" DESC`, [`%${search}%`])
    : await sql(`${POST_SELECT}${pub ? ' WHERE ' + pub : ''} ORDER BY p."createdAt" DESC`)) as Row[];
  return c.json(rows.map(withCategory));
});

app.get('/posts/recent', async (c) => {
  const pub = (await isAdmin(c)) ? '' : ' WHERE p.published = true';
  const rows = (await c.get('sql')(`${POST_SELECT}${pub} ORDER BY p."createdAt" DESC LIMIT 3`)) as Row[];
  return c.json(rows.map(withCategory));
});

app.get('/posts/:id', async (c) => {
  const pub = (await isAdmin(c)) ? '' : ' AND p.published = true';
  const rows = (await c.get('sql')(`${POST_SELECT} WHERE p.id=$1${pub}`, [(c.req.param('id') as string)])) as Row[];
  if (!rows.length) return c.body('');
  return c.json(withCategory(rows[0]));
});

app.patch('/posts/:id', adminGuard, async (c) => {
  const sql = c.get('sql');
  const dto = await body(c);
  const data = pick(dto, POST_KEYS);
  if (typeof dto.content === 'string') data.readingTime = readingTime(dto.content).minutes.toFixed(0);
  const id = (c.req.param('id') as string);
  if (Object.keys(data).length) await update(sql, 'Post', id, data);
  const rows = (await sql(`${POST_SELECT} WHERE p.id=$1`, [id])) as Row[];
  if (!rows.length) throw new HttpError(404, 'Record to update not found.');
  return c.json(withCategory(rows[0]));
});

app.delete('/posts/:id', adminGuard, async (c) => c.json(await remove(c.get('sql'), 'Post', (c.req.param('id') as string))));

// ---------- category ----------
app.post('/category', adminGuard, async (c) => {
  const dto = await body(c);
  return c.json(await insert(c.get('sql'), 'Category', pick(dto, ['name'])), 201);
});

app.delete('/category/batch', adminGuard, async (c) => {
  const ids = asIds(await body(c));
  const rows = (await c.get('sql')(`DELETE FROM "Category" WHERE id = ANY($1::text[]) RETURNING id`, [ids])) as Row[];
  return c.json({ count: rows.length });
});

app.get('/category', async (c) => {
  const sql = c.get('sql');
  const cats = (await sql(`SELECT * FROM "Category"`)) as Row[];
  const posts = (await sql(
    `SELECT * FROM "Post" WHERE "categoryId" IS NOT NULL${(await isAdmin(c)) ? '' : ' AND published = true'}`
  )) as Row[];
  return c.json(
    cats.map((cat) => {
      const Post = posts.filter((p) => p.categoryId === cat.id);
      return { ...cat, Post, postCount: Post.length };
    })
  );
});

app.get('/category/:id', async (c) => {
  const row = await findById(c.get('sql'), 'Category', (c.req.param('id') as string));
  return row ? c.json(row) : c.body('');
});

app.patch('/category/:id', adminGuard, async (c) => {
  const sql = c.get('sql');
  const id = (c.req.param('id') as string);
  const data = pick(await body(c), ['name']);
  if (!Object.keys(data).length) {
    const row = await findById(sql, 'Category', id);
    if (!row) throw new HttpError(404, 'Record to update not found.');
    return c.json(row);
  }
  return c.json(await update(sql, 'Category', id, data));
});

app.delete('/category/:id', adminGuard, async (c) => c.json(await remove(c.get('sql'), 'Category', (c.req.param('id') as string))));

// ---------- photos ----------
const PHOTO_KEYS = ['url', 'title', 'content'];

async function photoWithTags(sql: Sql, photo: Row): Promise<Row> {
  const tags = (await sql(
    `SELECT t.* FROM "PhotoTag" t JOIN "_PhotoTagToPhoto" j ON j."B" = t.id WHERE j."A" = $1`,
    [photo.id]
  )) as Row[];
  return { ...photo, PhotoTags: tags };
}

app.post('/photos', adminGuard, async (c) => {
  const sql = c.get('sql');
  const dto = await body(c);
  const tags = Array.from(new Set(asIds(dto.tags)));
  const photo = await insert(sql, 'Photo', pick(dto, PHOTO_KEYS));
  for (const name of tags) {
    await sql(
      `INSERT INTO "PhotoTag" (id,name,"createdAt","updatedAt") VALUES ($1,$2,${NOW},${NOW}) ON CONFLICT (name) DO NOTHING`,
      [cuid(), name]
    );
    await sql(
      `INSERT INTO "_PhotoTagToPhoto" ("A","B") SELECT $1, id FROM "PhotoTag" WHERE name=$2 ON CONFLICT DO NOTHING`,
      [photo.id, name]
    );
  }
  return c.json(await photoWithTags(sql, photo), 201);
});

app.get('/photos/recent', async (c) =>
  c.json(await c.get('sql')(`SELECT * FROM "Photo" ORDER BY "createdAt" DESC LIMIT 9`))
);

app.get('/photos/tags', async (c) => c.json(await c.get('sql')(`SELECT * FROM "PhotoTag"`)));

app.get('/photos', async (c) => c.json(await c.get('sql')(`SELECT * FROM "Photo" ORDER BY "createdAt" DESC`)));

app.delete('/photos/batch', adminGuard, async (c) => {
  const ids = asIds(await body(c));
  const rows = (await c.get('sql')(`DELETE FROM "Photo" WHERE id = ANY($1::text[]) RETURNING id`, [ids])) as Row[];
  return c.json({ count: rows.length });
});

app.get('/photos/:id', async (c) => {
  const row = await findById(c.get('sql'), 'Photo', (c.req.param('id') as string));
  return row ? c.json(row) : c.body('');
});

app.patch('/photos/:id', adminGuard, async (c) => {
  const sql = c.get('sql');
  const id = (c.req.param('id') as string);
  const data = pick(await body(c), PHOTO_KEYS);
  if (!Object.keys(data).length) {
    const row = await findById(sql, 'Photo', id);
    if (!row) throw new HttpError(404, 'Record to update not found.');
    return c.json(row);
  }
  return c.json(await update(sql, 'Photo', id, data));
});

app.delete('/photos/:id', adminGuard, async (c) => c.json(await remove(c.get('sql'), 'Photo', (c.req.param('id') as string))));

// ---------- projects ----------
const PROJECT_KEYS = ['name', 'url', 'image', 'content', 'github', 'postId'];

function projectData(dto: Row): Row {
  const data = pick(dto, PROJECT_KEYS);
  // The generated client sends githubUrl; the column is "github".
  if (data.github === undefined && dto.githubUrl !== undefined) data.github = dto.githubUrl;
  return data;
}

async function projectsWithPost(sql: Sql, where: string, params: unknown[], admin = true): Promise<Row[]> {
  const rows = (await sql(
    `SELECT pr.*, po.id AS "post_id", po."createdAt" AS "post_createdAt", po."updatedAt" AS "post_updatedAt",
            po.title AS "post_title", po.content AS "post_content", po.html AS "post_html", po.toc AS "post_toc",
            po.published AS "post_published", po."authorId" AS "post_authorId", po."categoryId" AS "post_categoryId",
            po."readingTime" AS "post_readingTime", po.cover AS "post_cover", po."projectId" AS "post_projectId"
     FROM "Project" pr LEFT JOIN "Post" po ON po.id = pr."postId" ${where}`,
    params
  )) as Row[];
  return rows.map((r) => {
    const out: Row = {};
    const post: Row = {};
    for (const k of Object.keys(r)) {
      if (k.startsWith('post_')) post[k.slice(5)] = r[k];
      else out[k] = r[k];
    }
    out.post = post.id && (admin || post.published === true) ? post : null;
    return out;
  });
}

app.post('/projects', adminGuard, async (c) => {
  const sql = c.get('sql');
  const row = await insert(sql, 'Project', projectData(await body(c)));
  return c.json((await projectsWithPost(sql, 'WHERE pr.id=$1', [row.id]))[0], 201);
});

app.get('/projects', async (c) => c.json(await projectsWithPost(c.get('sql'), '', [], await isAdmin(c))));

app.delete('/projects/batch', adminGuard, async (c) => {
  const ids = asIds(await body(c));
  const rows = (await c.get('sql')(`DELETE FROM "Project" WHERE id = ANY($1::text[]) RETURNING id`, [ids])) as Row[];
  return c.json({ count: rows.length });
});

app.get('/projects/:id', async (c) => {
  const rows = await projectsWithPost(c.get('sql'), 'WHERE pr.id=$1', [(c.req.param('id') as string)], await isAdmin(c));
  return rows.length ? c.json(rows[0]) : c.body('');
});

app.patch('/projects/:id', adminGuard, async (c) => {
  const sql = c.get('sql');
  const id = (c.req.param('id') as string);
  const data = projectData(await body(c));
  if (Object.keys(data).length) await update(sql, 'Project', id, data);
  const rows = await projectsWithPost(sql, 'WHERE pr.id=$1', [id]);
  if (!rows.length) throw new HttpError(404, 'Record to update not found.');
  return c.json(rows[0]);
});

app.delete('/projects/:id', adminGuard, async (c) => c.json(await remove(c.get('sql'), 'Project', (c.req.param('id') as string))));

// ---------- settings ----------
const SETTING_KEYS = [
  'github', 'githubAvatar', 'weibo', 'weiboAvatar', 'bilibili', 'bilibiliAvatar', 'twitter', 'twitterAvatar', 'photoLayout',
];

app.post('/settings', adminGuard, async (c) =>
  c.json(await insert(c.get('sql'), 'Setting', pick(await body(c), SETTING_KEYS)), 201)
);

app.post('/settings/photo', adminGuard, async (c) => {
  const sql = c.get('sql');
  const layout = await c.req.json().catch(() => []);
  const first = ((await sql(`SELECT * FROM "Setting" LIMIT 1`)) as Row[])[0];
  if (!first) throw new HttpError(500, 'No settings row');
  return c.json(await update(sql, 'Setting', first.id, { photoLayout: JSON.stringify(layout) }), 201);
});

app.get('/settings', async (c) => {
  const row = ((await c.get('sql')(`SELECT * FROM "Setting" LIMIT 1`)) as Row[])[0];
  return row ? c.json(row) : c.body('');
});

app.patch('/settings/:id', adminGuard, async (c) => {
  const sql = c.get('sql');
  const id = (c.req.param('id') as string);
  const data = pick(await body(c), SETTING_KEYS);
  if (!Object.keys(data).length) {
    const row = await findById(sql, 'Setting', id);
    if (!row) throw new HttpError(404, 'Record to update not found.');
    return c.json(row);
  }
  return c.json(await update(sql, 'Setting', id, data));
});

// ---------- comments ----------
app.post('/comments', guard, async (c) => {
  const user = c.get('user');
  const data = pick(await body(c), ['content', 'postId', 'parentId', 'replyToId']);
  data.authorId = user.id;
  return c.json(await insert(c.get('sql'), 'Comment', data), 201);
});

app.get('/comments', async (c) => {
  const sql = c.get('sql');
  const top = (await sql(`SELECT * FROM "Comment" WHERE "parentId" IS NULL ORDER BY "createdAt" DESC`)) as Row[];
  if (!top.length) return c.json([]);
  const topIds = top.map((x) => x.id);
  const children = (await sql(`SELECT * FROM "Comment" WHERE "parentId" = ANY($1::text[])`, [topIds])) as Row[];
  const replyIds = top.map((x) => x.replyToId).filter(Boolean);
  const replies = replyIds.length ? ((await sql(`SELECT * FROM "Comment" WHERE id = ANY($1::text[])`, [replyIds])) as Row[]) : [];
  const authorIds = Array.from(new Set([...top, ...children, ...replies].map((x) => x.authorId)));
  const users = (await sql(`SELECT * FROM "User" WHERE id = ANY($1::text[])`, [authorIds])) as Row[];
  const byId = new Map(users.map((u) => [u.id, u]));
  const replyById = new Map(replies.map((r) => [r.id, r]));
  return c.json(
    top.map((t) => ({
      ...t,
      children: children.filter((ch) => ch.parentId === t.id).map((ch) => ({ ...ch, author: byId.get(ch.authorId) ?? null })),
      author: byId.get(t.authorId) ?? null,
      replyTo: t.replyToId && replyById.get(t.replyToId) ? { ...replyById.get(t.replyToId), author: byId.get(replyById.get(t.replyToId)!.authorId) ?? null } : null,
    }))
  );
});

app.get('/comments/:id', (c) => c.text(`This action returns a #${(c.req.param('id') as string)} comment`));
app.patch('/comments/:id', guard, (c) => c.text(`This action updates a #${(c.req.param('id') as string)} comment`));

app.delete('/comments/:id', guard, async (c) => {
  const sql = c.get('sql');
  const id = (c.req.param('id') as string);
  const comment = await findById(sql, 'Comment', id);
  if (!comment) throw new HttpError(404, 'Comment not found');
  if (comment.authorId !== c.get('user').id && c.get('user').role !== 'ADMIN') throw new HttpError(403, 'Unauthorized');
  return c.json(await remove(sql, 'Comment', id));
});

export default app;

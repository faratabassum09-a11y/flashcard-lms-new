// backend/server.js
// Exam schedules are typed as local time; make the server interpret them in the
// institute's timezone even when hosted on a UTC cloud machine. Override with TZ in .env.
// Vercel presets TZ to ":UTC", which Intl rejects ("Invalid time zone"). Accept only a real zone name.
{ const z = (process.env.TZ || "").replace(/^:/, "");
  process.env.TZ = (z && z !== "UTC" && z !== "Etc/UTC") ? z : "Asia/Kolkata"; }
// Password hashing (pbkdf2) runs on libuv's thread pool (default 4 threads). A classroom logging in
// at the same second would queue behind it, so give it more threads.
process.env.UV_THREADPOOL_SIZE = process.env.UV_THREADPOOL_SIZE || "16";

const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });

const express        = require("express");
const mongoose       = require("mongoose");
const ejsMate        = require("ejs-mate");
const session        = require("express-session");
const MongoStore     = require("connect-mongo").default;
const flash          = require("connect-flash");
const passport       = require("passport");
const LocalStrategy  = require("passport-local");
const methodOverride = require("method-override");
const cron           = require("node-cron");
const compression    = require("compression");
const fmt            = require("./utils/format");
const icons          = require("./utils/icons");
const roles          = require("./utils/roles");
const dbFix          = require("./utils/dbFix");
const userCache      = require("./utils/userCache");
const cache          = require("./utils/cache");
const { finalizeDrafts } = require("./utils/drafts");

const User         = require("./models/user");
const Test         = require("./models/test");
const ExpressError = require("./utils/ExpressError");
const rateLimit    = require("./middleware/rateLimit");

const authRoutes      = require("./routes/authRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const flashcardRoutes = require("./routes/flashcardRoutes");
const testRoutes      = require("./routes/testRoutes");
const adminRoutes     = require("./routes/adminRoutes");
const userRoutes      = require("./routes/userRoutes");

if (!process.env.MONGO_URI || !process.env.SESSION_SECRET) {
  console.error("MONGO_URI and SESSION_SECRET must be set in .env");
  process.exit(1);
}

const ON_VERCEL = !!process.env.VERCEL;
const app = express();
const isProd = process.env.NODE_ENV === "production";
if (isProd || process.env.TRUST_PROXY) app.set("trust proxy", 1);   // correct client IP / secure cookies behind nginx, Render, etc.
app.disable("x-powered-by");
app.use(compression());                      // gzip every HTML/CSS/JS/JSON response (typically 70-80% smaller)

// ── Database ── bigger pool so ~200 simultaneous students are not queued behind 5 connections
mongoose.connect(process.env.MONGO_URI, ON_VERCEL ? { maxPoolSize: 10, serverSelectionTimeoutMS: 15000 } : { maxPoolSize: 50, minPoolSize: 5, serverSelectionTimeoutMS: 15000 })
  .then(async () => {
    console.log("MongoDB connected");
    try {
      await mongoose.connection.db.collection("results").dropIndex("rollNo_1_testId_1");
    } catch (e) { /* already clean */ }
    try { await dbFix.dropStrayUserIndexes(mongoose.connection.db); } catch (e) { console.warn("Index check skipped:", e.message); }
    try { await dbFix.measureDb(mongoose.connection.db); } catch (e) { /* not fatal */ }
  })
  .catch((err) => console.error("MongoDB error:", err));

// Lightweight health check (before session/passport so it never touches the DB)
app.get("/healthz", (req, res) => res.status(mongoose.connection.readyState === 1 ? 200 : 503).send("ok"));

// ── Views / static ──
app.engine("ejs", ejsMate);
app.set("view engine", "ejs");
if (process.env.NODE_ENV !== "development") app.set("view cache", true);     // compile each template once (Express only does this when NODE_ENV=production)
app.set("views", path.join(__dirname, "../frontend/views"));
app.set("layout", "layouts/boilerplate");

const ASSET_V = Date.now().toString(36);      // changes on every restart -> browsers fetch fresh CSS/JS after a deploy
app.use(express.static(path.join(__dirname, "../frontend/public"), { maxAge: isProd ? "30d" : 0, immutable: isProd }));

app.use((req, res, next) => {            // tell the console about slow pages (static files are served above and never logged)
  const t = Date.now();
  res.on("finish", () => { const ms = Date.now() - t; if (ms > 800) console.warn(`[SLOW] ${req.method} ${req.originalUrl} took ${ms} ms`); });
  next();
});

app.use((req, res, next) => {            // basic security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "same-origin");
  next();
});

app.use(express.urlencoded({ extended: true, limit: "1mb", parameterLimit: 5000 }));
app.use(express.json({ limit: "1mb" }));              // an exam can hold up to 200 answers of 4000 characters
app.use((req, res, next) => { if (req.body === undefined) req.body = {}; next(); });   // Express 5 leaves body undefined when a POST has none
app.use(methodOverride("_method"));

// ── Sessions ──
// No `crypto` option: it derived an encryption key with a SYNCHRONOUS PBKDF2 (~10 ms) on every session read/write, which froze
// the server under 300 users. The session only holds the user's id and flash messages (the cookie itself is signed), so nothing
// secret is stored. A new collection name is used because sessions saved by the old encrypted store cannot be read without it
// (students simply sign in once more after this update).
const mongoStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI,
  collectionName: "sessions_v2",
  touchAfter: 24 * 3600
});
const CachedSessionStore = require("./utils/cachedSessionStore");
const store = new CachedSessionStore(mongoStore, { ttlMs: Number(process.env.SESSION_MEMORY_TTL_MS ?? 5 * 60 * 1000) });
store.on("error", (err) => console.error("Session store error", err));

app.use(session({
  store,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   1000 * 60 * 60 * 24 * 7,
    httpOnly: true,
    sameSite: "lax",
    secure:   process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === "true" : ON_VERCEL     // set COOKIE_SECURE=true when served over HTTPS
  }
}));

app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.checkPassword(String(username || ""), String(password || ""));
    if (user) userCache.set(user.username, { _id: user._id, username: user.username, displayName: user.displayName, section: user.section, role: user.role, subjects: user.subjects ? Array.from(user.subjects) : [] });   // next request needs no lookup
    return user ? done(null, user) : done(null, false, { message: "Password or username is incorrect" });
  } catch (e) { return done(e); }
}));
// Only load what every page needs (the full user document carries password hash + study arrays)
passport.serializeUser((user, cb) => cb(null, user.username));
passport.deserializeUser((username, cb) => {
  const hit = userCache.get(username);
  if (hit) return cb(null, hit);
  User.findLeanForSession(username)
    .then(u => { if (u) userCache.set(username, u); cb(null, u || false); }, cb);
});
app.use(flash());

app.use((req, res, next) => {
  // only touch req.flash when a message is waiting: reading it creates session.flash and would force a session save on every first request
  const waiting = req.session && req.session.flash;
  res.locals.success  = waiting && waiting.success ? req.flash("success") : [];
  res.locals.error    = waiting && waiting.error   ? req.flash("error")   : [];
  res.locals.currUser = req.user;
  // isAdmin = "sees the staff console" (admin AND teachers); isSuper = the administrator only
  res.locals.isSuper   = roles.isSuper(req.user);
  res.locals.isTeacher = roles.isTeacher(req.user);
  res.locals.isAdmin   = roles.isStaff(req.user);
  res.locals.path     = req.path;
  res.locals.assetV   = ASSET_V;
  res.locals.fmt      = fmt;
  res.locals.icon     = icons.icon;
  res.locals.sprite   = icons.sprite;
  next();
});

// Pages are user-specific -> never cache them (static files above are unaffected)
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// ── Rate limits ── (keyed per student, NOT per IP: a whole classroom often shares one IP)
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 15,
  keyFn: (req) => `${req.ip}|${String((req.body && req.body.username) || "").toLowerCase().slice(0, 64)}`,
  onLimit: (req, res) => { req.flash("error", "Too many login attempts. Please wait a few minutes."); res.redirect("/login"); }
});
const checkAnswerLimiter = rateLimit({
  windowMs: 60 * 1000, max: 40,
  keyFn: (req) => String(req.user ? req.user._id : req.ip),
  onLimit: (req, res) => res.status(429).json({ percent: 0, error: "Too many checks, slow down" })
});
const draftLimiter = rateLimit({                 // the exam screen saves every ~15 s; 40/min leaves lots of room for retries
  windowMs: 60 * 1000, max: 40,
  keyFn: (req) => String(req.user ? req.user._id : req.ip),
  onLimit: (req, res) => res.status(429).json({ ok: false, message: "Too many saves" })
});
app.post("/login", loginLimiter);
app.post("/test/:id/draft", draftLimiter);
app.post("/check-answer", checkAnswerLimiter);

// ── Background jobs ──
// Render/VPS: node-cron runs them every minute. Vercel (serverless, no always-on process): they run
// opportunistically on incoming requests (throttled) and from /api/cron (daily Vercel cron as a backstop).
let schedRunning = false;
async function runScheduler() {
  if (schedRunning || mongoose.connection.readyState !== 1) return;
  schedRunning = true;
  try {
    const now = new Date();
    await Test.updateMany(
      { scheduledStart: { $lte: now }, isActive: false, isEnded: false },
      { isActive: true, startTime: now }
    );
    await Test.updateMany(
      { scheduledEnd: { $lte: now }, isActive: true, isEnded: false },
      { isActive: false, isEnded: true }
    );
    await Test.updateMany(
      {
        isActive: true, isEnded: false, startTime: { $ne: null },
        $expr: { $lte: [{ $add: ["$startTime", { $multiply: ["$duration", 60000] }] }, now] }
      },
      { isActive: false, isEnded: true }
    );
    cache.clearExam();      // status flags may have changed: next student sees the fresh test
  } catch (err) {
    console.error("Scheduler error:", err.message);
  } finally {
    schedRunning = false;
  }
}

// Safety net: a student whose browser died / battery ran out / network dropped at the end
// still gets a result: their last autosaved answers are marked once the test is over.
let draftsRunning = false;
async function runDraftFinalizer() {
  if (draftsRunning || mongoose.connection.readyState !== 1) return;
  draftsRunning = true;
  try {
    const n = await finalizeDrafts();
    if (n) console.log(`Auto-submitted ${n} unsubmitted answer sheet(s) from saved drafts`);
  } catch (err) {
    console.error("Draft finalizer error:", err.message);
  } finally {
    draftsRunning = false;
  }
}

if (!ON_VERCEL) {
  cron.schedule("* * * * *", runScheduler);
  cron.schedule("* * * * *", runDraftFinalizer);
} else {
  let lastTick = 0;
  app.use((req, res, next) => {            // at most once per 20 s per warm instance; never delays the response
    const now = Date.now();
    if (now - lastTick > 20000 && !req.path.startsWith("/css") && !req.path.startsWith("/js")) {
      lastTick = now;
      runScheduler().then(runDraftFinalizer).catch(() => {});
    }
    next();
  });
  app.get("/api/cron", async (req, res) => {   // Vercel cron sends "Authorization: Bearer $CRON_SECRET"
    if (process.env.CRON_SECRET && req.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).send("no");
    await runScheduler(); await runDraftFinalizer();
    res.send("ok");
  });
}

// ── Routes ──
app.get("/", (req, res) => res.redirect(req.isAuthenticated() ? "/dashboard" : "/login"));
app.use("/", authRoutes);
app.use("/", dashboardRoutes);
app.use("/", flashcardRoutes);
app.use("/", testRoutes);
app.use("/", adminRoutes);
app.use("/", userRoutes);

app.use((req, res, next) => next(new ExpressError(404, "Page not found")));
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  if (statusCode >= 500) console.error(err);
  if (res.headersSent) return next(err);
  res.status(statusCode).render("error", { title: "Error", err: statusCode >= 500 && isProd ? { statusCode, message: "Something went wrong" } : err });
});

if (!ON_VERCEL) {
  const PORT = process.env.PORT || 5000;
  const server = app.listen(PORT, "0.0.0.0", () => console.log(`Server running on ${PORT} (TZ=${process.env.TZ})`));
  server.keepAliveTimeout = 65 * 1000;
  process.on("SIGTERM", () => server.close(() => mongoose.connection.close().then(() => process.exit(0))));
}
process.on("unhandledRejection", (e) => console.error("Unhandled rejection:", e));

module.exports = app;

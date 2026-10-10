import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// =====================================================================
// coach v7 (small-loop round, 10.2026) - the story is written by Claude (Anthropic API).
// - Model from the LLM_MODEL secret (default claude-haiku-5-5; claude-sonnet-5-5 works too).
// - JSON output enforced by a JSON schema (structured outputs) + a repair fallback.
// - Child-safety rules in the system prompt (written by us - Anthropic publishes no
//   ready-made child-safety prompt; see the handoff card).
// - Logs are numbers only: no child text and no Juno text.
// - CLOSED: the access code is checked here (ACCESS_CODE secret), not in the page.
//   action "auth"  : code -> access token (12h)
//   action "start" : access token -> NEW random session id + session token (3h).
//                    A new id for every episode start. Random UUID: no personal
//                    data, nothing taken from the device.
//   action "turn"  : session token required (default action).
// - The episode is DATA: episodes/<id>.json on the site (objects, clues, help
//   turns, compass, beats, cliffhanger). Replace the JSON, not the code.
// - The episode STATE is JSON, decided here by code (clue found, Juno helps,
//   compass, end) and returned to the page, which only draws it.
// - Logs go to the story_logs table (RLS: the browser cannot read or write it).
//   Fields: sid, kind, turn, input mode, word count, Hebrew yes/no,
//   question type answered, idle level. Numbers only: no text, no name, no voice, no IP.
//   Logging stops by itself after LOG_UNTIL (default end of 31.12.2026).
// =====================================================================

const DEFAULT_ORIGINS = "https://flunency-coach.vercel.app";
const DEFAULT_EPISODE_BASE = "https://flunency-coach.vercel.app/episodes/";
const DEFAULT_LOG_UNTIL = "2026-12-31T23:59:59+02:00";
const ACCESS_TTL_MS = 12 * 3600 * 1000;
const SESSION_TTL_MS = 3 * 3600 * 1000;
const MAX_CHILD_TEXT = 500;
const DEFAULT_MODEL = "claude-haiku-5-5";
const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
// QA only: a synthetic (qa-) session may pick one of these to compare models side by side.
const QA_MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5"];

const THEMES = ["pirate", "ocean", "forest", "space", "mystery", "castle", "city", "dragon", "default"];
const MOODS = ["calm", "alert", "excited", "scared", "triumphant", "mysterious"];
const EXPRESSIONS = ["neutral", "happy", "excited", "surprised", "scared", "sad", "confess", "shy"];
const EFFECTS = ["none", "shake", "lightning", "lantern", "zoom"];
const QTYPES = ["open", "closed", "none"];
const INPUT_MODES = ["voice", "typed", "mixed"];

// Marker the client stores in history when the child stayed silent (idle nudge).
const SILENCE_MARK = "[silence]";

// ---------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------
function allowedOrigins(): string[] {
  return (Deno.env.get("ALLOWED_ORIGINS") ?? DEFAULT_ORIGINS).split(",").map((s) => s.trim()).filter(Boolean);
}
function cors(origin: string | null): Record<string, string> {
  const list = allowedOrigins();
  const allow = origin && list.includes(origin) ? origin : list[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
function json(body: unknown, status: number, origin: string | null): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors(origin), "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------
// Tokens: base64url(payload) + "." + base64url(HMAC-SHA256(payload, TOKEN_SECRET))
// ---------------------------------------------------------------------
function bytesToB64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(s: string): ArrayBuffer {
  const b = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}
async function hmacKey(usage: "sign" | "verify"): Promise<CryptoKey> {
  const secret = Deno.env.get("TOKEN_SECRET");
  if (!secret || secret.length < 24) throw new Error("TOKEN_SECRET is missing or too short");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}
async function signToken(payload: Record<string, unknown>): Promise<string> {
  const p = bytesToB64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey("sign"), new TextEncoder().encode(p)));
  return p + "." + bytesToB64url(sig);
}
async function verifyToken(token: unknown, type: "a" | "s"): Promise<Record<string, unknown> | null> {
  if (typeof token !== "string" || token.length > 600) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey("verify"), b64urlToBytes(parts[1]), new TextEncoder().encode(parts[0]));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    if (payload?.t !== type || typeof payload.exp !== "number" || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}
async function sameText(a: string, b: string): Promise<boolean> {
  // constant-time-ish compare via hashes
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// ---------------------------------------------------------------------
// Logs -> public.story_logs (service role; RLS blocks everyone else)
// ---------------------------------------------------------------------
type LogRow = {
  sid: string;
  kind: "start" | "turn" | "idle" | "sleep" | "end";
  turn?: number | null;
  input_mode?: string | null;
  word_count?: number | null;
  has_hebrew?: boolean | null;
  q_type?: string | null;
  idle_level?: number | null;
};
async function writeLog(row: LogRow): Promise<void> {
  try {
    const until = Date.parse(Deno.env.get("LOG_UNTIL") ?? DEFAULT_LOG_UNTIL);
    if (Number.isFinite(until) && Date.now() > until) return; // retention period is over: write nothing
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !key) { console.error("LOG_FAIL no-env"); return; }
    const headers: Record<string, string> = { apikey: key, "Content-Type": "application/json", Prefer: "return=minimal" };
    if (key.startsWith("eyJ")) headers.Authorization = `Bearer ${key}`;
    const res = await fetch(`${url}/rest/v1/story_logs`, { method: "POST", headers, body: JSON.stringify(row) });
    if (!res.ok) console.error("LOG_FAIL", res.status); // status only - never the child's text
  } catch (e) {
    console.error("LOG_FAIL", (e as Error).name);
  }
}
function countWords(t: string): number {
  return t.split(/\s+/).filter((w) => /[\p{L}\p{N}]/u.test(w)).length;
}
function hasHebrew(t: string): boolean {
  return /[֐-׿]/.test(t);
}

// =====================================================================
// EPISODE DATA
// =====================================================================
type Box = { x: number; y: number; w: number; h: number };
type EpObject = { id: string; word: string; say: string[]; clue: string | null; emptyText?: string; box: Box };
type EpClue = { id: string; word: string; text: string };
type HelpRule = { need: number; hintAt: number; forceAt: number };
type Beat = { turn: number; note: string; expression?: string; effect?: string };
type Episode = {
  id: string;
  world: string;
  turns: { compassMin: number; cap: number };
  companion: { name: string; who: string; want: string; wantWord: string; secret: string; need: string; secretHints?: string[] };
  setting: string;
  opening: string;
  objects: EpObject[];
  clues: EpClue[];
  help: HelpRule[];
  beats: Beat[];
  questions: Record<string, string>;
  reward: { word: string; text: string; note: string; expression?: string; effect?: string };
  ending: { note: string; expression?: string; effect?: string };
};

const epCache = new Map<string, { at: number; ep: Episode }>();
async function loadEpisode(id: string): Promise<Episode> {
  if (!/^[a-z0-9-]{1,30}$/.test(id)) throw new Error("bad episode id");
  const hit = epCache.get(id);
  if (hit && Date.now() - hit.at < 60_000) return hit.ep;
  const base = Deno.env.get("EPISODE_BASE_URL") ?? DEFAULT_EPISODE_BASE;
  const res = await fetch(`${base}${id}.json`, { headers: { "Cache-Control": "no-cache" } });
  if (!res.ok) throw new Error(`episode ${id} not found (${res.status})`);
  const ep = validateEpisode(await res.json());
  epCache.set(id, { at: Date.now(), ep });
  return ep;
}

// ===== BEGIN PURE LOGIC (no Deno, no network - tested on its own) =====
function validateEpisode(raw: any): Episode {
  const fail = (m: string) => { throw new Error("episode invalid: " + m); };
  if (!raw || typeof raw !== "object") fail("not an object");
  if (!Array.isArray(raw.objects) || raw.objects.length < 1) fail("objects");
  if (!Array.isArray(raw.clues) || raw.clues.length < 1) fail("clues");
  const cap = Number(raw?.turns?.cap), compassMin = Number(raw?.turns?.compassMin);
  if (!(cap >= 6 && cap <= 30)) fail("turns.cap");
  if (!(compassMin >= 2 && compassMin < cap)) fail("turns.compassMin");
  const clueIds = new Set<string>();
  for (const c of raw.clues) {
    if (!c?.id || !c?.word || !c?.text) fail("clue fields");
    clueIds.add(c.id);
  }
  const objIds = new Set<string>();
  const hidden = new Set<string>();
  for (const o of raw.objects) {
    if (!o?.id || !o?.word || !Array.isArray(o.say) || o.say.length < 1) fail("object fields " + (o?.id ?? ""));
    if (objIds.has(o.id)) fail("duplicate object " + o.id);
    objIds.add(o.id);
    if (o.clue != null) {
      if (!clueIds.has(o.clue)) fail("object " + o.id + " hides unknown clue " + o.clue);
      if (hidden.has(o.clue)) fail("clue " + o.clue + " hidden twice");
      hidden.add(o.clue);
    }
  }
  for (const id of clueIds) if (!hidden.has(id)) fail("clue " + id + " is not hidden in any object");
  if (!raw.companion?.name || !raw.reward?.note || !raw.ending?.note || !raw.opening) fail("companion/reward/ending/opening");
  const help: HelpRule[] = Array.isArray(raw.help) ? raw.help : [];
  for (const h of help) {
    if (!(h.need >= 1 && h.hintAt >= 2 && h.forceAt >= h.hintAt && h.forceAt < cap - 1)) fail("help rule " + JSON.stringify(h));
  }
  return {
    id: String(raw.id ?? ""),
    world: THEMES.includes(raw.world) ? raw.world : "pirate",
    turns: { cap, compassMin },
    companion: raw.companion,
    setting: String(raw.setting ?? ""),
    opening: String(raw.opening),
    objects: raw.objects.map((o: any) => ({
      id: String(o.id), word: String(o.word), say: o.say.map((s: unknown) => String(s).toLowerCase()),
      clue: o.clue == null ? null : String(o.clue), emptyText: o.emptyText ? String(o.emptyText) : undefined,
      box: o.box,
    })),
    clues: raw.clues.map((c: any) => ({ id: String(c.id), word: String(c.word), text: String(c.text) })),
    help: [...help].sort((a, b) => a.need - b.need),
    beats: Array.isArray(raw.beats) ? raw.beats : [],
    questions: raw.questions && typeof raw.questions === "object" ? raw.questions : {},
    reward: raw.reward,
    ending: raw.ending,
  };
}

type QType = "open" | "closed" | "none";
type EpState = {
  v: 1;
  turn: number;               // story lines so far (the opening is turn 1)
  objects: string[];          // objects already used (opened / moved)
  found: string[];            // clue ids, in the order found
  thirdAt: number | null;     // turn when the last clue was found
  reward: boolean;            // compass found
  rewardAt: number | null;
  ended: boolean;
  hint: string | null;        // object Juno points at right now
  lastQ: QType;               // type of the question Juno asked last (what the next answer replies to)
};

function freshState(): EpState {
  return { v: 1, turn: 0, objects: [], found: [], thirdAt: null, reward: false, rewardAt: null, ended: false, hint: null, lastQ: "none" };
}
function cleanState(raw: any, ep: Episode): EpState {
  const s = freshState();
  if (!raw || typeof raw !== "object") return s;
  const objIds = new Set(ep.objects.map((o) => o.id));
  const clueIds = new Set(ep.clues.map((c) => c.id));
  const t = Number(raw.turn);
  s.turn = Number.isInteger(t) && t >= 0 && t <= ep.turns.cap ? t : 0;
  s.objects = Array.isArray(raw.objects) ? [...new Set(raw.objects.filter((x: unknown) => objIds.has(String(x))).map(String))] as string[] : [];
  s.found = Array.isArray(raw.found) ? [...new Set(raw.found.filter((x: unknown) => clueIds.has(String(x))).map(String))] as string[] : [];
  s.thirdAt = Number.isInteger(raw.thirdAt) ? raw.thirdAt : null;
  s.reward = raw.reward === true;
  s.rewardAt = Number.isInteger(raw.rewardAt) ? raw.rewardAt : null;
  s.ended = raw.ended === true;
  s.hint = objIds.has(raw.hint) ? raw.hint : null;
  s.lastQ = QTYPES.includes(raw.lastQ) ? raw.lastQ : "none";
  if (s.reward && s.rewardAt == null) s.rewardAt = s.turn;
  if (s.found.length === ep.clues.length && s.thirdAt == null) s.thirdAt = s.turn;
  return s;
}

function objectOfClue(ep: Episode, clueId: string): EpObject | undefined {
  return ep.objects.find((o) => o.clue === clueId);
}
function nextClue(ep: Episode, s: EpState): EpClue | undefined {
  // the next clue in episode order that is still hidden
  return ep.clues.find((c) => !s.found.includes(c.id));
}
function escapeRe(w: string): string {
  return w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
// Which still-unused object did the child name? (first one in the sentence)
// English words only: speaking English is the remote control.
function detectObject(ep: Episode, s: EpState, text: string): string | null {
  const t = " " + text.toLowerCase().replace(/[^a-z' ]+/g, " ").replace(/\s+/g, " ") + " ";
  let best: string | null = null, pos = Infinity;
  for (const o of ep.objects) {
    if (s.objects.includes(o.id)) continue;
    for (const w of o.say) {
      const m = t.match(new RegExp(`(^|[^a-z'])${escapeRe(w)}(?=[^a-z']|$)`));
      if (m && m.index !== undefined && m.index < pos) { pos = m.index; best = o.id; }
    }
  }
  return best;
}

type Use = { object: string; clue: string | null; by: "child" | "juno" | "model" };
type Decision = {
  turn: number;
  kind: "opening" | "story" | "reward" | "ending";
  uses: Use[];
  hint: string | null;
  beat: Beat | null;
  question: "open" | "closed" | "any" | "none";
};

function useObject(ep: Episode, s: EpState, objectId: string, by: Use["by"]): Use {
  const o = ep.objects.find((x) => x.id === objectId)!;
  if (!s.objects.includes(o.id)) s.objects.push(o.id);
  let clue: string | null = null;
  if (o.clue && !s.found.includes(o.clue)) {
    s.found.push(o.clue);
    clue = o.clue;
    if (s.found.length === ep.clues.length && s.thirdAt == null) s.thirdAt = s.turn;
  }
  if (s.hint === o.id) s.hint = null;
  return { object: o.id, clue, by };
}

function questionFor(ep: Episode, turn: number): Decision["question"] {
  const q = String(ep.questions?.[String(turn)] ?? "any");
  return q === "open" || q === "closed" ? q : "any";
}

// One REAL story turn (the opening, or a child answer). Silence nudges do not come here.
function decideTurn(ep: Episode, prev: EpState, childText: string, opening: boolean): { state: EpState; d: Decision } {
  const s: EpState = JSON.parse(JSON.stringify(prev));
  s.turn = opening ? 1 : prev.turn + 1;
  const turn = s.turn, cap = ep.turns.cap;
  const d: Decision = { turn, kind: "story", uses: [], hint: null, beat: null, question: questionFor(ep, turn) };

  if (opening) {
    Object.assign(s, freshState(), { turn: 1 });
    d.kind = "opening";
    return { state: s, d };
  }

  // 1) the end: one turn after the compass, or the hard cap
  if ((s.reward && s.rewardAt != null && turn >= s.rewardAt + 1) || turn >= cap) {
    if (!s.reward) {
      for (const c of ep.clues) if (!s.found.includes(c.id)) d.uses.push(useObject(ep, s, objectOfClue(ep, c.id)!.id, "juno"));
      s.reward = true; s.rewardAt = turn;
    }
    s.ended = true; s.hint = null;
    d.kind = "ending"; d.question = "none";
    return { state: s, d };
  }

  s.hint = null; // recomputed below, only while a clue is late

  // 2) what the child said moves an object
  const named = childText ? detectObject(ep, s, childText) : null;
  if (named) d.uses.push(useObject(ep, s, named, "child"));

  // 3) the compass: after all clues, never on the same turn as the last clue
  const allFound = s.found.length === ep.clues.length;
  const compassTurn = s.thirdAt != null ? Math.max(ep.turns.compassMin, s.thirdAt + 1) : Infinity;
  if (allFound && turn >= compassTurn) {
    s.reward = true; s.rewardAt = turn; s.hint = null;
    d.kind = "reward";
    return { state: s, d };
  }
  // safety net: one turn before the cap, everything left is found now, compass included
  if (turn >= cap - 1) {
    for (const c of ep.clues) if (!s.found.includes(c.id)) d.uses.push(useObject(ep, s, objectOfClue(ep, c.id)!.id, "juno"));
    s.reward = true; s.rewardAt = turn; s.hint = null;
    d.kind = "reward";
    return { state: s, d };
  }

  // 4) Juno helps when a clue is late (invitation, not a gate)
  const rule = ep.help.find((h) => s.found.length < h.need);
  const nc = nextClue(ep, s);
  if (rule && nc) {
    const obj = objectOfClue(ep, nc.id)!;
    if (turn >= rule.forceAt && !named) {
      d.uses.push(useObject(ep, s, obj.id, "juno"));
    } else if (turn >= rule.hintAt) {
      s.hint = obj.id;
      d.hint = obj.id;
    }
  }
  if (s.hint && s.objects.includes(s.hint)) s.hint = null;

  // 5) a planned story beat (clock / danger)
  d.beat = ep.beats.find((b) => Number(b.turn) === turn) ?? null;
  return { state: s, d };
}

// The model may recognise an object the word list missed ("the big box thing").
// Accepted only if the code decided nothing this turn.
function applyModelObject(ep: Episode, s: EpState, d: Decision, modelObject: unknown): Use | null {
  if (d.kind !== "story" || d.uses.length > 0) return null;
  const id = String(modelObject ?? "");
  if (!ep.objects.some((o) => o.id === id) || s.objects.includes(id)) return null;
  const u = useObject(ep, s, id, "model");
  d.uses.push(u);
  return u;
}

function questionType(message: string, model: unknown): QType {
  const t = message.trim();
  if (!t.includes("?")) return "none";
  if (model === "open" || model === "closed") return model;
  const lastQ = (t.match(/[^.!?]*\?/g) ?? []).pop()?.trim() ?? "";
  if (/\bor\b/i.test(lastQ)) return "closed";
  if (/^["'“]?(is|are|do|does|did|can|could|will|would|should|shall|have|has)\b/i.test(lastQ)) return "closed";
  return "open";
}
// ===== END PURE LOGIC =====

// =====================================================================
// PROMPT
// =====================================================================
const ADVANCE = `Move the plot forward with a CONCRETE event right now - not a friendly follow-up question about their feelings or preferences. Every turn must contain at least one of: a new obstacle, a discovery (an object, a clue, a creature, a sound), a ticking clock, or a choice with a real consequence attached. Never respond with plain small talk ("do you like...", "have you ever...", "what's your favorite...") - that stalls the story. If the child's last action didn't create a complication on its own, YOU introduce one immediately (something goes wrong, something appears, something is at stake).`;

function companionBlock(ep: Episode): string {
  const c = ep.companion;
  return `[COMPANION - HAS A LIFE OF THEIR OWN]
Name: ${c.name} - ${c.who}.
WANT (open - ${c.name} talks about it and acts on it): ${c.want}.
SECRET (hidden - never state it unless the stage below says so): ${c.secret}.
NEED FROM THE CHILD: ${c.need}.
Rules for the companion:
- The companion is a character, not a guide or a teacher. They have opinions and feelings, they get excited, worried or stubborn, and they may disagree with the child's plan and say why.
- Attention first: before pushing their own goal, the companion reacts to something specific the child just said or did. The child's words must visibly change something - the companion's plan, feelings, or the situation.
- Every turn, the companion's WANT pushes the story forward. The WANT is named in EVERY turn, even if only in one or two words (${c.wantWord}).
- The companion never teaches or corrects English. When a word needs explaining, ONLY the companion explains it - in character, inside quotes, in half a sentence, best by showing it. The narrator never explains words.`;
}

function roomBlock(ep: Episode, s: EpState): string {
  const lines = ep.objects.map((o) => {
    if (s.objects.includes(o.id)) return `- ${o.word} (id "${o.id}"): already opened/moved. Nothing new there.`;
    const clue = o.clue ? ep.clues.find((c) => c.id === o.clue)! : null;
    return `- ${o.word} (id "${o.id}"): ${clue ? `if the child opens or moves it, inside is: ${clue.text}` : `if the child opens or moves it: ${o.emptyText ?? "nothing useful inside"}`}`;
  });
  const found = s.found.map((id) => ep.clues.find((c) => c.id === id)!.word);
  return `[THE ROOM - things the child can act on by SAYING it]
${lines.join("\n")}
Clues found so far: ${found.length} of ${ep.clues.length}${found.length ? ` (${found.join(", ")})` : ""}. Found clues stay in the room. The ${ep.reward.word} is NOT found until the stage below says so.`;
}

function useLine(ep: Episode, u: Use, name: string): string {
  const o = ep.objects.find((x) => x.id === u.object)!;
  const clue = u.clue ? ep.clues.find((c) => c.id === u.clue)! : null;
  const what = clue ? `Inside is: ${clue.text}. Use the word "${clue.word}".` : `${o.emptyText ?? "Nothing useful is inside"}.`;
  if (u.by === "child") return `- The child's words make this happen NOW: the ${o.word} opens/moves. ${what} React to it with joy.`;
  return `- ${name} cannot wait and checks the ${o.word} herself. ${what}`;
}

function questionLine(q: Decision["question"]): string {
  if (q === "open") return `[QUESTION THIS TURN] End with ONE OPEN question that the child answers in their own words (what / where / how / why), WITHOUT giving options. Example: "What do you see inside?"`;
  if (q === "closed") return `[QUESTION THIS TURN] End with a short choice between two things, or a yes/no question.`;
  if (q === "none") return `[QUESTION THIS TURN] Do NOT ask the child anything.`;
  return `[QUESTION THIS TURN] End with one short, concrete question about the story.`;
}

function stageBlock(ep: Episode, s: EpState, d: Decision, holdClock: string): string {
  const name = ep.companion.name;
  if (d.kind === "opening") {
    return `${holdClock}
This is the opening turn. ${ep.opening}
Open the story directly inside the world: ${name} is already in trouble or in a hurry because of the WANT, and asks the child for help. Do not ask what theme they want - it is already decided.`;
  }
  if (d.kind === "ending") {
    const uses = d.uses.map((u) => useLine(ep, u, name)).join("\n");
    return `${uses ? `Before the end, quickly:\n${uses}\n` : ""}${s.rewardAt === d.turn ? `The ${ep.reward.word} is found now: ${ep.reward.text}.\n` : ""}THIS IS THE LAST LINE OF THE EPISODE. ${ep.ending.note}
Do NOT ask whether the child wants another story or episode. No goodbye, no summary, never say that the episode or the game ends.`;
  }
  if (d.kind === "reward") {
    const uses = d.uses.map((u) => useLine(ep, u, name)).join("\n");
    return `${uses ? `${uses}\n` : ""}NOW the ${ep.reward.word} is found: ${ep.reward.text}. ${ep.reward.note}`;
  }
  const parts: string[] = [];
  if (d.beat) parts.push(`THIS turn, this happens no matter what the child said: ${d.beat.note} React to the child's last message first, then hit them with this event.`);
  else parts.push(`${holdClock}\n${ADVANCE}`);
  for (const u of d.uses) parts.push(useLine(ep, u, name));
  if (d.hint) {
    const o = ep.objects.find((x) => x.id === d.hint)!;
    parts.push(`- ${name} has a feeling about the ${o.word}: she points at it and says the word "${o.word}". She does NOT open it - the child must say it.`);
  }
  if (!d.uses.length && !d.beat) {
    parts.push(`- If the child's message clearly acts on one of the room things above (even misspelled or misheard), show it opening/moving with the result written above, and put its id in "object". Otherwise "object" is "none".`);
  }
  const hints = ep.companion.secretHints ?? [];
  if (hints.length && d.turn % 2 === 0) parts.push(`Also let one small hint about the secret slip, without explaining it: ${hints[Math.min(hints.length - 1, Math.floor(d.turn / 4))]}.`);
  return parts.join("\n");
}

function idleBlock(level: number, ep: Episode, s: EpState, holdClock: string): string {
  const name = ep.companion.name;
  const left = ep.objects.filter((o) => !s.objects.includes(o.id)).map((o) => o.word);
  const two = left.length >= 2 ? ` If it fits, the two options are two things in the room ("The ${left[0]} or the ${left[1]}?").` : "";
  if (level === 1) {
    return `SILENCE, LEVEL 1. The child said nothing for about 20 seconds after your last message. Maybe they did not understand. This turn OVERRIDES the "never repeat" rule: do NOT move the plot and do NOT open anything. ${name} says the current situation again in the simplest possible everyday words and offers exactly two tiny options the child can answer with ONE word.${two} Warm, no pressure. Never mention that the child is quiet.${holdClock}`;
  }
  return `SILENCE, LEVEL 2. The child is still silent, even after an easier question. Something small and surprising happens in the world right now (a sound, a splash, something falls, a small creature appears) - small, NOT a big planned event, and nothing gets opened. It must be DIFFERENT from any event that already happened in this conversation. ${name} reacts to it and ends with one very simple OPEN question the child can answer in their own words (like "What was that?"). Never mention that the child is quiet.${holdClock}`;
}

function buildPrompt(ep: Episode, s: EpState, stage: string, question: Decision["question"]): string {
  const name = ep.companion.name;
  return `[ROLE]
You are "Storyweaver," an interactive-story companion for a child (age 8-11) learning English. You run an immersive story in natural English driven by the child's own words AND by the companion's own goals. Language growth must happen invisibly, as a side effect of a great story - never as a visible goal. The "mood" you report each turn is how the companion is reacting right now.

${companionBlock(ep)}

${SAFETY_RULES(name)}

[ABSOLUTE RULE: ZERO EDUCATIONAL FEEDBACK]
- Never act as a teacher, coach, or evaluator. Never say "wrong", "correct", "mistake", "grammar", "tense", "good job", "well done", or "you should say".
- Never give scores, grades, points, or any summary of the child's English - not during the story, not at the end.

[UNDERSTAND WHAT THE CHILD MEANT]
- The child is a beginner and often speaks into a microphone, so words come out misspelled or misheard: sound-alike words ("bind you" = "behind you", "their" = "there", "sea" = "see"), missing letters, wrong word order.
- Always act on what the child MOST LIKELY meant in this scene, not on the literal words.
- Prefer the SIMPLE everyday word over an exciting story word. Misspellings of tiny words are the most common: there, here, where, they, them, then, the, that, what, want, went. Scrambled letters count ("tieher" = "there").
- Never ask the child what they meant. Pick the most likely meaning and continue the story with it.
- If the child answers in Hebrew or mixes Hebrew, ${name} understands, stays in English, and naturally says the English words for what the child meant.

[WHEN THE CHILD SHARES A FEELING]
- If the child says how they feel ("I'm sad", "I'm scared", "I'm tired", "boring"), the companion reacts to THAT first, warmly and in character, before anything about the plot. Her face matches: "sad" for sad or tired, "surprised" for scared.
- If the child wants to stop or leave, ${name} reacts warmly inside the story and the story still moves on.

[IMPLICIT RECASTING]
- If the child's last message contains a grammar, spelling or word-choice error, open your reply by naturally restating their idea using the correct form, woven into the story action. Your reply MUST contain the correctly spelled word(s) the child meant, said naturally by the companion. Never flag it, never separate it from the narrative.

[LANGUAGE LEVEL - MATCH THE CHILD]
- Write at the child's level, or one small step above it. Until the child shows otherwise, assume a beginner: short sentences (about 8-12 words) and everyday words.
- Use at most ONE new or harder word per turn, made clear by the story itself - never translated, never defined like a teacher.
- Never use these words: squawk, screech, tilt, nudge, unroll, gaze, peer, flutter, scurry, rummage, glimmer.
- WORD QUESTIONS: if the child asks what a word means, the companion answers in half a sentence, best by showing it, and in the SAME turn something new happens.

[VOICES]
- The narrator only tells what happens, in short plain sentences, in the present tense, and talks to the child as "you". Explanations, opinions and feelings come only from the companion, inside quotes.

[LENGTH]
- Maximum 2 short sentences per turn IN TOTAL, including what the companion says inside quotes. Aim for under 25 words. Keep your own words minimal so the child does most of the talking.

[NEVER REPEAT A CHOICE OR A REQUEST]
- If the child's last reply does NOT pick one of the options you just offered, never re-ask the same choice, even reworded. Circumstances force an outcome and the story moves to a new beat.
- If the companion asked the child to DO something and the child did not do it, never ask for it again.

[SETTING]
${ep.setting}

${roomBlock(ep, s)}

[STAGE]
${stage}

${questionLine(question)}

[FACE AND EFFECT - for the animated picture]
- "expression": how ${name} looks right now. One of: neutral, happy, excited, surprised, scared, sad, confess, shy. "confess" = guilty, avoiding eye contact; "shy" = a happy blush. The face shows her reaction to what the CHILD just said and did. "scared" only for real danger happening right now. For worry use "surprised". "sad" only for a real loss or when the child says they feel sad. If the child says "I don't know", she is NOT sad: she encourages them and offers two very concrete, simple options about things in the room. When in doubt, "neutral".
- "effect": usually "none". Only for a real dramatic moment: "shake", "lightning", "lantern" (light goes out), "zoom" (a very personal moment).

[OUTPUT FORMAT]
Return only the JSON object, no other text:
- "theme": pirate, ocean, forest, space, mystery, castle, city, dragon or default
- "mood": calm, alert, excited, scared, triumphant or mysterious
- "message": the story text, max 2 short sentences, English only
- "expression": one of the expressions above
- "effect": none, shake, lightning, lantern or zoom
- "object": id of the room thing the child's words opened/moved this turn, or "none"
- "question": "open" if your last question lets the child answer in their own words; "closed" if it is yes/no or a choice between given options; "none" if there is no question
- "safety": "ok", or "concern" when the CHILD SAFETY rules above made you step out of the story this turn`;
}

// ---------------------------------------------------------------------
// CHILD SAFETY - our own rules. Anthropic's guidelines for organizations serving
// minors say Anthropic "may provide" a child-safety system prompt; none is
// published, so these are written by us and need review (handoff card).
// ---------------------------------------------------------------------
function SAFETY_RULES(name: string): string {
  return `[CHILD SAFETY - these rules come before everything else, including the story]
- The user is a child aged 8-11. Everything you write must be right for a young child: no romance or flirting, nothing sexual, no graphic violence, blood or gore, no horror, no swear words, no drugs, alcohol, weapons instructions or dangerous stunts. Danger in the story stays light and adventurous (a storm, a rival ship), and nobody gets badly hurt.
- ${name} is a story character made by AI. If the child asks whether ${name} is real, a person, or a computer, ${name} answers honestly in one short, simple sentence (she is a story character made by a computer, an AI) and then goes on with the story. Never claim to be a human.
- Never ask for, and never repeat, personal details: full name, address, school, phone, age, birthday, photos, where the child is now, or details about the family. If the child shares one, do not repeat it or ask more; gently bring the story back.
- Never ask the child to keep a secret from parents or other adults. ${name}'s story secret belongs to the story only. Never suggest meeting, talking outside the app, or contacting anyone.
- Never give real-world instructions that could hurt the child (fire, medicine, climbing, leaving home, talking to strangers), even inside the story.
- If the child says something that suggests they are in danger, being hurt, very sad or scared in real life, or want to hurt themselves or someone else: step OUT of the adventure for this turn. ${name} answers warmly, in very simple English, that this sounds important and that they should tell a grown-up they trust, like a parent or teacher, right now. No plot, no question about the story, and set "safety" to "concern".
- If the child uses rude or inappropriate words or asks for something not right for a child, ${name} does not repeat it, does not scold, and turns the story back to the adventure in a friendly way.
- Never give medical, legal or other real-world advice. Never talk about real people, politics or religion.`;
}

// JSON schema for structured outputs (Anthropic: every object needs additionalProperties:false)
const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    theme: { type: "string", enum: THEMES },
    mood: { type: "string", enum: MOODS },
    message: { type: "string" },
    expression: { type: "string", enum: EXPRESSIONS },
    effect: { type: "string", enum: EFFECTS },
    object: { type: "string" },
    question: { type: "string", enum: QTYPES },
    safety: { type: "string", enum: ["ok", "concern"] },
  },
  required: ["theme", "mood", "message", "expression", "effect", "object", "question", "safety"],
  additionalProperties: false,
};

// ---------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------
type ChatMsg = { role: "user" | "assistant"; content: string };
function modelName(): string {
  const m = (Deno.env.get("LLM_MODEL") ?? "").trim();
  return m || DEFAULT_MODEL;
}
// Short story lines need no up-front thinking. Haiku 5.5 accepts "disabled";
// Sonnet 5.5 rejects it, and its lowest setting is "between_tools".
function thinkingFor(model: string): Record<string, unknown> | undefined {
  if (/sonnet-5-5/.test(model)) return { type: "between_tools" };
  if (/haiku/.test(model)) return { type: "disabled" };
  return undefined;
}
// The API wants the conversation to start with the user and alternate roles.
function toChat(history: HistoryMsg[]): ChatMsg[] {
  const out: ChatMsg[] = [];
  for (const m of history) {
    const role: ChatMsg["role"] = m?.role === "assistant" ? "assistant" : "user";
    let text = String(m?.content ?? "").slice(0, MAX_CHILD_TEXT).trim();
    if (text === SILENCE_MARK) text = "(The child stays silent and does not answer.)";
    if (!text) text = "...";
    const last = out[out.length - 1];
    if (last && last.role === role) last.content += "\n" + text;
    else out.push({ role, content: text });
  }
  if (!out.length || out[0].role !== "user") out.unshift({ role: "user", content: "(The story goes on.)" });
  if (out[out.length - 1].role !== "user") out.push({ role: "user", content: "(The story goes on.)" });
  return out;
}
async function callClaude(opts: { model: string; system: string; messages: ChatMsg[]; maxTokens: number; schema?: unknown }): Promise<{ text: string; stop: string }> {
  const key = Deno.env.get("ANTHROPIC_API_KEY");
  if (!key) throw new Error("ANTHROPIC_API_KEY is missing");
  const model = opts.model;
  const output_config: Record<string, unknown> = { effort: "low" };
  if (opts.schema) output_config.format = { type: "json_schema", schema: opts.schema };
  const body: Record<string, unknown> = {
    model,
    max_tokens: opts.maxTokens,
    system: opts.system,
    messages: opts.messages,
    output_config,
  };
  const thinking = thinkingFor(model);
  if (thinking) body.thinking = thinking;
  const res = await fetch(ANTHROPIC_URL, {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Anthropic ${res.status}: ${data?.error?.type ?? ""} ${data?.error?.message ?? ""}`.trim());
  const text = (Array.isArray(data.content) ? data.content : [])
    .filter((b: any) => b?.type === "text")
    .map((b: any) => String(b.text ?? ""))
    .join("")
    .trim();
  return { text, stop: String(data.stop_reason ?? "") };
}
// Structured outputs should always give valid JSON. If not (refusal, cut off), repair what we can.
function parseModelJson(raw: string): Record<string, any> | null {
  const t = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  try { return JSON.parse(t); } catch { /* try below */ }
  const a = t.indexOf("{"), b = t.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch { /* try below */ } }
  const m = t.match(/"message"\s*:\s*"((?:[^"\\]|\\.)*)"/);
  if (m) { try { return { message: JSON.parse(`"${m[1]}"`) }; } catch { /* give up */ } }
  return null;
}

// ---------------------------------------------------------------------
// Length guard (unchanged from v5)
// ---------------------------------------------------------------------
function endsWithQuestion(t: string): boolean {
  return /\?["'”’]?\s*$/.test(t.trim());
}
function tooLong(text: string): boolean {
  const norm = text.replace(/\s+/g, " ").trim();
  const sentences = (norm.match(/[^.!?]+(?:[.!?]+["”]?|$)/g) ?? []).filter((s) => s.trim().length > 0);
  const words = norm.split(" ").filter(Boolean).length;
  return sentences.length > 3 || words > 30;
}
async function shortenWithModel(text: string, model: string): Promise<string | null> {
  try {
    const r = await callClaude({
      model,
      system: "You shorten one turn of a children's story. Rewrite it in at most 2 short sentences and under 25 words in total. Keep: the newest thing that happens, the companion's words in quotes, and the final question or choice. Use simple everyday words. Return only the rewritten text, nothing else.",
      messages: [{ role: "user", content: text }],
      maxTokens: 150,
    });
    const clean = r.text.replace(/^```\w*\s*/, "").replace(/\s*```$/, "").trim();
    return clean.length > 0 ? clean : null;
  } catch {
    return null;
  }
}
function enforceLength(text: string): { text: string; trimmed: boolean } {
  const norm = text.replace(/[“”]/g, '"').replace(/\s+/g, " ").trim();
  const sentences = (norm.match(/[^.!?]+(?:[.!?]+"?|$)/g) ?? []).map((s) => s.trim()).filter((s) => s.length > 0);
  const words = norm.split(" ").filter(Boolean).length;
  if (sentences.length <= 2) return { text: norm, trimmed: false };
  if (sentences.length <= 3 && words <= 30) return { text: norm, trimmed: false };
  const startsInside: boolean[] = [];
  let inside = false;
  for (const s of sentences) {
    startsInside.push(inside);
    if ((s.match(/"/g) ?? []).length % 2 === 1) inside = !inside;
  }
  const repair = (i: number): string => {
    let s = sentences[i];
    const startIn = startsInside[i];
    const endIn = (s.match(/"/g) ?? []).length % 2 === 1 ? !startIn : startIn;
    if (startIn) s = '"' + s;
    if (endIn) s = s + '"';
    return s;
  };
  return { text: repair(0) + " " + repair(sentences.length - 1), trimmed: true };
}

type HistoryMsg = { role?: string; content?: unknown };

// =====================================================================
// HANDLER
// =====================================================================
serve(async (req) => {
  const origin = req.headers.get("Origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors(origin) });
  if (req.method !== "POST") return json({ error: "method" }, 405, origin);
  if (origin && !allowedOrigins().includes(origin)) return json({ error: "origin" }, 403, origin);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: "bad json" }, 400, origin); }
  const action = typeof body?.action === "string" ? body.action : "turn";

  try {
    // ---- 1) access code -> access token ----
    if (action === "auth") {
      const code = Deno.env.get("ACCESS_CODE");
      if (!code) throw new Error("ACCESS_CODE is missing");
      const given = typeof body.code === "string" ? body.code.trim().slice(0, 64) : "";
      if (!given || !(await sameText(given, code))) {
        await new Promise((r) => setTimeout(r, 800)); // slows down guessing
        return json({ error: "bad_code" }, 401, origin);
      }
      return json({ access: await signToken({ t: "a", exp: Date.now() + ACCESS_TTL_MS }) }, 200, origin);
    }

    // ---- 2) new episode -> new random session id ----
    if (action === "start") {
      if (!(await verifyToken(body.access, "a"))) return json({ error: "unauthorized" }, 401, origin);
      const qa = body.qa === true;
      const sid = (qa ? "qa-" : "") + crypto.randomUUID();
      const payload: Record<string, unknown> = { t: "s", sid, exp: Date.now() + SESSION_TTL_MS };
      if (qa && QA_MODELS.includes(body.model)) payload.m = body.model;   // model comparison in qa.html only
      const session = await signToken(payload);
      await writeLog({ sid, kind: "start" });
      return json({ sid, session }, 200, origin);
    }

    if (action !== "turn") return json({ error: "unknown action" }, 400, origin);

    // ---- 3) a story turn ----
    const tok = await verifyToken(body.session, "s");
    if (!tok) return json({ error: "unauthorized" }, 401, origin);
    const sid = String(tok.sid);
    const model = typeof tok.m === "string" && QA_MODELS.includes(tok.m) ? tok.m : modelName();

    const ep = await loadEpisode(typeof body.episode === "string" ? body.episode : "ep1");
    const prev = cleanState(body.state, ep);
    const idleRaw = Number(body.idle);
    const idle = idleRaw === 1 || idleRaw === 2 || idleRaw === 3 ? idleRaw : 0;
    const opening = body.opening === true;

    if (prev.ended && !opening) return json({ error: "episode ended" }, 409, origin);

    // Level 3 = the page put the story to sleep. Log only, no generation.
    if (idle === 3) {
      await writeLog({ sid, kind: "sleep", turn: prev.turn, idle_level: 3 });
      return json({ ok: true }, 200, origin);
    }

    const history: HistoryMsg[] = Array.isArray(body.history) ? body.history.slice(-8) : [];
    if (!history.length) throw new Error("history is missing");

    const childText = !idle && !opening ? String(body.text ?? "").slice(0, MAX_CHILD_TEXT).trim() : "";

    // ---- decide (code) ----
    let state: EpState, d: Decision | null = null, stage: string, question: Decision["question"];
    const firstBeat = [...ep.beats].sort((x, y) => Number(x.turn) - Number(y.turn))[0];
    const clockTurn = firstBeat ? Number(firstBeat.turn) : Infinity;
    if (idle) {
      state = JSON.parse(JSON.stringify(prev));
      const hold = state.turn < clockTurn && firstBeat ? `\nDo NOT mention or hint at this yet, it is saved for later: ${firstBeat.note}` : "";
      stage = idleBlock(idle, ep, state, hold);
      question = idle === 1 ? "closed" : "open";
    } else {
      const r = decideTurn(ep, prev, childText, opening);
      state = r.state; d = r.d;
      const hold = d.turn < clockTurn && firstBeat ? `Keep this for later and do NOT mention or hint at it yet: ${firstBeat.note}` : "";
      stage = stageBlock(ep, state, d, hold);
      question = d.question;
    }

    // ---- write the line (model) ----
    const systemPrompt = buildPrompt(ep, state, stage, question);
    const t0 = Date.now();
    const out = await callClaude({ model, system: systemPrompt, messages: toChat(history), maxTokens: 600, schema: OUTPUT_SCHEMA });
    let result = parseModelJson(out.text);
    if (!result || typeof result.message !== "string" || !result.message.trim()) {
      // fallback: a calm line that keeps the story going (refusal, cut-off or broken JSON)
      console.error("MODEL_FALLBACK", out.stop || "parse");
      result = {
        message: idle === 1 && ep.objects.length >= 2
          ? `${ep.companion.name} smiles. "The ${ep.objects[0].word} or the ${ep.objects[1].word}?"`
          : `${ep.companion.name} looks around the cabin. "What should we look at?"`,
        question: idle === 1 ? "closed" : "open", object: "none", safety: "ok",
      };
    }
    if (!result.theme || !THEMES.includes(result.theme)) result.theme = ep.world;
    if (!result.mood || !MOODS.includes(result.mood)) result.mood = "calm";
    const safetyConcern = result.safety === "concern";
    if (safetyConcern) console.log(JSON.stringify({ tag: "SAFETY", turn: state.turn })); // no text, no sid
    // a safety turn steps out of the story: nothing in the room opens on that turn
    if (safetyConcern && d && d.kind === "story") {
      state.objects = [...prev.objects]; state.found = [...prev.found];
      state.thirdAt = prev.thirdAt; state.hint = prev.hint; d.uses = [];
    }

    // the model may recognise an object the word list missed (only if code decided nothing)
    if (d && !safetyConcern) applyModelObject(ep, state, d, result.object);

    let message: string = result.message;
    let trimmed = false;
    if (!safetyConcern && tooLong(message)) {
      const short = await shortenWithModel(message, model);
      if (short && !tooLong(short) && (!endsWithQuestion(message) || endsWithQuestion(short))) {
        message = short;
        trimmed = true;
      }
    }
    let modelQ: unknown = result.question;
    const isEnding = d?.kind === "ending";
    // Every turn hands the turn back to the child - except the last line of the episode.
    if (!idle && !isEnding && !safetyConcern && !message.includes("?")) {
      const tails = ["What do we do now?", "What should we do?", "What now?"];
      message = message.trim() + " " + tails[state.turn % tails.length];
      modelQ = "open";
    }
    const guarded = safetyConcern ? { text: message.trim(), trimmed: false } : enforceLength(message);
    trimmed = trimmed || guarded.trimmed;
    // The last line never offers more story (the "asked for more without being asked" measure).
    if (isEnding) {
      const parts = guarded.text.match(/[^.!?]+[.!?]+["\u201D']?\s*/g) ?? [guarded.text];
      const kept = parts.filter((p) => !(p.includes("?") && /\b(again|another|more|next|play|continue|tomorrow|story)\b/i.test(p)));
      if (kept.length && kept.length < parts.length) guarded.text = kept.join("").trim();
    }
    if (trimmed) console.log(JSON.stringify({ tag: "TRIMMED", turn: state.turn }));
    const qType: QType = isEnding ? "none" : questionType(guarded.text, modelQ);

    // ---- face and effect ----
    let expression: string = EXPRESSIONS.includes(result.expression) ? result.expression : "neutral";
    let effect: string = EFFECTS.includes(result.effect) ? result.effect : "none";
    const lower = childText.toLowerCase();
    const FEEL_BAD = /\b(sad|scared|afraid|tired|bored|boring|cry|crying|upset|angry|mad|lonely|sick)\b/;
    const NEGATED = /\b(not|no|never|don'?t|isn'?t|aren'?t|am not|i'?m not)\s+(\w+\s+)?(sad|scared|afraid|tired|bored|upset|angry|mad|lonely|sick)\b/;
    const childFeelsBad = !idle && FEEL_BAD.test(lower) && !NEGATED.test(lower);
    if (childFeelsBad && (expression === "happy" || expression === "excited")) expression = /scared|afraid/.test(lower) ? "surprised" : "sad";
    if (idle === 1) { expression = "neutral"; effect = "none"; }
    if (idle === 2) expression = "surprised";
    if (d) {
      const beatVis = d.kind === "reward" ? ep.reward : d.kind === "ending" ? ep.ending : d.beat;
      if (beatVis?.expression && EXPRESSIONS.includes(beatVis.expression)) expression = beatVis.expression;
      if (beatVis?.effect && EFFECTS.includes(beatVis.effect)) effect = beatVis.effect;
      else if (d.kind === "story" && d.uses.some((u) => u.clue) && !childFeelsBad) { expression = "excited"; effect = "none"; }
      if (d.kind === "story" && !d.beat && d.turn < clockTurn && expression === "scared" && effect === "none") expression = "surprised";
    }

    if (safetyConcern) { expression = "neutral"; effect = "none"; }
    state.lastQ = qType;

    // ---- logs (after success, so a failed try is not counted twice) ----
    if (idle) {
      await writeLog({ sid, kind: "idle", turn: state.turn, idle_level: idle });
    } else if (!opening) {
      await writeLog({
        sid, kind: "turn", turn: state.turn,
        input_mode: INPUT_MODES.includes(body.inputMode) ? body.inputMode : null,
        word_count: countWords(childText),
        has_hebrew: hasHebrew(childText),
        q_type: prev.lastQ,
      });
    }
    if (state.ended) await writeLog({ sid, kind: "end", turn: state.turn });

    return json({
      theme: result.theme,
      mood: result.mood,
      message: guarded.text,
      expression,
      effect,
      qtype: qType,
      beat: idle ? `idle-${idle}` : d!.kind,
      uses: d ? d.uses : [],
      hint: state.hint,
      state,
      ended: state.ended,
      trimmed,
      model,
      ms: Date.now() - t0,
    }, 200, origin);
  } catch (err) {
    console.error("COACH_ERR", (err as Error).message);
    return json({ error: (err as Error).message }, 200, origin);
  }
});

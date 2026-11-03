import { Terminal, type ITheme } from "@xterm/xterm";

export interface RecordingMeta {
  id: string;
  hostId: string;
  host: string;
  user: string;
  ip: string;
  startedAt: number;
  endedAt?: number;
  bytes: number;
  cols: number;
  rows: number;
  status: "recording" | "complete" | "partial" | "failed";
  reason?: string;
}

interface CastEvent { t: number; code: "o" | "r"; data: string }
export interface Cast { cols: number; rows: number; events: CastEvent[]; duration: number }

const MAX_COLS = 500;
const MAX_ROWS = 200;

/** Parses asciicast v2 text. Lines that are not output or resize events are counted and skipped. */
export function parseCast(text: string): { cast: Cast; bad: number } {
  let cols = 80;
  let rows = 24;
  let bad = 0;
  const events: CastEvent[] = [];
  text.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    let v: unknown;
    try {
      v = JSON.parse(line);
    } catch {
      bad++;
      return;
    }
    if (i === 0 && v && typeof v === "object" && !Array.isArray(v)) {
      const h = v as { width?: unknown; height?: unknown };
      if (typeof h.width === "number" && h.width > 0) cols = Math.min(Math.floor(h.width), MAX_COLS);
      if (typeof h.height === "number" && h.height > 0) rows = Math.min(Math.floor(h.height), MAX_ROWS);
      return;
    }
    const e = v as unknown[];
    if (Array.isArray(e) && typeof e[0] === "number" && (e[1] === "o" || e[1] === "r") && typeof e[2] === "string") {
      events.push({ t: Math.max(0, e[0]), code: e[1], data: e[2] });
    } else {
      bad++;
    }
  });
  return { cast: { cols, rows, events, duration: events.length ? events[events.length - 1].t : 0 }, bad };
}

const clock = (s: number) => {
  const total = Math.floor(s);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = String(total % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
};

export const fmtLength = (ms: number) => clock(Math.max(0, ms) / 1000);

export const fmtSize = (bytes: number) => (bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);

interface PlayerParts {
  screen: HTMLElement;
  play: HTMLButtonElement;
  seek: HTMLInputElement;
  time: HTMLElement;
  speed: HTMLSelectElement;
  theme: () => ITheme;
}

/**
 * Replays a cast into a read-only terminal. Output is written in step with the recorded timing,
 * so seeking backwards resets the terminal and writes again from the start.
 */
export function createPlayer(parts: PlayerParts) {
  let term: Terminal | undefined;
  let cast: Cast = { cols: 80, rows: 24, events: [], duration: 0 };
  let idx = 0;
  let pos = 0;
  let speed = Number(parts.speed.value) || 1;
  let playing = false;
  let last = 0;
  let raf = 0;

  const paint = () => {
    const d = cast.duration;
    parts.seek.value = String(d > 0 ? Math.round((pos / d) * 1000) : 0);
    parts.time.textContent = `${clock(pos)} / ${clock(d)}`;
    parts.play.textContent = playing ? "Pause" : d > 0 && pos >= d ? "Replay" : "Play";
  };

  const apply = () => {
    while (term && idx < cast.events.length && cast.events[idx].t <= pos) {
      const e = cast.events[idx++];
      if (e.code === "o") {
        term.write(e.data);
      } else {
        const [c, r] = e.data.split("x").map(Number);
        if (c > 0 && r > 0) term.resize(Math.min(c, MAX_COLS), Math.min(r, MAX_ROWS));
      }
    }
  };

  const seek = (t: number) => {
    if (!term) return;
    const target = Math.min(Math.max(t, 0), cast.duration);
    if (target < pos) {
      term.reset();
      term.resize(cast.cols, cast.rows);
      idx = 0;
    }
    pos = target;
    apply();
    paint();
  };

  const frame = (now: number) => {
    raf = 0;
    if (!playing) return;
    pos = Math.min(cast.duration, pos + ((now - last) / 1000) * speed);
    last = now;
    apply();
    if (pos >= cast.duration) playing = false;
    else raf = requestAnimationFrame(frame);
    paint();
  };

  const setPlaying = (on: boolean) => {
    playing = on;
    if (on) {
      if (pos >= cast.duration) seek(0);
      last = performance.now();
      raf = requestAnimationFrame(frame);
    } else if (raf) {
      cancelAnimationFrame(raf);
      raf = 0;
    }
    paint();
  };

  parts.play.onclick = () => setPlaying(!playing);
  parts.seek.oninput = () => seek((Number(parts.seek.value) / 1000) * cast.duration);
  parts.speed.onchange = () => {
    speed = Number(parts.speed.value) || 1;
  };

  return {
    load(next: Cast) {
      setPlaying(false);
      term?.dispose();
      cast = next;
      pos = 0;
      idx = 0;
      term = new Terminal({
        cols: cast.cols,
        rows: cast.rows,
        disableStdin: true,
        cursorBlink: false,
        scrollback: 5000,
        fontFamily: '"JetBrains Mono", ui-monospace, Menlo, Consolas, monospace',
        fontSize: 13.5,
        lineHeight: 1.2,
        theme: parts.theme(),
      });
      term.open(parts.screen);
      paint();
    },
    dispose() {
      setPlaying(false);
      term?.dispose();
      term = undefined;
      cast = { cols: 80, rows: 24, events: [], duration: 0 };
    },
  };
}

export function initRecordingPage(el: HTMLElement, hooks: { theme: () => ITheme; deleted: (id: string) => void }) {
  const q = <T extends HTMLElement>(sel: string) => el.querySelector<T>(sel)!;
  const title = q("#rec-title");
  const meta = q("#rec-meta");
  const note = q("#rec-note");
  const download = q<HTMLAnchorElement>("#rec-download");
  const del = q<HTMLButtonElement>("#rec-delete");
  const player = createPlayer({
    screen: q("#rec-screen"),
    play: q<HTMLButtonElement>("#rec-play"),
    seek: q<HTMLInputElement>("#rec-seek"),
    time: q("#rec-time"),
    speed: q<HTMLSelectElement>("#rec-speed"),
    theme: hooks.theme,
  });
  let current: RecordingMeta | undefined;
  let serial = 0;
  let armed: number | undefined;

  const setNote = (text: string, alert = false) => {
    note.className = alert ? "rec-note form-err" : "rec-note";
    note.textContent = text;
  };

  const disarm = () => {
    clearTimeout(armed);
    armed = undefined;
    del.textContent = "Delete";
  };

  del.onclick = async () => {
    if (!current) return;
    if (armed === undefined) {
      del.textContent = "Confirm delete";
      armed = window.setTimeout(disarm, 5000);
      return;
    }
    const id = current.id;
    disarm();
    try {
      const r = await fetch(`/api/recordings/${encodeURIComponent(id)}`, { method: "DELETE", credentials: "same-origin" });
      if (!r.ok) throw new Error(`status ${r.status}`);
      hooks.deleted(id);
    } catch (e) {
      setNote(`The recording could not be deleted (${(e as Error).message}).`, true);
    }
  };

  const describe = (m: RecordingMeta) => {
    switch (m.status) {
      case "recording":
        return "This session is still being recorded, so playback shows what has been recorded so far.";
      case "partial":
        return "The server stopped while this session was recording, so the recording ends there.";
      case "failed":
        return `The recording stopped early (${m.reason ?? "unknown reason"}). Everything up to that point is shown.`;
      default:
        return `Terminal output only. Typed keys are not recorded.${m.reason ? ` Ended: ${m.reason}.` : ""}`;
    }
  };

  return {
    async show(m: RecordingMeta) {
      const mine = ++serial;
      current = m;
      disarm();
      title.textContent = `Recording · ${m.host}`;
      const length = fmtLength((m.endedAt ?? Date.now()) - m.startedAt);
      meta.textContent = `${new Date(m.startedAt).toLocaleString()} · ${m.user}${m.ip ? ` from ${m.ip}` : ""} · ${length} · ${fmtSize(m.bytes)}`;
      download.href = `/api/recordings/${encodeURIComponent(m.id)}/download`;
      setNote(describe(m));
      try {
        const r = await fetch(`/api/recordings/${encodeURIComponent(m.id)}`, { credentials: "same-origin" });
        if (mine !== serial) return;
        if (r.status === 401) return location.reload();
        if (!r.ok) throw new Error(r.status === 404 ? "It has been deleted or has expired." : `status ${r.status}`);
        const { cast, bad } = parseCast(await r.text());
        if (mine !== serial) return;
        player.load(cast);
        const skipped = Number(r.headers.get("X-Unreadable-Lines") ?? 0) + bad;
        if (skipped) setNote(`${describe(m)} ${skipped} ${skipped === 1 ? "line" : "lines"} could not be read and ${skipped === 1 ? "was" : "were"} skipped.`);
      } catch (e) {
        if (mine === serial) setNote(`This recording could not be opened. ${(e as Error).message}`, true);
      }
    },
    close() {
      serial++;
      current = undefined;
      disarm();
      player.dispose();
    },
  };
}

/* relais_core.js — portage JavaScript du module coeur Relais v0.1.
   Fonctionne dans le navigateur (WebCrypto) et dans node >= 20 (crypto global).
   Valide octet par octet contre core/test-vectors.json.
   Les structures sont des objets {champs nommes} ; l'encodage CBOR utilise
   les cles entieres normatives de la spec (docs/SPEC..., §4-5). */

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Relais = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const te = new TextEncoder(), td = new TextDecoder();

  /* ---------- utilitaires octets ---------- */
  const hex = (u8) => Array.from(u8, b => b.toString(16).padStart(2, "0")).join("");
  const unhex = (s) => new Uint8Array(s.match(/../g).map(h => parseInt(h, 16)));
  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  /* ---------- CBOR deterministe (RFC 8949 §4.2.1) ----------
     Sous-ensemble : uint, bstr, tstr, array, map a cles uint. */
  function head(major, value) {
    if (value < 24) return new Uint8Array([(major << 5) | value]);
    if (value < 0x100) return new Uint8Array([(major << 5) | 24, value]);
    if (value < 0x10000)
      return new Uint8Array([(major << 5) | 25, value >> 8, value & 0xff]);
    if (value < 0x100000000) {
      const b = new Uint8Array(5); b[0] = (major << 5) | 26;
      new DataView(b.buffer).setUint32(1, value); return b;
    }
    const b = new Uint8Array(9); b[0] = (major << 5) | 27;
    new DataView(b.buffer).setBigUint64(1, BigInt(value)); return b;
  }

  function cborEncode(obj) {
    if (typeof obj === "number") {
      if (!Number.isInteger(obj) || obj < 0) throw new Error("uint attendu");
      return head(0, obj);
    }
    if (obj instanceof Uint8Array) return concat(head(2, obj.length), obj);
    if (typeof obj === "string") {
      const b = te.encode(obj); return concat(head(3, b.length), b);
    }
    if (Array.isArray(obj))
      return concat(head(4, obj.length), ...obj.map(cborEncode));
    if (obj instanceof Map) {
      const items = [...obj.entries()]
        .map(([k, v]) => [cborEncode(k), cborEncode(v)]);
      items.sort((a, b) => {           // tri par octets de la cle encodee
        const x = a[0], y = b[0];
        for (let i = 0; i < Math.min(x.length, y.length); i++)
          if (x[i] !== y[i]) return x[i] - y[i];
        return x.length - y.length;
      });
      return concat(head(5, items.length), ...items.flat());
    }
    throw new Error("type non supporte");
  }

  function cborDecode(u8) {
    let pos = 0;
    function arg(info) {
      if (info < 24) return info;
      if (info === 24) return u8[pos++];
      if (info === 25) { const v = (u8[pos] << 8) | u8[pos + 1]; pos += 2; return v; }
      if (info === 26) {
        const v = new DataView(u8.buffer, u8.byteOffset + pos).getUint32(0);
        pos += 4; return v;
      }
      if (info === 27) {
        const v = new DataView(u8.buffer, u8.byteOffset + pos).getBigUint64(0);
        pos += 8; return Number(v);
      }
      throw new Error("longueur indefinie interdite");
    }
    function item() {
      const b = u8[pos++], major = b >> 5, n = arg(b & 31);
      switch (major) {
        case 0: return n;
        case 2: { const v = u8.slice(pos, pos + n); pos += n; return v; }
        case 3: { const v = td.decode(u8.slice(pos, pos + n)); pos += n; return v; }
        case 4: { const a = []; for (let i = 0; i < n; i++) a.push(item()); return a; }
        case 5: {
          const m = new Map();
          for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); }
          return m;
        }
        default: throw new Error("type majeur non supporte : " + major);
      }
    }
    const v = item();
    if (pos !== u8.length) throw new Error("octets excedentaires");
    return v;
  }

  /* ---------- crypto ---------- */
  const PKCS8_PREFIX = unhex("302e020100300506032b657004220420");
  const sha256 = async (u8) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", u8));

  async function keypairFromSeed(seed32) {
    const sk = await crypto.subtle.importKey(
      "pkcs8", concat(PKCS8_PREFIX, seed32), { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", sk);
    const pk = Uint8Array.from(atob(jwk.x.replace(/-/g, "+").replace(/_/g, "/")),
      c => c.charCodeAt(0));
    return { sk, pk };
  }
  const sign = async (sk, msg) =>
    new Uint8Array(await crypto.subtle.sign("Ed25519", sk, msg));
  async function verify(pkRaw, sig, msg) {
    try {
      const pk = await crypto.subtle.importKey(
        "raw", pkRaw, { name: "Ed25519" }, false, ["verify"]);
      return await crypto.subtle.verify("Ed25519", pk, sig, msg);
    } catch { return false; }
  }

  /* ---------- structures (cles CBOR normatives, spec §4-5) ---------- */
  const issUnsigned = (i) => new Map([[1, i.version], [2, i.noteId],
    [3, i.denomination], [4, i.unit], [5, i.issuerId], [6, i.issuedTo],
    [7, i.issuedAt], [8, i.expiresAt], [9, i.maxHops]]);
  const issSigned = (i) => new Map([...issUnsigned(i), [10, i.issuerSig]]);
  const trUnsigned = (t) => new Map([[1, t.noteId], [2, t.hop], [3, t.prevHash],
    [4, t.senderPk], [5, t.recipientPk], [6, t.requestNonce], [7, t.localTime]]);
  const trSigned = (t) => new Map([...trUnsigned(t), [8, t.senderSig]]);

  const encodeNote = (note) => cborEncode(
    [issSigned(note.issuance), ...note.transfers.map(trSigned)]);
  const currentOwner = (note) => note.transfers.length
    ? note.transfers[note.transfers.length - 1].recipientPk
    : note.issuance.issuedTo;

  function decodeNote(u8) {
    const arr = cborDecode(u8);
    const im = arr[0];
    const issuance = { version: im.get(1), noteId: im.get(2),
      denomination: im.get(3), unit: im.get(4), issuerId: im.get(5),
      issuedTo: im.get(6), issuedAt: im.get(7), expiresAt: im.get(8),
      maxHops: im.get(9), issuerSig: im.get(10) };
    const transfers = arr.slice(1).map(m => ({ noteId: m.get(1), hop: m.get(2),
      prevHash: m.get(3), senderPk: m.get(4), recipientPk: m.get(5),
      requestNonce: m.get(6), localTime: m.get(7), senderSig: m.get(8) }));
    return { issuance, transfers };
  }

  const encodeRequest = (r) => cborEncode(new Map([[1, r.version],
    [2, r.recipientPk], [3, r.amount], [4, r.unit], [5, r.nonce],
    [6, r.createdAt], [7, r.ttl]]));
  function decodeRequest(u8) {
    const m = cborDecode(u8);
    return { version: m.get(1), recipientPk: m.get(2), amount: m.get(3),
      unit: m.get(4), nonce: m.get(5), createdAt: m.get(6), ttl: m.get(7) };
  }

  /* ---------- emission et transfert ---------- */
  async function issueNote(issuerSk, f) {
    const issuance = { version: 1, ...f, issuerSig: new Uint8Array(0) };
    issuance.issuerSig = await sign(issuerSk, cborEncode(issUnsigned(issuance)));
    return { issuance, transfers: [] };
  }

  async function makeTransfer(note, senderSk, senderPk, recipientPk,
                              requestNonce, localTime) {
    const prev = note.transfers.length
      ? cborEncode(trSigned(note.transfers[note.transfers.length - 1]))
      : cborEncode(issSigned(note.issuance));
    const t = { noteId: note.issuance.noteId, hop: note.transfers.length + 1,
      prevHash: await sha256(prev), senderPk, recipientPk, requestNonce,
      localTime, senderSig: new Uint8Array(0) };
    t.senderSig = await sign(senderSk, cborEncode(trUnsigned(t)));
    return { issuance: note.issuance, transfers: [...note.transfers, t] };
  }

  /* ---------- validation (§6) — codes de rejet normatifs ---------- */
  const CODES = {
    OK: "OK", EMETTEUR_INCONNU: "EMETTEUR_INCONNU",
    EMISSION_INVALIDE: "EMISSION_INVALIDE", EXPIRE: "EXPIRE",
    UNITE: "UNITE_DIFFERENTE", CHAINE_CASSEE: "CHAINE_CASSEE",
    SIGNATAIRE: "SIGNATAIRE_ILLEGITIME", SIG: "SIG_TRANSFERT_INVALIDE",
    GELE: "BILLET_GELE_MAX_HOPS", DEST: "MAUVAIS_DESTINATAIRE",
    REJEU: "REJEU_NONCE", DOUBLE: "DOUBLE_DEPENSE", PLAFOND: "PLAFOND_HORS_LIGNE",
  };
  const TOLERANCE_HORLOGE = 48 * 3600;

  /* ctx = { issuers: {id: pkU8}, myPk, plafond, seen: Map(noteIdHex ->
       {lastHop, chainHashHex, firstSeen}), myNonces: Set(nonceHex),
       fraudEvents: [] } */
  function newContext(issuers, myPk, plafond = 2000) {
    return { issuers, myPk, plafond, seen: new Map(),
             myNonces: new Set(), fraudEvents: [] };
  }

  async function validateNote(note, req, ctx, now) {
    const iss = note.issuance;
    if (iss.version !== 1) return CODES.EMISSION_INVALIDE;
    const issuerPk = ctx.issuers[iss.issuerId];
    if (!issuerPk) return CODES.EMETTEUR_INCONNU;
    if (!await verify(issuerPk, iss.issuerSig, cborEncode(issUnsigned(iss))))
      return CODES.EMISSION_INVALIDE;
    if (now >= iss.expiresAt + TOLERANCE_HORLOGE) return CODES.EXPIRE;
    if (iss.unit !== req.unit) return CODES.UNITE;

    let prevEncoded = cborEncode(issSigned(iss));
    let owner = iss.issuedTo;
    for (const t of note.transfers) {
      if (!eq(t.noteId, iss.noteId) ||
          !eq(t.prevHash, await sha256(prevEncoded)))
        return CODES.CHAINE_CASSEE;
      if (!eq(t.senderPk, owner)) return CODES.SIGNATAIRE;
      if (!await verify(t.senderPk, t.senderSig, cborEncode(trUnsigned(t))))
        return CODES.SIG;
      owner = t.recipientPk;
      prevEncoded = cborEncode(trSigned(t));
    }
    if (note.transfers.length > iss.maxHops) return CODES.GELE;
    if (!note.transfers.length) return CODES.DEST;

    const last = note.transfers[note.transfers.length - 1];
    if (!eq(last.recipientPk, ctx.myPk)) return CODES.DEST;
    if (!eq(last.requestNonce, req.nonce) || !ctx.myNonces.has(hex(req.nonce)))
      return CODES.REJEU;

    const chainHash = hex(await sha256(encodeNote(note)));
    const seen = ctx.seen.get(hex(iss.noteId));
    if (seen && seen.chainHashHex !== chainHash && seen.lastHop >= last.hop) {
      ctx.fraudEvents.push({ noteIdHex: hex(iss.noteId),
        seenHash: seen.chainHashHex, offeredHash: chainHash, at: now });
      return CODES.DOUBLE;
    }
    if (iss.denomination > ctx.plafond) return CODES.PLAFOND;

    ctx.seen.set(hex(iss.noteId),
      { lastHop: last.hop, chainHashHex: chainHash, firstSeen: now });
    ctx.myNonces.delete(hex(req.nonce));
    return CODES.OK;
  }

  /* Gossip local : integrer les billets vus d'un pair (spec §7, differentiel). */
  function mergeGossip(ctx, entries) {
    for (const [idHex, e] of entries) {
      const mine = ctx.seen.get(idHex);
      if (!mine || e.lastHop > mine.lastHop) ctx.seen.set(idHex, e);
    }
  }

  return { hex, unhex, concat, eq, rand, cborEncode, cborDecode, sha256,
    keypairFromSeed, sign, verify, issUnsigned, issSigned, trUnsigned,
    trSigned, encodeNote, decodeNote, currentOwner, encodeRequest,
    decodeRequest, issueNote, makeTransfer, validateNote, newContext,
    mergeGossip, CODES, TOLERANCE_HORLOGE };
});

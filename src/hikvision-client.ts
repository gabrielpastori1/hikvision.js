// src/hikvision-client-axios.ts
/* eslint-disable @typescript-eslint/no-explicit-any */
import crypto from "crypto";
import https from "https";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import { XMLParser, XMLBuilder } from "fast-xml-parser";

type SessionLoginCap = {
  sessionID: string;
  challenge: string;
  iterations: number;
  isIrreversible: boolean;
  salt: string;
  isSupportSessionTag?: boolean;
  sessionIDVersion?: number;
};

type HikClientOptions = {
  baseUrl: string; // ex: https://192.168.200.13
  username: string;
  password: string; // em texto
  rejectUnauthorized?: boolean; // default true; em dev use false para self-signed
  timeoutMs?: number;
};

type LoginState = {
  sessionID: string | null;
  sessionTag?: string;
  lastLoginAt?: number;
};

type DigestAuth = {
  realm: string;
  nonce: string;
  qop: string;
  opaque?: string;
  domain?: string;
  stale?: string;
};

type DigestChallenge = {
  username: string;
  realm: string;
  nonce: string;
  uri: string;
  response: string;
  qop: string;
  nc: string;
  cnonce: string;
};

function sha256Hex(input: Buffer | string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Algoritmo de hash (sessionIDVersion=2, isIrreversible=true):
 * P0 = SHA256(username + salt + plainPassword)
 * repetir i vezes: P = SHA256(P + challenge)
 */
function buildHikvisionPasswordHex(params: {
  username: string;
  plainPassword: string;
  salt: string;
  challenge: string;
  iterations: number;
}) {
  const { username, plainPassword, salt, challenge, iterations } = params;
  let p = sha256Hex(username + salt + plainPassword);
  p = sha256Hex(p + challenge);
  for (var i = 2; i < iterations; i++) p = sha256Hex(p);
  return p;
}

function joinUrl(base: string, path: string) {
  if (base.endsWith("/")) base = base.slice(0, -1);
  if (!path.startsWith("/")) path = "/" + path;
  return base + path;
}

function md5Hex(input: string): string {
  return crypto.createHash("md5").update(input).digest("hex");
}

function parseDigestAuth(wwwAuthenticate: string): DigestAuth {
  const match = wwwAuthenticate.match(/Digest\s+(.+)/);
  if (!match) {
    throw new Error("Invalid WWW-Authenticate header");
  }

  const params = match[1];
  const auth: DigestAuth = { realm: "", nonce: "", qop: "" };

  // Parse parameters
  const paramRegex = /(\w+)="([^"]*)"/g;
  let paramMatch;
  while ((paramMatch = paramRegex.exec(params)) !== null) {
    const [, key, value] = paramMatch;
    (auth as any)[key] = value;
  }

  return auth;
}

function generateDigestResponse(
  username: string,
  password: string,
  realm: string,
  nonce: string,
  method: string,
  uri: string,
  qop: string,
  nc: string,
  cnonce: string
): string {
  const ha1 = md5Hex(`${username}:${realm}:${password}`);
  const ha2 = md5Hex(`${method}:${uri}`);
  const response = md5Hex(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  return response;
}

function generateDigestHeader(challenge: DigestChallenge): string {
  const parts = [
    `username="${challenge.username}"`,
    `realm="${challenge.realm}"`,
    `nonce="${challenge.nonce}"`,
    `uri="${challenge.uri}"`,
    `response="${challenge.response}"`,
    `qop=${challenge.qop}`,
    `nc=${challenge.nc}`,
    `cnonce="${challenge.cnonce}"`
  ];
  return `Digest ${parts.join(", ")}`;
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  parseTagValue: true,
  parseAttributeValue: true,
  trimValues: true,
});

const xmlBuilder = new XMLBuilder({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  suppressBooleanAttributes: false,
  format: false,
});

export class HikvisionClientAxios {
  private baseUrl: string;
  private username: string;
  private password: string;
  private timeoutMs: number;
  private login: LoginState = { sessionID: null };
  private isLoggingIn = false;
  private axios: AxiosInstance;
  private digestAuth: DigestAuth | null = null;
  private nc = 0; // nonce counter

  constructor(opts: HikClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.username = opts.username;
    this.password = opts.password;
    this.timeoutMs = opts.timeoutMs ?? 10000;

    const rejectUnauthorized = opts.rejectUnauthorized !== false;

    // Agent HTTPS para lidar com self-signed (rejectUnauthorized=false em dev)
    const agent = new https.Agent({ rejectUnauthorized });

    // Cria instância axios com agent
    this.axios = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeoutMs,
      httpsAgent: agent,
      // ISAPI retorna e aceita XML
      headers: {
        Accept: "application/xml",
      },
      // Desabilita transformação automática; lidaremos com XML manualmente
      transformResponse: [(data) => data],
    });

    // Interceptor de resposta: tenta autenticação Digest em 401
    this.axios.interceptors.response.use(
      (res) => res,
      async (error) => {
        const config = error.config as AxiosRequestConfig & {
          _retry?: boolean;
        };

        if (
          error.response &&
          error.response.status === 401 &&
          !config._retry &&
          error.response.headers["www-authenticate"]
        ) {
          config._retry = true;
          
          // Parse WWW-Authenticate header
          const wwwAuth = error.response.headers["www-authenticate"];
          this.digestAuth = parseDigestAuth(wwwAuth);
          
          // Reexecuta a requisição original com autenticação Digest
          return this.axios.request(config);
        }
        return Promise.reject(error);
      }
    );
  }

  async loginIfNeeded(force = false) {
    if (!force && this.login.sessionID) return;

    if (this.isLoggingIn) {
      await new Promise((r) => setTimeout(r, 250));
      if (this.login.sessionID) return;
    }

    this.isLoggingIn = true;
    try {
      const caps = await this.fetchCapabilities();

      const passwordHex = buildHikvisionPasswordHex({
        username: this.username,
        plainPassword: this.password,
        salt: caps.salt,
        challenge: caps.challenge,
        iterations: caps.iterations,
      });

      const timeStamp = Date.now();
      const url = `/ISAPI/Security/sessionLogin?timeStamp=${timeStamp}`;

      const bodyXml = this.buildSessionLoginXml({
        userName: this.username,
        passwordHex,
        sessionID: caps.sessionID,
        sessionIDVersion: caps.sessionIDVersion ?? 2,
        isNeedSessionTag: caps.isSupportSessionTag ?? true,
      });

      const res = await this.axios.post(url, bodyXml, {
        headers: {
          "Content-Type": "application/xml",
          Accept: "application/xml",
        },
        // A Session-Tag, se vier, pega via header
        validateStatus: () => true,
      });

      if (res.status < 200 || res.status >= 300) {
        throw new Error(
          `sessionLogin failed: ${res.status} ${res.statusText} - ${res.data}`
        );
      }

      const data = xmlParser.parse(res.data as string);

      const sessionTag = data.SessionLogin.sessionTag;

      this.login = {
        sessionID: caps.sessionID,
        sessionTag: sessionTag,
        lastLoginAt: Date.now(),
      };
    } finally {
      this.isLoggingIn = false;
    }
  }

  async request(
    path: string,
    config?: AxiosRequestConfig & {
      searchParams?: Record<string, string | number>;
    }
  ): Promise<AxiosResponse> {
    await this.loginIfNeeded(false);

    // Monta URL com query string se fornecida
    let url = path.startsWith("/") ? path : `/${path}`;
    if (config?.searchParams) {
      const usp = new URLSearchParams();
      for (const [k, v] of Object.entries(config.searchParams)) {
        usp.set(k, String(v));
      }
      const qs = usp.toString();
      if (qs) url += `?${qs}`;
    }

    // Headers padrão + Session-Tag se houver
    const headers: Record<string, any> = {
      Accept: "application/xml",
      ...(config?.headers || {}),
    };
    if (this.login.sessionTag) {
      headers["SessionTag"] = this.login.sessionTag;
    }

    // Adiciona autenticação Digest se disponível
    if (this.digestAuth) {
      this.nc++;
      const nc = this.nc.toString().padStart(8, "0");
      const cnonce = crypto.randomBytes(16).toString("hex");
      const method = (config?.method ?? "GET").toUpperCase();
      
      const response = generateDigestResponse(
        this.username,
        this.password,
        this.digestAuth.realm,
        this.digestAuth.nonce,
        method,
        url,
        this.digestAuth.qop,
        nc,
        cnonce
      );

      const digestChallenge: DigestChallenge = {
        username: this.username,
        realm: this.digestAuth.realm,
        nonce: this.digestAuth.nonce,
        uri: url,
        response,
        qop: this.digestAuth.qop,
        nc,
        cnonce
      };

      headers["Authorization"] = generateDigestHeader(digestChallenge);
    }

    const res = await this.axios.request({
      url,
      method: config?.method ?? "GET",
      headers,
      data: config?.data,
      responseType: config?.responseType ?? "text", // queremos XML como string
      validateStatus: () => true,
      // demais configs são herdadas do axios instance (agent, timeout...)
    });

    // Atualizar sessionTag se vier novamente
    const maybeTag = res.headers["session-tag"] || res.headers["Session-Tag"];
    if (maybeTag) {
      this.login.sessionTag = Array.isArray(maybeTag) ? maybeTag[0] : maybeTag;
    }

    return res;
  }

  // --------- Internos ---------

  private async fetchCapabilities(): Promise<SessionLoginCap> {
    const random = Math.floor(Math.random() * 1e8);
    const url = `/ISAPI/Security/sessionLogin/capabilities?username=${encodeURIComponent(
      this.username
    )}&random=${random}`;

    const res = await this.axios.get(url, {
      headers: { Accept: "application/xml" },
      responseType: "text",
      validateStatus: () => true,
    });

    if (res.status < 200 || res.status >= 300) {
      throw new Error(
        `capabilities failed: ${res.status} ${res.statusText} - ${res.data}`
      );
    }

    return this.parseCapabilities(res.data as string);
  }

  private buildSessionLoginXml(params: {
    userName: string;
    passwordHex: string;
    sessionID: string;
    sessionIDVersion: number;
    isNeedSessionTag: boolean;
  }) {
    const obj = {
      SessionLogin: {
        userName: params.userName,
        password: params.passwordHex,
        sessionID: params.sessionID,
        isSessionIDValidLongTerm: false,
        sessionIDVersion: params.sessionIDVersion,
        isNeedSessionTag: params.isNeedSessionTag,
      },
    };
    return xmlBuilder.build(obj);
  }

  private parseCapabilities(xml: string): SessionLoginCap {
    const parsed = xmlParser.parse(xml) as any;

    // Tenta localizar SessionLoginCap independentemente de namespace
    const capNode =
      parsed?.SessionLoginCap ||
      (
        Object.values(parsed || {}).find(
          (v: any) => v && typeof v === "object" && v.SessionLoginCap
        ) as any
      )?.SessionLoginCap ||
      parsed; // fallback (alguns dispositivos podem botar direto)

    const sessionID = String(capNode?.sessionID ?? "");
    const challenge = String(capNode?.challenge ?? "");
    const iterations = Number(capNode?.iterations ?? 0);
    const isIrreversible =
      String(capNode?.isIrreversible ?? "").toLowerCase() === "true";
    const salt = String(capNode?.salt ?? "");
    const isSupportSessionTag =
      String(capNode?.isSupportSessionTag ?? "").toLowerCase() === "true";
    const sessionIDVersion =
      capNode?.sessionIDVersion != null ? Number(capNode.sessionIDVersion) : 2;

    if (!sessionID || !challenge || !iterations || !salt) {
      throw new Error(
        "capabilities parse error: missing required fields (sessionID/challenge/iterations/salt)"
      );
    }

    return {
      sessionID,
      challenge,
      iterations,
      isIrreversible,
      salt,
      isSupportSessionTag,
      sessionIDVersion,
    };
  }
}

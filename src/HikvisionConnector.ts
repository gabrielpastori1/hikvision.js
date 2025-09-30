import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";
import { XMLParser, XMLBuilder } from "fast-xml-parser";

/**
 * Interface para configuração do HikvisionConnector
 */
export interface HikvisionConfig {
  /** O endereço IP ou hostname do equipamento (ex: '192.168.1.64') */
  host: string;
  /** O nome de usuário para autenticação */
  username: string;
  /** A senha em texto plano */
  plainPassword: string;
  /** Se o protocolo deve ser HTTPS (padrão: true) */
  https?: boolean;
}

/**
 * Interface para as capacidades de sessão retornadas pela Hikvision
 */
export interface SessionCapabilities {
  sessionID: string;
  challenge: string;
  salt: string;
  iterations: number;
  sessionIDVersion?: number;
  isIrreversible?: boolean;
  isNeedSessionTag?: boolean;
}

/**
 * Interface para os dados de autenticação da sessão
 */
export interface SessionAuth {
  sessionID: string;
  sessionTag: string;
  cookies: Record<string, string>;
  [key: string]: any;
}

/**
 * Interface para os parâmetros do Digest Authentication
 */
export interface DigestParams {
  realm: string;
  nonce: string;
  qop: string;
  opaque: string;
  [key: string]: string;
}

/**
 * Cria um hash MD5 de uma string e retorna em formato hexadecimal.
 * @param data - A string para fazer o hash.
 * @returns O hash MD5 em hexadecimal.
 */
function md5Hex(data: string): string {
  return crypto.createHash("md5").update(data).digest("hex");
}

/**
 * Cria um hash SHA-256 de uma string e retorna em formato hexadecimal.
 * @param data - A string para fazer o hash.
 * @returns O hash SHA-256 em hexadecimal.
 */
function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Classe para gerenciar a conexão e autenticação com equipamentos Hikvision via ISAPI.
 */
export class HikvisionConnector {
  private readonly host: string;
  private readonly username: string;
  private readonly plainPassword: string;
  private readonly https: boolean;
  private readonly agent: http.Agent | https.Agent;
  private readonly api: AxiosInstance;
  private readonly xmlParser: XMLParser;
  private readonly xmlBuilder: XMLBuilder;

  private sessionID: string | null = null;
  private sessionCap: SessionCapabilities | null = null;
  private auth: SessionAuth | null = null;
  private digestAuthHeader: string | null = null;
  private loggedIn: boolean = false;
  private securityToken: string | null = null;

  /**
   * Cria uma nova instância do HikvisionConnector
   * @param config - Configuração de conexão
   */
  constructor(config: HikvisionConfig) {
    const { host, username, plainPassword, https: useHttps = true } = config;

    if (!host || !username || !plainPassword) {
      throw new Error("Host, username e plainPassword são obrigatórios.");
    }

    this.host = host;
    this.username = username;
    this.plainPassword = plainPassword;
    this.https = useHttps;
    this.agent = this.https
      ? new https.Agent({ rejectUnauthorized: false })
      : new http.Agent({});

    // Configuração do Axios
    this.api = axios.create({
      baseURL: `http${this.https ? "s" : ""}://${this.host}`,
      httpsAgent: this.https ? this.agent : undefined,
      httpAgent: this.https ? undefined : this.agent,
    });

    // Configuração do Parser XML
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
      parseTagValue: true,
      parseAttributeValue: true,
      trimValues: true,
    });
    this.xmlBuilder = new XMLBuilder({
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
      suppressBooleanAttributes: false,
      format: false,
    });
  }

  /**
   * Constrói o hash da senha usando a lógica específica da Hikvision para sessionLogin.
   * Algoritmo (sessionIDVersion=2, isIrreversible=true):
   * P0 = SHA256(username + salt + plainPassword)
   * repetir i vezes: P = SHA256(P + challenge)
   * @private
   */
  private _buildPasswordHash(): string {
    if (!this.sessionCap) {
      throw new Error("sessionCap não está disponível.");
    }

    const { salt, challenge, iterations } = this.sessionCap;
    if (!salt || !challenge || !iterations) {
      throw new Error("Não foi possível obter salt, challenge ou iterations.");
    }

    let p = sha256Hex(this.username + salt + this.plainPassword);
    p = sha256Hex(p + challenge);
    for (let i = 2; i < iterations; i++) {
      p = sha256Hex(p);
    }
    return p;
  }

  /**
   * Passo 1 do login: Obtém as capacidades de sessão (salt, challenge, iterations).
   * @private
   */
  private async _getSessionCapabilities(): Promise<void> {
    try {
      console.log("Obtendo capacidades de sessão...");
      const random = Math.floor(Math.random() * 1e8);
      const url = `/ISAPI/Security/sessionLogin/capabilities?username=${encodeURIComponent(
        this.username
      )}&random=${random}`;

      const response: AxiosResponse<string> = await this.api.get(url);
      const parsedData: any = this.xmlParser.parse(response.data);

      this.sessionCap = parsedData.SessionLoginCap;
      console.log("Capacidades de sessão obtidas com sucesso.");
    } catch (error: any) {
      console.error("Erro ao obter capacidades de sessão:", error.message);
      throw new Error(
        "Falha ao obter capacidades de sessão. Verifique o usuário ou se o equipamento suporta este método de login."
      );
    }
  }

  /**
   * Passo 2 do login: Realiza o login com o hash da senha para obter o sessionID.
   * @private
   */
  private async _performSessionLogin(): Promise<void> {
    if (!this.sessionCap) {
      throw new Error("sessionCap não está disponível.");
    }

    try {
      console.log("Realizando login de sessão...");
      const hashedPassword = this._buildPasswordHash();
      const timeStamp = new Date().getTime();

      const xmlBody = this.xmlBuilder.build({
        SessionLogin: {
          userName: this.username,
          password: hashedPassword,
          sessionID: this.sessionCap.sessionID,
          isSessionIDValidLongTerm: false,
          sessionIDVersion: `${this.sessionCap.sessionIDVersion || 2}`,
          isNeedSessionTag: this.sessionCap.isNeedSessionTag || true,
        },
      });

      const response: AxiosResponse<string> = await this.api.post(
        `/ISAPI/Security/sessionLogin?timeStamp=${timeStamp}`,
        xmlBody,
        { headers: { "Content-Type": "application/xml" } }
      );

      const parsedData: any = this.xmlParser.parse(response.data);
      this.sessionID = this.sessionCap.sessionID;
      this.auth = {
        sessionID: this.sessionCap.sessionID,
        ...parsedData.SessionLogin,
        cookies: {},
      };

      const cookies = response.headers["set-cookie"];
      if (cookies) {
        const sessionCookie = cookies.find((cookie: string) =>
          cookie.startsWith("WebSession_")
        );
        if (sessionCookie) {
          const components = sessionCookie.split(";");
          const [key, value] = components[0].split("=");
          this.auth!.cookies = { [key]: value };
        }
      }

      if (!this.sessionID) {
        throw new Error("SessionID não encontrado na resposta.");
      }

      this.loggedIn = true;
      console.log("Login realizado com sucesso. SessionID:", this.sessionID);
    } catch (error: any) {
      console.error(
        "Erro ao realizar o login:",
        (error.response && error.response.data) || error.message
      );
      throw new Error(
        "Falha ao realizar login. Verifique as credenciais e o processo de hash."
      );
    }
  }

  private async _testLogin(): Promise<boolean> {
    try {
      await this.request({
        method: "get",
        url: "/ISAPI/System/deviceInfo",
      });
      return true;
    } catch (error: any) {
      return false;
    }
  }

  /**
   * Realiza o processo completo de login de sessão.
   * Deve ser chamado antes de usar o método `request`.
   */
  public async login(auth: SessionAuth): Promise<SessionAuth> {
    if (auth) {
      this.sessionID = auth.sessionID;
      this.auth = auth;
      this.loggedIn = true;
      if (await this._testLogin()) return auth;
      this.sessionID = null;
      this.auth = null;
      this.loggedIn = false;
    }

    await this._getSessionCapabilities();
    await this._performSessionLogin();
    
    return this.auth!;
  }

  /**
   * Analisa o header 'WWW-Authenticate' para extrair os parâmetros do Digest.
   * @param authHeader - O valor do header WWW-Authenticate.
   * @returns Um objeto com os parâmetros do Digest.
   * @private
   */
  private _parseDigestHeader(authHeader: string): DigestParams {
    const digestParams: Record<string, string> = {};
    authHeader.replace(/(\w+)="([^"]*)"/g, (match, key, value) => {
      digestParams[key] = value;
      return "";
    });
    return digestParams as DigestParams;
  }

  /**
   * Gera o header de autorização para autenticação Digest.
   * @param digestParams - Parâmetros extraídos do header WWW-Authenticate.
   * @param method - O método HTTP da requisição (GET, PUT, etc.).
   * @param path - O caminho da URL da requisição (ex: /ISAPI/System/deviceInfo).
   * @returns O header de autorização Digest completo.
   * @private
   */
  private _generateDigestAuthHeader(
    digestParams: DigestParams,
    method: string,
    path: string
  ): string {
    const ha1 = md5Hex(
      `${this.username}:${digestParams.realm}:${this.plainPassword}`
    );
    const ha2 = md5Hex(`${method}:${path}`);
    const cnonce = crypto.randomBytes(8).toString("hex");
    const nc = "00000001";

    const response = md5Hex(
      `${ha1}:${digestParams.nonce}:${nc}:${cnonce}:${digestParams.qop}:${ha2}`
    );

    return `Digest username="${this.username}", realm="${digestParams.realm}", nonce="${digestParams.nonce}", uri="${path}", qop=${digestParams.qop}, nc=${nc}, cnonce="${cnonce}", response="${response}", opaque="${digestParams.opaque}"`;
  }

  /**
   * Gera um token de segurança para download de arquivos.
   * @returns O token de segurança.
   * @private
   */
  private async _generateSecurityToken(): Promise<string> {
    const response: any = await this.request({
      method: "get",
      url: `/ISAPI/Security/token?format=json`,
      headers: { "Content-Type": "application/json" },
    });
    this.securityToken = response.data.Token.value;
    return this.securityToken!;
  }

  /**
   * Baixa um arquivo da Hikvision.
   * @param url - O URL do arquivo.
   * @returns O arquivo baixado como ArrayBuffer.
   */
  public async getFile(url: string): Promise<ArrayBuffer> {
    const securityToken = await this._generateSecurityToken();
    const file: AxiosResponse = await this.request({
      method: "get",
      url: url,
      params: { token: securityToken },
      responseType: "arraybuffer",
    });
    return file.data;
  }

  /**
   * Realiza uma requisição autenticada ao equipamento.
   * Lida automaticamente com a autenticação Digest.
   * @param config - Uma configuração de requisição do Axios (url, method, data, etc.).
   * @returns A resposta da requisição do Axios ou dados parseados do XML.
   */
  public async request(config: AxiosRequestConfig): Promise<any> {
    if (!this.loggedIn) {
      throw new Error("Não autenticado. Chame o método login() primeiro.");
    }

    if (!this.auth) {
      throw new Error("Dados de autenticação não disponíveis.");
    }

    // Adiciona o cookie de sessão a todas as requisições
    const requestConfig: AxiosRequestConfig = {
      ...(config || {}),
      headers: {
        ...(config.headers || {}),
        SessionTag: this.auth.sessionTag,
        Cookie: Object.entries(this.auth.cookies || {})
          .map(([key, value]) => `${key}=${value}`)
          .join("; "),
      },
    };

    try {
      // Primeira tentativa
      const response: AxiosResponse = await this.api(requestConfig);

      // Se for xml, parsea e retorna
      if (response.headers["content-type"] === "application/xml") {
        return this.xmlParser.parse(response.data);
      }

      return response;
    } catch (error: any) {
      // Se a primeira tentativa falhar com 401, é um desafio de autenticação Digest
      if (error.response && error.response.status === 401) {
        console.log(
          "Recebido desafio de autenticação Digest. Gerando header..."
        );

        const authHeader = error.response.headers["www-authenticate"];
        if (!authHeader || !authHeader.toLowerCase().startsWith("digest")) {
          throw new Error(
            "Autenticação falhou, mas não foi um desafio Digest válido."
          );
        }

        const digestParams = this._parseDigestHeader(authHeader);
        const digestAuthHeader = this._generateDigestAuthHeader(
          digestParams,
          (requestConfig.method || "GET").toUpperCase(),
          requestConfig.url || ""
        );

        // Armazena o header para futuras requisições (otimização)
        this.digestAuthHeader = digestAuthHeader;

        // Segunda tentativa com o header de autorização
        if (!requestConfig.headers) {
          requestConfig.headers = {};
        }
        requestConfig.headers["Authorization"] = this.digestAuthHeader;

        console.log("Repetindo requisição com header Digest...");
        return await this.api(requestConfig);
      }

      // Se for outro erro, apenas o relança
      throw error;
    }
  }
}

// Exportação padrão para compatibilidade com require()
export default HikvisionConnector;

// Compatibilidade CommonJS
module.exports = HikvisionConnector;
module.exports.HikvisionConnector = HikvisionConnector;
module.exports.default = HikvisionConnector;

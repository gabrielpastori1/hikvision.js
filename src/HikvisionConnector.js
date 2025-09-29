const axios = require("axios");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const { XMLParser, XMLBuilder } = require("fast-xml-parser");

/**
 * Cria um hash MD5 de uma string e retorna em formato hexadecimal.
 * @param {string} data - A string para fazer o hash.
 * @returns {string} O hash MD5 em hexadecimal.
 */
function md5Hex(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

/**
 * Cria um hash SHA-256 de uma string e retorna em formato hexadecimal.
 * @param {string} data - A string para fazer o hash.
 * @returns {string} O hash SHA-256 em hexadecimal.
 */
function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Classe para gerenciar a conexão e autenticação com equipamentos Hikvision via ISAPI.
 */
class HikvisionConnector {
  /**
   * @param {object} config
   * @param {string} config.host - O endereço IP ou hostname do equipamento (ex: '192.168.1.64').
   * @param {string} config.username - O nome de usuário para autenticação.
   * @param {string} config.plainPassword - A senha em texto plano.
   * @param {boolean} config.https - Se o protocolo deve ser HTTPS.
   */
  constructor({ host, username, plainPassword, https: useHttps = true }) {
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
      httpsAgent: this.https ? this.agent : null,
      httpAgent: this.https ? null : this.agent,
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

    // Estado da autenticação
    this.sessionID = null;
    this.sessionCap = null; // Armazena salt, challenge, iterations
    this.auth = null; // Armazena o resultado do login
    this.digestAuthHeader = null; // Armazena o último header de autenticação Digest
    this.loggedIn = false;
    this.securityToken = null;
  }

  /**
   * Constrói o hash da senha usando a lógica específica da Hikvision para sessionLogin.
   * Algoritmo (sessionIDVersion=2, isIrreversible=true):
   * P0 = SHA256(username + salt + plainPassword)
   * repetir i vezes: P = SHA256(P + challenge)
   * @private
   */
  _buildPasswordHash() {
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
  async _getSessionCapabilities() {
    try {
      console.log("Obtendo capacidades de sessão...");
      const random = Math.floor(Math.random() * 1e8);
      const url = `/ISAPI/Security/sessionLogin/capabilities?username=${encodeURIComponent(
        this.username
      )}&random=${random}`;

      const response = await this.api.get(url);
      const parsedData = this.xmlParser.parse(response.data);

      this.sessionCap = parsedData.SessionLoginCap;
      console.log("Capacidades de sessão obtidas com sucesso.");
    } catch (error) {
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
  async _performSessionLogin() {
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

      const response = await this.api.post(
        `/ISAPI/Security/sessionLogin?timeStamp=${timeStamp}`,
        xmlBody,
        { headers: { "Content-Type": "application/xml" } }
      );

      const parsedData = this.xmlParser.parse(response.data);
      this.sessionID = this.sessionCap.sessionID;
      this.auth = parsedData.SessionLogin;

      const cookies = response.headers["set-cookie"];
      if (cookies) {
        const sessionCookie = cookies.find((cookie) =>
          cookie.startsWith("WebSession_")
        );
        if (sessionCookie) {
          const components = sessionCookie.split(";");
          const [key, value] = components[0].split("=");
          this.auth.cookies = { [key]: value };
        }
      }

      if (!this.sessionID) {
        throw new Error("SessionID não encontrado na resposta.");
      }

      this.loggedIn = true;
      console.log("Login realizado com sucesso. SessionID:", this.sessionID);
    } catch (error) {
      console.error(
        "Erro ao realizar o login:",
        error.response?.data || error.message
      );
      throw new Error(
        "Falha ao realizar login. Verifique as credenciais e o processo de hash."
      );
    }
  }

  /**
   * Realiza o processo completo de login de sessão.
   * Deve ser chamado antes de usar o método `request`.
   */
  async login() {
    await this._getSessionCapabilities();
    await this._performSessionLogin();
  }

  /**
   * Analisa o header 'WWW-Authenticate' para extrair os parâmetros do Digest.
   * @param {string} authHeader - O valor do header WWW-Authenticate.
   * @returns {object} Um objeto com os parâmetros do Digest.
   * @private
   */
  _parseDigestHeader(authHeader) {
    const digestParams = {};
    authHeader.replace(/(\w+)="([^"]*)"/g, (match, key, value) => {
      digestParams[key] = value;
      return "";
    });
    return digestParams;
  }

  /**
   * Gera o header de autorização para autenticação Digest.
   * @param {object} digestParams - Parâmetros extraídos do header WWW-Authenticate.
   * @param {string} method - O método HTTP da requisição (GET, PUT, etc.).
   * @param {string} path - O caminho da URL da requisição (ex: /ISAPI/System/deviceInfo).
   * @returns {string} O header de autorização Digest completo.
   * @private
   */
  _generateDigestAuthHeader(digestParams, method, path) {
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
   * @returns {string} O token de segurança.
   * @private
   */
  async _generateSecurityToken() {
    // if (this.securityToken) return this.securityToken;
    const response = await this.request({
      method: "get",
      url: `/ISAPI/Security/token?format=json`,
      headers: { "Content-Type": "application/json" },
    });
    this.securityToken = response.data.Token.value;
    return this.securityToken;
  }

  /**
   * Baixa um arquivo da Hikvision.
   * @param {string} url - O URL do arquivo.
   * @returns {Promise<ArrayBuffer>} O arquivo baixado.
   */
  async getFile(url) {
    const securityToken = await this._generateSecurityToken();
    const file = await this.request({
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
   * @param {object} config - Uma configuração de requisição do Axios (url, method, data, etc.).
   * @returns {Promise<object>} A resposta da requisição do Axios.
   */
  async request(config) {
    if (!this.loggedIn) {
      throw new Error("Não autenticado. Chame o método login() primeiro.");
    }

    // Adiciona o cookie de sessão a todas as requisições
    const requestConfig = {
      ...config,
      headers: {
        ...config.headers,
        SessionTag: this.auth.sessionTag,
        Cookie: Object.entries(this.auth.cookies)
          .map(([key, value]) => `${key}=${value}`)
          .join("; "),
      },
    };

    try {
      // Primeira tentativa
      const response = await this.api(requestConfig);

      // Se for xml, parsea e retorna
      if (response.headers["content-type"] === "application/xml")
        return this.xmlParser.parse(response.data);

      return response;
    } catch (error) {
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
          requestConfig.method.toUpperCase(),
          requestConfig.url
        );

        // Armazena o header para futuras requisições (otimização)
        this.digestAuthHeader = digestAuthHeader;

        // Segunda tentativa com o header de autorização
        requestConfig.headers["Authorization"] = this.digestAuthHeader;

        console.log("Repetindo requisição com header Digest...");
        return await this.api(requestConfig);
      }

      // Se for outro erro, apenas o relança
      throw error;
    }
  }
}

module.exports = HikvisionConnector;

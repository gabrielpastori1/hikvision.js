"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HikvisionConnector = void 0;
const axios_1 = __importDefault(require("axios"));
const crypto = __importStar(require("crypto"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
const fast_xml_parser_1 = require("fast-xml-parser");
/**
 * Cria um hash MD5 de uma string e retorna em formato hexadecimal.
 * @param data - A string para fazer o hash.
 * @returns O hash MD5 em hexadecimal.
 */
function md5Hex(data) {
    return crypto.createHash("md5").update(data).digest("hex");
}
/**
 * Cria um hash SHA-256 de uma string e retorna em formato hexadecimal.
 * @param data - A string para fazer o hash.
 * @returns O hash SHA-256 em hexadecimal.
 */
function sha256Hex(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}
/**
 * Classe para gerenciar a conexão e autenticação com equipamentos Hikvision via ISAPI.
 */
class HikvisionConnector {
    /**
     * Cria uma nova instância do HikvisionConnector
     * @param config - Configuração de conexão
     */
    constructor(config) {
        this.sessionID = null;
        this.sessionCap = null;
        this.auth = null;
        this.digestAuthHeader = null;
        this.loggedIn = false;
        this.securityToken = null;
        const { host, username, plainPassword, https: useHttps = true, disableSessionCookie = false, maxRetries = 3, } = config;
        if (!host || !username || !plainPassword) {
            throw new Error("Host, username e plainPassword são obrigatórios.");
        }
        this.host = host;
        this.username = username;
        this.plainPassword = plainPassword;
        this.https = useHttps;
        this.disableSessionCookie = disableSessionCookie;
        this.maxRetries = maxRetries;
        this.agent = this.https
            ? new https.Agent({ rejectUnauthorized: false })
            : new http.Agent({});
        // Configuração do Axios
        this.api = axios_1.default.create({
            baseURL: `http${this.https ? "s" : ""}://${this.host}`,
            httpsAgent: this.https ? this.agent : undefined,
            httpAgent: this.https ? undefined : this.agent,
        });
        // Configuração do Parser XML
        this.xmlParser = new fast_xml_parser_1.XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: "@_",
            parseTagValue: true,
            parseAttributeValue: true,
            trimValues: true,
        });
        this.xmlBuilder = new fast_xml_parser_1.XMLBuilder({
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
    _buildPasswordHash() {
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
    async _getSessionCapabilities() {
        try {
            console.log("Obtendo capacidades de sessão...");
            const random = Math.floor(Math.random() * 1e8);
            const url = `/ISAPI/Security/sessionLogin/capabilities?username=${encodeURIComponent(this.username)}&random=${random}`;
            const response = await this.api.get(url);
            const parsedData = this.xmlParser.parse(response.data);
            this.sessionCap = parsedData.SessionLoginCap;
            console.log("Capacidades de sessão obtidas com sucesso.");
        }
        catch (error) {
            console.error("Erro ao obter capacidades de sessão:", error.message);
            throw new Error("Falha ao obter capacidades de sessão. Verifique o usuário ou se o equipamento suporta este método de login.");
        }
    }
    /**
     * Passo 2 do login: Realiza o login com o hash da senha para obter o sessionID.
     * @private
     */
    async _performSessionLogin() {
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
            const response = await this.api.post(`/ISAPI/Security/sessionLogin?timeStamp=${timeStamp}`, xmlBody, { headers: { "Content-Type": "application/xml" } });
            const parsedData = this.xmlParser.parse(response.data);
            this.sessionID = this.sessionCap.sessionID;
            this.auth = Object.assign(Object.assign({ sessionID: this.sessionCap.sessionID }, parsedData.SessionLogin), { cookies: {} });
            const cookies = response.headers["set-cookie"];
            if (cookies) {
                const sessionCookie = cookies.find((cookie) => cookie.startsWith("WebSession_"));
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
        }
        catch (error) {
            console.error("Erro ao realizar o login:", (error.response && error.response.data) || error.message);
            throw new Error("Falha ao realizar login. Verifique as credenciais e o processo de hash.");
        }
    }
    async _testLogin() {
        try {
            await this.request({
                method: "get",
                url: "/ISAPI/System/deviceInfo",
            });
            return true;
        }
        catch (error) {
            return false;
        }
    }
    /**
     * Realiza o processo completo de login de sessão.
     * Deve ser chamado antes de usar o método `request`.
     */
    async login(auth) {
        if (auth) {
            this.sessionID = auth.sessionID;
            this.auth = auth;
            this.loggedIn = true;
            if (await this._testLogin())
                return auth;
            this.sessionID = null;
            this.auth = null;
            this.loggedIn = false;
        }
        await this._getSessionCapabilities();
        await this._performSessionLogin();
        return this.auth;
    }
    /**
     * Analisa o header 'WWW-Authenticate' para extrair os parâmetros do Digest.
     * @param authHeader - O valor do header WWW-Authenticate.
     * @returns Um objeto com os parâmetros do Digest.
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
     * @param digestParams - Parâmetros extraídos do header WWW-Authenticate.
     * @param method - O método HTTP da requisição (GET, PUT, etc.).
     * @param path - O caminho da URL da requisição (ex: /ISAPI/System/deviceInfo).
     * @returns O header de autorização Digest completo.
     * @private
     */
    _generateDigestAuthHeader(digestParams, method, path) {
        const ha1 = md5Hex(`${this.username}:${digestParams.realm}:${this.plainPassword}`);
        const ha2 = md5Hex(`${method}:${path}`);
        const cnonce = crypto.randomBytes(8).toString("hex");
        const nc = "00000001";
        const response = md5Hex(`${ha1}:${digestParams.nonce}:${nc}:${cnonce}:${digestParams.qop}:${ha2}`);
        return `Digest username="${this.username}", realm="${digestParams.realm}", nonce="${digestParams.nonce}", uri="${path}", qop=${digestParams.qop}, nc=${nc}, cnonce="${cnonce}", response="${response}", opaque="${digestParams.opaque}"`;
    }
    /**
     * Gera um token de segurança para download de arquivos.
     * @returns O token de segurança.
     * @private
     */
    async _generateSecurityToken() {
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
     * @param url - O URL do arquivo.
     * @returns O arquivo baixado como ArrayBuffer.
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
     * @param config - Uma configuração de requisição do Axios (url, method, data, etc.).
     * @returns A resposta da requisição do Axios ou dados parseados do XML.
     */
    async request(config, retryCount = 0) {
        if (!this.loggedIn) {
            throw new Error("Não autenticado. Chame o método login() primeiro.");
        }
        if (!this.auth) {
            throw new Error("Dados de autenticação não disponíveis.");
        }
        const cookies = this.disableSessionCookie
            ? undefined
            : Object.entries(this.auth.cookies || {}).map(([key, value]) => `${key}=${value}`);
        // Adiciona o cookie de sessão a todas as requisições
        const requestConfig = Object.assign(Object.assign({}, (config || {})), { headers: Object.assign(Object.assign({}, (config.headers || {})), { SessionTag: this.auth.sessionTag, Cookie: cookies }) });
        try {
            // Primeira tentativa
            const response = await this.api(requestConfig);
            // Se for xml, parsea e retorna
            if (response.headers["content-type"] === "application/xml") {
                return this.xmlParser.parse(response.data);
            }
            return response;
        }
        catch (error) {
            if (this.maxRetries > (retryCount || 0)) {
                await this.login(this.auth);
                return await this.request(config, retryCount + 1);
            }
            // Se for outro erro, apenas o relança
            throw error;
        }
    }
}
exports.HikvisionConnector = HikvisionConnector;
// Exportação padrão para compatibilidade com require()
exports.default = HikvisionConnector;
// Compatibilidade CommonJS
module.exports = HikvisionConnector;
module.exports.HikvisionConnector = HikvisionConnector;
module.exports.default = HikvisionConnector;
//# sourceMappingURL=HikvisionConnector.js.map
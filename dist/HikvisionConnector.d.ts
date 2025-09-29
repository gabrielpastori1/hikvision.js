import { AxiosRequestConfig } from "axios";
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
 * Classe para gerenciar a conexão e autenticação com equipamentos Hikvision via ISAPI.
 */
export declare class HikvisionConnector {
    private readonly host;
    private readonly username;
    private readonly plainPassword;
    private readonly https;
    private readonly agent;
    private readonly api;
    private readonly xmlParser;
    private readonly xmlBuilder;
    private sessionID;
    private sessionCap;
    private auth;
    private digestAuthHeader;
    private loggedIn;
    private securityToken;
    /**
     * Cria uma nova instância do HikvisionConnector
     * @param config - Configuração de conexão
     */
    constructor(config: HikvisionConfig);
    /**
     * Constrói o hash da senha usando a lógica específica da Hikvision para sessionLogin.
     * Algoritmo (sessionIDVersion=2, isIrreversible=true):
     * P0 = SHA256(username + salt + plainPassword)
     * repetir i vezes: P = SHA256(P + challenge)
     * @private
     */
    private _buildPasswordHash;
    /**
     * Passo 1 do login: Obtém as capacidades de sessão (salt, challenge, iterations).
     * @private
     */
    private _getSessionCapabilities;
    /**
     * Passo 2 do login: Realiza o login com o hash da senha para obter o sessionID.
     * @private
     */
    private _performSessionLogin;
    /**
     * Realiza o processo completo de login de sessão.
     * Deve ser chamado antes de usar o método `request`.
     */
    login(): Promise<void>;
    /**
     * Analisa o header 'WWW-Authenticate' para extrair os parâmetros do Digest.
     * @param authHeader - O valor do header WWW-Authenticate.
     * @returns Um objeto com os parâmetros do Digest.
     * @private
     */
    private _parseDigestHeader;
    /**
     * Gera o header de autorização para autenticação Digest.
     * @param digestParams - Parâmetros extraídos do header WWW-Authenticate.
     * @param method - O método HTTP da requisição (GET, PUT, etc.).
     * @param path - O caminho da URL da requisição (ex: /ISAPI/System/deviceInfo).
     * @returns O header de autorização Digest completo.
     * @private
     */
    private _generateDigestAuthHeader;
    /**
     * Gera um token de segurança para download de arquivos.
     * @returns O token de segurança.
     * @private
     */
    private _generateSecurityToken;
    /**
     * Baixa um arquivo da Hikvision.
     * @param url - O URL do arquivo.
     * @returns O arquivo baixado como ArrayBuffer.
     */
    getFile(url: string): Promise<ArrayBuffer>;
    /**
     * Realiza uma requisição autenticada ao equipamento.
     * Lida automaticamente com a autenticação Digest.
     * @param config - Uma configuração de requisição do Axios (url, method, data, etc.).
     * @returns A resposta da requisição do Axios ou dados parseados do XML.
     */
    request(config: AxiosRequestConfig): Promise<any>;
}
export default HikvisionConnector;

# Hikvision.js

Cliente JavaScript/TypeScript para comunicação com equipamentos Hikvision via ISAPI, com suporte completo a autenticação de sessão e Digest Authentication.

## 🚀 Características

- ✅ **Autenticação de Sessão**: Suporte completo ao protocolo de login de sessão da Hikvision
- ✅ **Digest Authentication**: Autenticação automática quando necessário
- ✅ **TypeScript**: Totalmente tipado com interfaces exportadas
- ✅ **Compatibilidade Universal**: Funciona com `import` e `require()`
- ✅ **Download de Arquivos**: Suporte a download com token de segurança
- ✅ **Parsing XML**: Parsing automático de respostas XML

## 📦 Instalação

### Via GitHub (Recomendado)

```bash
# npm
npm install gabrielpastori1/hikvision.js

# yarn
yarn add gabrielpastori1/hikvision.js

# pnpm
pnpm add gabrielpastori1/hikvision.js
```

### Via npm (quando publicar)

```bash
npm install hikvision.js
```

## 🔧 Compatibilidade

- **Node.js**: >= 8.0.0
- **Browsers**: ES2017+ (ou com polyfills)
- **Webpack**: Compatível com configurações padrão
- **Vue.js**: Compatível com Vue 2 e Vue 3
- **React**: Compatível
- **Angular**: Compatível

## 🎯 Uso Básico

### TypeScript/ES6

```typescript
import { HikvisionConnector } from 'hikvision.js';

const connector = new HikvisionConnector({
  host: '192.168.1.64',
  username: 'admin',
  plainPassword: 'senha123',
  https: true
});

async function exemplo() {
  try {
    // Fazer login
    await connector.login();
    console.log('Login realizado com sucesso!');

    // Fazer uma requisição
    const deviceInfo = await connector.request({
      method: 'get',
      url: '/ISAPI/System/deviceInfo'
    });
    
    console.log('Informações do dispositivo:', deviceInfo);
  } catch (error) {
    console.error('Erro:', error.message);
  }
}
```

### CommonJS/Node.js

```javascript
const { HikvisionConnector } = require('hikvision.js');

const connector = new HikvisionConnector({
  host: '192.168.1.64',
  username: 'admin',
  plainPassword: 'senha123',
  https: true
});

async function exemplo() {
  try {
    await connector.login();
    const deviceInfo = await connector.request({
      method: 'get',
      url: '/ISAPI/System/deviceInfo'
    });
    console.log('Informações do dispositivo:', deviceInfo);
  } catch (error) {
    console.error('Erro:', error.message);
  }
}
```

## 📋 API

### HikvisionConnector

#### Constructor

```typescript
new HikvisionConnector(config: HikvisionConfig)
```

**HikvisionConfig:**
- `host: string` - IP ou hostname do equipamento
- `username: string` - Nome de usuário
- `plainPassword: string` - Senha em texto plano
- `https?: boolean` - Usar HTTPS (padrão: true)

#### Métodos

##### `login(): Promise<void>`
Realiza o processo completo de login de sessão.

##### `request(config: AxiosRequestConfig): Promise<any>`
Faz uma requisição autenticada ao equipamento.

##### `getFile(url: string): Promise<ArrayBuffer>`
Baixa um arquivo do equipamento.

## 🔧 Exemplos

### Obter Informações do Dispositivo

```typescript
const deviceInfo = await connector.request({
  method: 'get',
  url: '/ISAPI/System/deviceInfo'
});
```

### Listar Câmeras

```typescript
const cameras = await connector.request({
  method: 'get',
  url: '/ISAPI/ContentMgmt/InputProxy/channels'
});
```

### Baixar Snapshot

```typescript
const snapshot = await connector.getFile('/ISAPI/Streaming/channels/101/picture');
```

### Configurar Parâmetros

```typescript
const result = await connector.request({
  method: 'put',
  url: '/ISAPI/System/Network/interfaces/1/ipAddress',
  data: {
    IPAddress: {
      ipVersion: 'v4',
      addressingType: 'static',
      ipAddress: '192.168.1.100',
      subnetMask: '255.255.255.0',
      defaultGateway: '192.168.1.1'
    }
  }
});
```

## 🛠️ Desenvolvimento

### Pré-requisitos

- Node.js >= 14.0.0
- npm ou yarn

### Instalação

```bash
git clone https://github.com/SEU_USUARIO/hikvision.js.git
cd hikvision.js
npm install
```

### Build

```bash
npm run build
```

### Teste

```bash
npm test
```

## 📝 Licença

MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🤝 Contribuição

Contribuições são bem-vindas! Por favor, abra uma issue ou pull request.

## 🔧 Solução de Problemas

### Erro de Webpack: "Unexpected token"

Se você receber um erro como `Module parse failed: Unexpected token`, isso geralmente significa que o webpack não está configurado para processar o código ES2017+. 

**Soluções:**

1. **Configurar Babel** (Recomendado):
```bash
npm install --save-dev @babel/core @babel/preset-env babel-loader
```

2. **Configurar webpack** para usar Babel:
```javascript
// webpack.config.js
module.exports = {
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules\/(?!hikvision\.js)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  }
};
```

3. **Para projetos Vue.js**, adicione no `vue.config.js`:
```javascript
module.exports = {
  transpileDependencies: ['hikvision.js']
};
```

### Erro de Módulos Node.js no Browser

Se você estiver usando no browser e receber erros sobre módulos Node.js (como `crypto`, `http`), configure webpack com polyfills:

```bash
npm install --save-dev crypto-browserify stream-browserify buffer
```

```javascript
// webpack.config.js
module.exports = {
  resolve: {
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer")
    }
  }
};
```

## 📞 Suporte

Se você encontrar algum problema ou tiver dúvidas, por favor abra uma [issue](https://github.com/gabrielpasto/hikvision.js/issues).

---

**Nota**: Este pacote é não-oficial e não está associado à Hikvision. Use por sua própria conta e risco.

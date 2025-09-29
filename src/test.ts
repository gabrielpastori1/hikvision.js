const HikvisionConnector = require("./HikvisionConnector");
const fs = require("fs");

// Substitua com as informações do seu equipamento
const HIKVISION_CONFIG = {
  host: "192.168.200.5",
  username: "admin",
  plainPassword: "abc12345", // Coloque sua senha aqui
  https: true,
};

async function main() {
  try {
    // 1. Instanciar e conectar
    const hikvision = new HikvisionConnector(HIKVISION_CONFIG);
    await hikvision.login();

    console.log("\n--- Autenticação bem-sucedida! ---\n");

    // 2. Fazer uma requisição autenticada para obter informações do dispositivo
    console.log("Buscando informações do dispositivo...");
    const deviceInfoResponse = await hikvision.request({
      method: "get",
      url: "/ISAPI/System/deviceInfo",
    });

    // Como a resposta é XML, vamos parseá-la para um objeto JS
    const deviceInfo = deviceInfoResponse.DeviceInfo;

    console.log("\n--- Informações do Dispositivo ---");
    console.log("Nome do Dispositivo:", deviceInfo.deviceName);
    console.log("Modelo:", deviceInfo.model);
    console.log("Número de Série:", deviceInfo.serialNumber);
    console.log("Versão do Firmware:", deviceInfo.firmwareVersion);
    console.log("--------------------------------\n");

    // Busca ultomos logs
    const { data: logsResponse } = await hikvision.request({
      method: "post",
      url: "/ISAPI/AccessControl/AcsEvent",
      params: {
        format: "json",
      },
      data: {
        AcsEventCond: {
          searchID: "637b5a00716c70d563a5d11c6b9915c4",
          searchResultPosition: 0,
          maxResults: 50,
          major: 0,
          minor: 0,
          startTime: "2025-09-28T00:00:00-03:00",
          endTime: "2025-09-29T23:59:59-03:00",
          timeReverseOrder: true,
        },
      },
    });
    const logs = logsResponse.AcsEvent;

    // console.log("\n--- Últimos Logs ---");
    // console.log(logs.InfoList);
    // console.log("--------------------------------\n");
    //                                    /LOCALS/pic/acsLinkCap/202509_00/29_143201_30104_0.jpeg

    const logImage = logs.InfoList.find((log: any) => log.pictureURL);
    if (!logImage) {
      console.log("Nenhuma imagem encontrada");
      return;
    }

    const file = await hikvision.getFile(logImage.pictureURL);
    console.log(file);
    fs.writeFileSync("image.jpg", file);
  } catch (error: any) {
    console.error("\n*** OCORREU UM ERRO ***");
    if (error.response) {
      // Erro de uma requisição HTTP (ex: 401, 404, 500)
      console.error("Status:", error.response.status);
      console.error("Dados:", error.response.data);
    } else {
      // Outros erros (ex: falha de rede, erro no código)
      console.error("Mensagem:", error.message);
    }
  }
}

main();

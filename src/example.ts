import { HikvisionClientAxios } from "./HikvisionConnector";

async function main() {
  const client = new HikvisionClientAxios({
    baseUrl: "https://192.168.200.13",
    username: "admin",
    password: "abc12345",
    rejectUnauthorized: false, // true em produção
  });

  const res = await client.request("/ISAPI/AccessControl/FaceRecognizeMode?format=json", {
    method: "GET",
    headers: { Accept: "application/xml" },
  });
  const xml = await res.data;
  console.log(xml);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

export { HikvisionConnector, HikvisionConfig, SessionCapabilities, SessionAuth, DigestParams } from "./HikvisionConnector";
export { default } from "./HikvisionConnector";

// Compatibilidade CommonJS
import HikvisionConnector from "./HikvisionConnector";
module.exports = HikvisionConnector;
module.exports.HikvisionConnector = HikvisionConnector;
module.exports.default = HikvisionConnector;
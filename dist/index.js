"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = exports.HikvisionConnector = void 0;
var HikvisionConnector_1 = require("./HikvisionConnector");
Object.defineProperty(exports, "HikvisionConnector", { enumerable: true, get: function () { return HikvisionConnector_1.HikvisionConnector; } });
var HikvisionConnector_2 = require("./HikvisionConnector");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return __importDefault(HikvisionConnector_2).default; } });
// Compatibilidade CommonJS
const HikvisionConnector_3 = __importDefault(require("./HikvisionConnector"));
module.exports = HikvisionConnector_3.default;
module.exports.HikvisionConnector = HikvisionConnector_3.default;
module.exports.default = HikvisionConnector_3.default;

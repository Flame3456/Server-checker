'use strict';

const SIGNATURES = [];

const CONFIG_EXTENSIONS = ['.ctl'];

const MINECRAFT_MARKERS = ['.minecraft', 'versions', 'mods', 'saves', 'resourcepacks', 'options.txt', 'servers.dat'];

const INTERESTING_EXTENSIONS = ['.jar', '.exe', '.dll', '.zip', '.rar', '.7z'];

let remoteSignatures = [];
const SIGNATURE_MASK = 0x5a;

function encodeName(name) {
  return Buffer.from(name, 'utf8').map((byte) => byte ^ SIGNATURE_MASK).toString('base64');
}

function decodeName(name) {
  return Buffer.from(name, 'base64').map((byte) => byte ^ SIGNATURE_MASK).toString('utf8');
}

function setRemoteSignatures(signatures) {
  remoteSignatures = Array.isArray(signatures)
    ? signatures.map(({ name, ...details }) => ({ ...details, encodedName: encodeName(String(name || '')) }))
    : [];
}
function getSignatures() {
  return [...SIGNATURES, ...remoteSignatures.map(({ encodedName, ...details }) => ({ ...details, name: decodeName(encodedName) }))];
}

module.exports = {
  SIGNATURES,
  CONFIG_EXTENSIONS,
  MINECRAFT_MARKERS,
  INTERESTING_EXTENSIONS,
  setRemoteSignatures,
  getSignatures,
};

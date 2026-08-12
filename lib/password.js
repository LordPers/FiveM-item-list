// Hashování hesel pomocí vestavěného modulu crypto (scrypt) - bez externí
// závislosti na bcrypt. Formát uloženého hashe: "salt_hex:hash_hex".
const crypto = require("crypto");

const KEY_LENGTH = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, KEY_LENGTH).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, hashHex] = stored.split(":");
  try {
    const hashBuffer = Buffer.from(hashHex, "hex");
    const candidateBuffer = crypto.scryptSync(password, salt, KEY_LENGTH);
    if (hashBuffer.length !== candidateBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, candidateBuffer);
  } catch (err) {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };

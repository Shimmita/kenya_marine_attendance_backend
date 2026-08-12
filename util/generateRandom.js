import crypto from "crypto";

export const generateResetCode = (length = 8) => {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%";
  const bytes = crypto.randomBytes(length);

  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join("");
};
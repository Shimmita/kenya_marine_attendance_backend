/* 
import axios from 'axios';
import "dotenv/config";
import PlatformConfig from "../model/PlatformConfig.js";

const PLATFORM_SITE_LINK = "https://clocking.kmfri.go.ke/";

const formatReminderTemplate = (template, user, password = '') => {
  const firstName = user?.name?.split(' ')[0] || 'User';
  const fullName = user?.name || firstName;

  let message = String(template || '').trim();
  if (!message) return '';

  return message
    .replace(/{firstName}/gi, firstName)
    .replace(/{fullName}/gi, fullName)
    .replace(/{email}/gi, user?.email || '')
    .replace(/{phone}/gi, user?.phone || '')
    .replace(/{employeeId}/gi, user?.employeeId || '')
    .replace(/{station}/gi, user?.station || '')
    .replace(/{department}/gi, user?.department || '')
    .replace(/{siteLink}/gi, PLATFORM_SITE_LINK)
    .replace(/{password}/gi, password);
};


// normalize phone numbers
const normalizeKenyaPhone = (phone) => {
  if (!phone) return null;

  let digits = String(phone).replace(/\D/g, "");

  if (digits.startsWith("0")) {
    digits = "254" + digits.slice(1);
  } else if (digits.length === 9 && /^[71]/.test(digits)) {
    digits = "254" + digits;
  }

  if (/^254[71]\d{8}$/.test(digits)) {
    return digits;
  }

  return null;
};

export const SendMessageNow = async (
  user,
  messageParams = "",
  plainPassword = ""
) => {
  const cfg = await PlatformConfig.getSingleton();

  const templateMessage =
    user?.role === "employee"
      ? cfg.notificationReminders.staffRegMessage
      : cfg.notificationReminders.internRegMessage;

  const message = formatReminderTemplate(
    templateMessage,
    user,
    plainPassword
  );

  const validPhone = normalizeKenyaPhone(user.phone);

  return axios.get("https://client.airtouch.co.ke:9012/sms/api/", {
    params: {
      issn: "TNC013",
      msisdn: validPhone,
      text: messageParams || message,
      username: process.env.SMS_USERNAME,
      password: process.env.SMS_PASSWORD
    }
  });
};
 */




import axios from "axios";
import "dotenv/config";
import PlatformConfig from "../model/PlatformConfig.js";


// ─────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────

const PLATFORM_SITE_LINK = "https://clocking.kmfri.go.ke/";

const SMS_URL =
  process.env.SOKOJUMLA_SMS_URL ||
  "https://cpaas.sokojumla.com/api/services/sendsms/";


// ─────────────────────────────────────────────────────────────
// FORMAT MESSAGE TEMPLATE
// ─────────────────────────────────────────────────────────────

const formatReminderTemplate = (
  template,
  user,
  password = ""
) => {
  const firstName =
    user?.name?.split(" ")[0] || "User";

  const fullName =
    user?.name || firstName;

  let message = String(template || "").trim();

  if (!message) {
    return "";
  }

  return message
    .replace(/{firstName}/gi, firstName)
    .replace(/{fullName}/gi, fullName)
    .replace(/{email}/gi, user?.email || "")
    .replace(/{phone}/gi, user?.phone || "")
    .replace(/{employeeId}/gi, user?.employeeId || "")
    .replace(/{station}/gi, user?.station || "")
    .replace(/{department}/gi, user?.department || "")
    .replace(/{siteLink}/gi, PLATFORM_SITE_LINK)
    .replace(/{password}/gi, password);
};


// ─────────────────────────────────────────────────────────────
// NORMALIZE KENYAN PHONE NUMBER
//
// Accepted:
// 0712345678
// 0112345678
// 712345678
// 112345678
// +254712345678
// 254712345678
// ─────────────────────────────────────────────────────────────

export const normalizeKenyaPhone = (phone) => {
  if (!phone) {
    return null;
  }

  let digits = String(phone)
    .trim()
    .replace(/\D/g, "");

  // 07XXXXXXXX / 01XXXXXXXX
  if (
    digits.length === 10 &&
    digits.startsWith("0")
  ) {
    digits = "254" + digits.slice(1);
  }

  // 7XXXXXXXX / 1XXXXXXXX
  else if (
    digits.length === 9 &&
    /^[71]/.test(digits)
  ) {
    digits = "254" + digits;
  }

  // Already 254XXXXXXXXX
  if (/^254[71]\d{8}$/.test(digits)) {
    return digits;
  }

  return null;
};


// ─────────────────────────────────────────────────────────────
// VALIDATE SMS ENVIRONMENT CONFIGURATION
// ─────────────────────────────────────────────────────────────

const validateSMSConfig = () => {
  const missing = [];

  if (!process.env.SOKOJUMLA_API_KEY) {
    missing.push("SOKOJUMLA_API_KEY");
  }

  if (!process.env.SOKOJUMLA_PARTNER_ID) {
    missing.push("SOKOJUMLA_PARTNER_ID");
  }

  if (!process.env.SOKOJUMLA_SHORTCODE) {
    missing.push("SOKOJUMLA_SHORTCODE");
  }

  if (missing.length > 0) {
    throw new Error(
      `Missing SMS configuration: ${missing.join(", ")}`
    );
  }
};


// ─────────────────────────────────────────────────────────────
// LOW-LEVEL SOKO JUMLA SMS REQUEST
//
// GET:
//
// /sendsms/
//    ?apikey=...
//    &partnerID=1568
//    &mobile=2547XXXXXXXX
//    &message=...
//    &shortcode=KMFRI
//
// Axios automatically URL-encodes the message.
// ─────────────────────────────────────────────────────────────

export const sendSokoJumlaSMS = async (
  phone,
  message
) => {
  validateSMSConfig();

  const mobile = normalizeKenyaPhone(phone);

  if (!mobile) {
    throw new Error(
      `Invalid Kenyan phone number: ${phone || "empty"}`
    );
  }

  const cleanMessage =
    String(message || "").trim();

  if (!cleanMessage) {
    throw new Error(
      "Cannot send an empty SMS message"
    );
  }

  try {

    const response = await axios.get(
      SMS_URL,
      {
        params: {
          apikey: process.env.SOKOJUMLA_API_KEY,
          partnerID: process.env.SOKOJUMLA_PARTNER_ID,
          mobile,
          message: cleanMessage,
          shortcode: process.env.SOKOJUMLA_SHORTCODE
        },

        headers: {
          Accept: "application/json"
        },

        timeout: 15000
      }
    );


    // Do NOT log API key/request URL.
    console.log(
      `[SMS] Request completed for ${mobile}`
    );

    console.log(
      "[SMS] Provider response:",
      response.data
    );


    return {
      success: true,
      mobile,
      data: response.data,
      status: response.status
    };

  } catch (error) {

    const providerError =
      error.response?.data;

    const status =
      error.response?.status;


    console.error(
      `[SMS] Failed sending SMS to ${mobile}`
    );

    console.error(
      "[SMS] HTTP Status:",
      status || "NO_RESPONSE"
    );

    console.error(
      "[SMS] Provider Error:",
      providerError || error.message
    );


    const smsError = new Error(
      providerError?.["response-description"] ||
      providerError?.message ||
      error.message ||
      "Failed to send SMS"
    );

    smsError.status = status;

    smsError.providerResponse =
      providerError;

    smsError.mobile =
      mobile;

    throw smsError;
  }
};


// ─────────────────────────────────────────────────────────────
// SEND REGISTRATION / TEMPLATE MESSAGE
//
// Existing usage remains:
//
// SendMessageNow(user)
//
// SendMessageNow(user, "Custom message")
//
// SendMessageNow(user, "", plainPassword)
// ─────────────────────────────────────────────────────────────

export const SendMessageNow = async (
  user,
  messageParams = "",
  plainPassword = ""
) => {

  if (!user) {
    throw new Error(
      "User is required to send SMS"
    );
  }


  // ───────────────────────────────────────────────────────────
  // Load platform configuration
  // ───────────────────────────────────────────────────────────

  const cfg =
    await PlatformConfig.getSingleton();


  // ───────────────────────────────────────────────────────────
  // Select registration template
  // ───────────────────────────────────────────────────────────

  const templateMessage =
    user?.role === "employee"
      ? cfg?.notificationReminders?.staffRegMessage
      : cfg?.notificationReminders?.internRegMessage;


  // ───────────────────────────────────────────────────────────
  // Generate template message
  // ───────────────────────────────────────────────────────────

  const generatedMessage =
    formatReminderTemplate(
      templateMessage,
      user,
      plainPassword
    );


  // Custom message takes priority
  const finalMessage =
    String(
      messageParams ||
      generatedMessage ||
      ""
    ).trim();


  if (!finalMessage) {
    throw new Error(
      `No SMS message available for ${
        user?.email ||
        user?.employeeId ||
        user?.name ||
        "user"
      }`
    );
  }


  // ───────────────────────────────────────────────────────────
  // Validate phone
  // ───────────────────────────────────────────────────────────

  const validPhone =
    normalizeKenyaPhone(user?.phone);


  if (!validPhone) {

    console.error(
      `[SMS] Invalid phone number for ${
        user?.email ||
        user?.employeeId ||
        user?.name ||
        "user"
      }: ${user?.phone}`
    );

    throw new Error(
      `Invalid Kenyan phone number: ${
        user?.phone || "missing"
      }`
    );
  }


  // ───────────────────────────────────────────────────────────
  // Send
  // ───────────────────────────────────────────────────────────

  return sendSokoJumlaSMS(
    validPhone,
    finalMessage
  );
};


// ─────────────────────────────────────────────────────────────
// GENERIC SMS FUNCTION
//
// Useful for:
// - Clock-in notifications
// - Clock-out notifications
// - Password reset
// - Clock-outside approval
// - Clock-outside rejection
// - Reminders
// - Admin notifications
//
// Example:
//
// await sendSMS(user.phone, "You have successfully clocked in.");
// ─────────────────────────────────────────────────────────────

export const sendSMS = async (
  phone,
  message
) => {
  return sendSokoJumlaSMS(
    phone,
    message
  );
};


// ─────────────────────────────────────────────────────────────
// SEND SMS TO MULTIPLE USERS
//
// Uses Promise.allSettled so one bad number/provider failure
// does not stop the whole batch.
// ─────────────────────────────────────────────────────────────

export const sendBulkSMS = async (
  users,
  message
) => {

  if (!Array.isArray(users)) {
    throw new Error(
      "Users must be an array"
    );
  }

  const results =
    await Promise.allSettled(
      users.map(async (user) => {

        const finalMessage =
          typeof message === "function"
            ? message(user)
            : message;

        return sendSMS(
          user.phone,
          finalMessage
        );
      })
    );


  const summary = {
    total: results.length,

    successful:
      results.filter(
        result =>
          result.status === "fulfilled"
      ).length,

    failed:
      results.filter(
        result =>
          result.status === "rejected"
      ).length,

    results
  };


  console.log(
    `[SMS] Batch complete: ${summary.successful}/${summary.total} successful`
  );


  return summary;
};


export default SendMessageNow;
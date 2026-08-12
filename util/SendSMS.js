
import axios from 'axios';
import "dotenv/config";
import PlatformConfig from "../model/PlatformConfig.js";

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


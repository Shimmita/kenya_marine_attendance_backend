
import axios from 'axios';
import "dotenv/config";
import PlatformConfig from "../model/PlatformConfig.js";

const formatReminderTemplate = (template, user) => {
    const firstName = user?.name?.split(' ')[0] || 'User';
    const fullName = user?.name || firstName;
    let message = String(template || '').trim();
    if (!message) return '';
    return message
        .replace(/\{firstName\}/gi, firstName)
        .replace(/\{email\}/gi, user?.email)
        .replace(/\{phone\}/gi, user?.phone)
        .replace(/\{station\}/gi, user?.station)
        .replace(/\{department\}/gi, user?.department)
        .replace(/\{name\}/gi, fullName);
};


export const SendMessageNow = async (user) => {

    // load platform cong especially for message
    const cfg = await PlatformConfig.getSingleton();
    // staff and intern/attachee will receive appropriate message
    const templateMessage = user?.role === "employee" ? cfg.notificationReminders.staffRegMessage : cfg.notificationReminders.internRegMessage;
    const message = formatReminderTemplate(templateMessage, user)
    return axios.get("https://client.airtouch.co.ke:9012/sms/api/", {
        params: {
            issn: "TNC013",
            msisdn: user?.phone,
            text: message,
            username: process.env.SMS_USERNAME,
            password: process.env.SMS_PASSWORD
        }
    });
};


import PlatformConfig from "../model/PlatformConfig.js";
import { SendMessageNow } from "../util/SendSMS.js";

/*
|--------------------------------------------------------------------------
| Format Message
|--------------------------------------------------------------------------
*/

export const formatMessage = (template, user) => {

    if (!template) return "";

    const firstName = user?.name?.split(" ")[0] || "User";

    return template

        .replace(/\{firstName\}/gi, firstName)
        .replace(/\{name\}/gi, user?.name || "")
        .replace(/\{email\}/gi, user?.email || "")
        .replace(/\{phone\}/gi, user?.phone || "")
        .replace(/\{department\}/gi, user?.department || "")
        .replace(/\{station\}/gi, user?.station || "");

};

/*
|--------------------------------------------------------------------------
| SMS
|--------------------------------------------------------------------------
*/

const sendSMS = async (user, message) => {

    try {

        if (!user?.phone) {
            console.warn(`SMS skipped (${user?.email || "unknown"}): missing phone`);
            return false;
        }

        if (!message) {
            console.warn(`SMS skipped (${user?.email || "unknown"}): empty message`);
            return false;
        }

        await SendMessageNow(user, message, "");

        return true;

    } catch (err) {

        console.error(`SMS Error (${user?.email || "unknown"})`, err.message);

        return false;

    }

};

/*
|--------------------------------------------------------------------------
| In-App Notification
|--------------------------------------------------------------------------
|
| Future implementation
|
*/

const sendInApp = async (user, message, type) => {

    console.log(`IN-APP -> ${user?.email || "unknown"} (${type})`);

    // send SMS for now 
    await sendSMS(user, message);

    return true;

};

/*
|--------------------------------------------------------------------------
| Email
|--------------------------------------------------------------------------
|
| Future implementation
|
*/

const sendEmail = async (user, message, type) => {

    console.log(`EMAIL -> ${user?.email || "unknown"} (${type})`);

    return true;

};

/*
|--------------------------------------------------------------------------
| Main Notification Service
|--------------------------------------------------------------------------
*/

export const sendNotification = async (

    user,

    template,

    type

) => {

    try {

        const config = await PlatformConfig.getSingleton();

        const channels =
            config.notificationReminders?.channels || [];

        const message =
            formatMessage(template, user);

        let delivered = false;

        if (channels.includes("sms")) {

            delivered = await sendSMS(user, message) || delivered;

        }

        if (channels.includes("in_app")) {

            delivered = await sendInApp(
                user,
                message,
                type
            ) || delivered;

        }

        if (channels.includes("email")) {

            delivered = await sendEmail(
                user,
                message,
                type
            ) || delivered;

        }

        return delivered;

    }

    catch (err) {

        console.error("Notification Error:", err);

        return false;

    }

};

export default {

    sendNotification,

    formatMessage

};

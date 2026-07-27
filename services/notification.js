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

        await SendMessageNow(user, message);

        return true;

    } catch (err) {

        console.error(`SMS Error (${user.email})`, err.message);

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

    console.log(`IN-APP -> ${user.email} (${type})`);

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

    console.log(`EMAIL -> ${user.email} (${type})`);

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
            config.notificationReminders.channels || [];

        const message =
            formatMessage(template, user);

        if (channels.includes("sms")) {

            await sendSMS(user, message);

        }

        if (channels.includes("in_app")) {

            await sendInApp(
                user,
                message,
                type
            );

        }

        if (channels.includes("email")) {

            await sendEmail(
                user,
                message,
                type
            );

        }

        return true;

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
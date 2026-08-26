import PlatformConfig from "../model/PlatformConfig.js";
import MessageUser from "../model/MessageUser.js";
import { SendMessageNow } from "../util/SendSMS.js";

const PLATFORM_SITE_LINK = "https://clocking.kmfri.go.ke/";

/*
|--------------------------------------------------------------------------
| Format Message
|--------------------------------------------------------------------------
*/

export const formatMessage = (template, user, values = {}) => {

    if (!template) return "";

    const firstName = user?.name?.split(" ")[0] || "User";
    const replacements = {
        firstName,
        name: user?.name || "",
        fullName: user?.name || "",
        email: user?.email || "",
        phone: user?.phone || "",
        employeeId: user?.employeeId || "",
        role: user?.role || "",
        rank: user?.rank || "",
        department: user?.department || "",
        station: user?.station || "",
        siteLink: PLATFORM_SITE_LINK,
        ...values,
    };

    return Object.entries(replacements).reduce(
        (message, [key, value]) =>
            message.replace(new RegExp(`\\{${key}\\}`, "gi"), value == null ? "" : String(value)),
        String(template)
    );

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

    if (!user?.email || !message) {
        return false;
    }

    await MessageUser.create({
        user_email: user.email,
        message,
        title: type,
        label: "none",
        status: "pending",
    });

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

    type,

    values = {}

) => {

    try {

        const config = await PlatformConfig.getSingleton();

        const channels =
            config.notificationReminders?.channels || [];

        const message =
            formatMessage(template, user, values);

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

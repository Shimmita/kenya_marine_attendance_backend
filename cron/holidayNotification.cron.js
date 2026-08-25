import PlatformConfig from "../model/PlatformConfig.js";
import ReminderDelivery from "../model/ReminderDelivery.js";
import User from "../model/User.js";
import { getHolidayForDate } from "../services/holiday.js";
import { sendNotification } from "../services/notification.js";

const getReminderDateKey = () =>
    new Intl.DateTimeFormat("en-CA", {
        timeZone: "Africa/Nairobi",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
    }).format(new Date());

const formatHolidayDateLabel = (dateKey) => {
    const date = new Date(`${dateKey}T00:00:00+03:00`);
    return new Intl.DateTimeFormat("en-GB", {
        timeZone: "Africa/Nairobi",
        weekday: "long",
        day: "2-digit",
        month: "long",
        year: "numeric",
    }).format(date);
};

const reserveReminderDelivery = async (user, type, dateKey) => {
    const email = String(user?.email || "").trim().toLowerCase();
    if (!email) return false;

    try {
        await ReminderDelivery.create({
            reminderKey: `${type}:${email}:${dateKey}`,
            user_email: email,
            type,
            dateKey,
        });

        return true;
    } catch (err) {
        if (err?.code === 11000) return false;
        throw err;
    }
};

const markReminderDelivery = async (user, type, dateKey, sent, error = "") => {
    const email = String(user?.email || "").trim().toLowerCase();
    if (!email) return;

    await ReminderDelivery.updateOne(
        { reminderKey: `${type}:${email}:${dateKey}` },
        {
            $set: {
                status: sent ? "sent" : "failed",
                sentAt: sent ? new Date() : null,
                error: error ? String(error).slice(0, 500) : "",
            },
        }
    );
};

const registerHolidayNotificationJob = async () => {
    try {
        console.log("=======================================");
        console.log("Running Holiday Notification Job...");
        console.log("=======================================");

        const config = await PlatformConfig.getSingleton();
        const holiday = await getHolidayForDate(new Date(), config);

        if (!holiday) {
            console.log("Today is not a configured holiday.");
            return;
        }

        const users = await User.find({
            isAccountActive: { $ne: false },
            email: { $exists: true, $ne: "" },
        }).lean();

        const reminderType = "HOLIDAY_NOTICE";
        const reminderDateKey = getReminderDateKey();
        const holidayDate = formatHolidayDateLabel(holiday.date || reminderDateKey);
        const template = config.notificationReminders?.holidayNoticeMessage ||
            "Dear {firstName}, today ({holidayDate}) is {holidayName}. KMFRI Attendance clocking is not required for the holiday.";

        let totalSent = 0;
        let totalSkipped = 0;

        for (const user of users) {
            try {
                const reserved = await reserveReminderDelivery(user, reminderType, reminderDateKey);
                if (!reserved) {
                    totalSkipped++;
                    continue;
                }

                const sent = await sendNotification(user, template, reminderType, {
                    date: holidayDate,
                    holidayDate,
                    holidayName: holiday.name,
                    reason: holiday.name,
                });

                await markReminderDelivery(user, reminderType, reminderDateKey, sent);
                if (sent) totalSent++;
            } catch (err) {
                await markReminderDelivery(user, reminderType, reminderDateKey, false, err?.message || err);
                console.error(`Holiday Notice User Error (${user?.email || "unknown"}):`, err);
            }
        }

        console.log("---------------------------------------");
        console.log(`Holiday Notices Sent : ${totalSent}`);
        console.log(`Holiday Notices Skipped : ${totalSkipped}`);
        console.log(`Holiday Notice Finished : ${holiday.name}`);
        console.log("---------------------------------------");
    } catch (err) {
        console.error("Holiday Notification Job Error:", err);
    }
};

export default registerHolidayNotificationJob;

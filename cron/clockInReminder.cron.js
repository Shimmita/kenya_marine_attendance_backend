import PlatformConfig from "../model/PlatformConfig.js";
import ReminderDelivery from "../model/ReminderDelivery.js";
import { getAbsentUsersToday } from "../services/attendance.js";

import {
    isWorkingDay
} from "../services/holiday.js";
import { sendNotification } from "../services/notification.js";

import { endOfToday, startOfToday } from "../util/Date.js";

const getReminderDateKey = () =>
    new Intl.DateTimeFormat("en-CA", {
        timeZone: "Africa/Nairobi",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
    }).format(new Date());

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


/*
|--------------------------------------------------------------------------
| Clock In Reminder
|--------------------------------------------------------------------------
|
| Runs at the configured time.
|
| Sends reminders to every active user that
| has NOT clocked in today.
|
*/

const registerClockInReminder = async () => {

    try {

        console.log("=======================================");
        console.log("Running Clock In Reminder...");
        console.log("=======================================");

        /*
        |--------------------------------------------------------------------------
        | Working Day Check
        |--------------------------------------------------------------------------
        */

        const workingDay =
            await isWorkingDay();

        if (!workingDay) {

            console.log("Today is not a working day.");

            return;

        }

        /*
        |--------------------------------------------------------------------------
        | Load Platform Config
        |--------------------------------------------------------------------------
        */

        const config =
            await PlatformConfig.getSingleton();

        const reminderMessage =
            config.notificationReminders.clockInMessage;

        /*
        |--------------------------------------------------------------------------
        | Get Active Users
        |--------------------------------------------------------------------------
        */

        const start =
            startOfToday();

        const end =
            endOfToday();

        const users =
            await getAbsentUsersToday(start, end);

        let totalSent = 0;
        let totalSkipped = 0;
        const reminderType = "CLOCK_IN_REMINDER";
        const reminderDateKey = getReminderDateKey();

        /*
        |--------------------------------------------------------------------------
        | Check Attendance
        |--------------------------------------------------------------------------
        */

        for (const user of users) {

            try {
                const reserved = await reserveReminderDelivery(user, reminderType, reminderDateKey);
                if (!reserved) {
                    totalSkipped++;
                    continue;
                }

                const sent =
                    await sendNotification(

                        user,

                        reminderMessage,

                        reminderType

                    );

                await markReminderDelivery(user, reminderType, reminderDateKey, sent);

                if(sent)
                    totalSent++

            } catch (err) {

                await markReminderDelivery(user, reminderType, reminderDateKey, false, err?.message || err);
                console.error(`Clock In Reminder User Error (${user?.email || "unknown"}):`, err);

            }

        }

        console.log("---------------------------------------");
        console.log(`Clock In Reminders Sent : ${totalSent}`);
        console.log(`Clock In Reminders Skipped : ${totalSkipped}`);
        console.log("Clock In Reminder Finished");
        console.log("---------------------------------------");

    }

    catch (err) {

        console.error(

            "Clock In Reminder Error:",

            err

        );

    }

};

export default registerClockInReminder;

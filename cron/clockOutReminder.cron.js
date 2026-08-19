import PlatformConfig from "../model/PlatformConfig.js";
import ReminderDelivery from "../model/ReminderDelivery.js";

import { sendNotification } from "../services/notification.js";

import { isWorkingDay } from "../services/holiday.js";
import { endOfToday, startOfToday } from "../util/Date.js";
import { getUsersNotClockedOutToday } from "../services/attendance.js";

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
| Clock Out Reminder
|--------------------------------------------------------------------------
|
| Sends reminders to users who:
|
| 1. Clocked in today
| 2. Have NOT clocked out
|
*/

const registerClockOutReminder = async () => {

    try {

        console.log("=======================================");
        console.log("Running Clock Out Reminder...");
        console.log("=======================================");

        /*
        |--------------------------------------------------------------------------
        | Working Day Check
        |--------------------------------------------------------------------------
        */

        if (!(await isWorkingDay())) {

            console.log("Today is not a working day.");

            return;

        }

        /*
        |--------------------------------------------------------------------------
        | Platform Configuration
        |--------------------------------------------------------------------------
        */

        const config =
            await PlatformConfig.getSingleton();

        const reminderMessage =
            config.notificationReminders.clockOutMessage;

        /*
        |--------------------------------------------------------------------------
        | Today's Attendance
        |--------------------------------------------------------------------------
        */

        const attendanceRecords =
            await getUsersNotClockedOutToday(startOfToday(), endOfToday());

        let totalSent = 0;
        let totalSkipped = 0;
        const reminderType = "CLOCK_OUT_REMINDER";
        const reminderDateKey = getReminderDateKey();

        /*
        |--------------------------------------------------------------------------
        | Notify Users
        |--------------------------------------------------------------------------
        */

        for (const attendance of attendanceRecords) {

            try {

                const user = {

                    name: attendance.name,
                    email: attendance.email,
                    phone: attendance.phone,
                    department: attendance.department,
                    station: attendance.station

                };

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

                if (sent)
                    totalSent++

            } catch (err) {

                await markReminderDelivery(attendance, reminderType, reminderDateKey, false, err?.message || err);
                console.error(`Clock Out Reminder User Error (${attendance?.email || "unknown"}):`, err);

            }

        }

        console.log("---------------------------------------");
        console.log(`Clock Out Reminders Sent : ${totalSent}`);
        console.log(`Clock Out Reminders Skipped : ${totalSkipped}`);
        console.log("Clock Out Reminder Finished");
        console.log("---------------------------------------");

    }

    catch (err) {

        console.error(

            "Clock Out Reminder Error:",

            err

        );

    }

};

export default registerClockOutReminder;

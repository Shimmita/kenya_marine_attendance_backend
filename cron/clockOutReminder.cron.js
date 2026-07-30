import PlatformConfig from "../model/PlatformConfig.js";

import { sendNotification } from "../services/notification.js";

import { isWorkingDay } from "../services/holiday.js";
import { endOfToday, startOfToday } from "../util/Date.js";
import { getUsersNotClockedOutToday } from "../services/attendance.js";

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

                const sent =
                    await sendNotification(

                        user,

                        reminderMessage,

                        "CLOCK_OUT_REMINDER"

                    );


                if (sent)
                    totalSent++

            } catch (err) {

                console.error(`Clock Out Reminder User Error (${attendance?.email || "unknown"}):`, err);

            }

        }

        console.log("---------------------------------------");
        console.log(`Clock Out Reminders Sent : ${totalSent}`);
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

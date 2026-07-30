import PlatformConfig from "../model/PlatformConfig.js";
import { getAbsentUsersToday } from "../services/attendance.js";

import {
    isWorkingDay
} from "../services/holiday.js";
import { sendNotification } from "../services/notification.js";

import { endOfToday, startOfToday } from "../util/Date.js";


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

        /*
        |--------------------------------------------------------------------------
        | Check Attendance
        |--------------------------------------------------------------------------
        */

        for (const user of users) {

            try {

                const sent =
                    await sendNotification(

                        user,

                        reminderMessage,

                        "CLOCK_IN_REMINDER"

                    );


                if(sent)
                    totalSent++

            } catch (err) {

                console.error(`Clock In Reminder User Error (${user?.email || "unknown"}):`, err);

            }

        }

        console.log("---------------------------------------");
        console.log(`Clock In Reminders Sent : ${totalSent}`);
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

import PlatformConfig from "../model/PlatformConfig.js";
import Clocking from "../model/Clocking.js";

import { sendNotification } from "../services/notification.js";

import { isWorkingDay } from "../services/holiday.js";
import { endOfToday, startOfToday } from "../util/Date.js";

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
            await Clocking.find({

                clock_in: {

                    $gte: startOfToday(),

                    $lte: endOfToday()

                },

                clock_out: null

            });

        let totalSent = 0;

        /*
        |--------------------------------------------------------------------------
        | Notify Users
        |--------------------------------------------------------------------------
        */

        for (const attendance of attendanceRecords) {

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
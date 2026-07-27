import PlatformConfig from "../model/PlatformConfig.js";
import Clocking from "../model/Clocking.js";

import {
    isWorkingDay
} from "../services/holiday.js";

import { sendNotification } from "../services/notification.js";

import {
    startOfYesterday,
    endOfYesterday
} from "../util/Date.js";
import { getEligibleUsers, hasClockedYesterday } from "../services/attendance.js";

/*
|--------------------------------------------------------------------------
| Midnight Attendance Processing
|--------------------------------------------------------------------------
|
| 1. Marks missed clock-outs
| 2. Sends missed clock-out reminders
| 3. Sends absent reminders
|
*/

const registerMidnightAttendanceJob = async () => {

    try {

        console.log("=======================================");
        console.log("Running Midnight Attendance Job...");
        console.log("=======================================");

        /*
        |--------------------------------------------------------------------------
        | Yesterday
        |--------------------------------------------------------------------------
        */

        const start =
            startOfYesterday();

        const end =
            endOfYesterday();

        /*
        |--------------------------------------------------------------------------
        | Was Yesterday A Working Day?
        |--------------------------------------------------------------------------
        */

        const yesterday =
            new Date(start);

        if (!(await isWorkingDay(yesterday))) {

            console.log("Yesterday was not a working day.");

            return;

        }

        /*
        |--------------------------------------------------------------------------
        | Platform Config
        |--------------------------------------------------------------------------
        */

        const config =
            await PlatformConfig.getSingleton();

        const missedClockOutMessage =
            config.notificationReminders.missedClockOutMessage;

        const absentMessage =
            config.notificationReminders.absentMessage;

        /*
        |--------------------------------------------------------------------------
        | PART 1
        | Missed Clock Out
        |--------------------------------------------------------------------------
        */

        const records =
            await Clocking.find({

                clock_in: {

                    $gte: start,

                    $lte: end

                }

            });

        let missedClockOutCount = 0;

        for (const attendance of records) {

            if (attendance.clock_out)
                continue;

            attendance.missedClockOut = true;

            await attendance.save();

            await sendNotification(

                {

                    name: attendance.name,

                    email: attendance.email,

                    phone: attendance.phone,

                    department: attendance.department,

                    station: attendance.station

                },

                missedClockOutMessage,

                "MISSED_CLOCK_OUT"

            );

            missedClockOutCount++;

        }

        /*
        |--------------------------------------------------------------------------
        | PART 2
        | Absent Users
        |--------------------------------------------------------------------------
        */

        const users =
            await getEligibleUsers();

        let absentCount = 0;

        for (const user of users) {

            const attendance =
                await hasClockedYesterday(

                    user.email,

                    start,

                    end

                );

            if (attendance)
                continue;

            await sendNotification(

                user,

                absentMessage,

                "ABSENT"

            );

            absentCount++;

        }

        console.log("---------------------------------------");
        console.log(`Missed Clock Outs : ${missedClockOutCount}`);
        console.log(`Absent Users      : ${absentCount}`);
        console.log("Midnight Attendance Completed");
        console.log("---------------------------------------");

    }

    catch (err) {

        console.error(

            "Midnight Attendance Error:",

            err

        );

    }

};

export default registerMidnightAttendanceJob;
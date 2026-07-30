import PlatformConfig from "../model/PlatformConfig.js";
import {
    isWorkingDay
} from "../services/holiday.js";

import { sendNotification } from "../services/notification.js";

import {
    startOfYesterday,
    endOfYesterday,
    now
} from "../util/Date.js";
import {
    getAbsentUsersYesterday,
    getMissedClockOutsYesterday,
    markMissedClockOut
} from "../services/attendance.js";

const processedAttendanceDates = new Set();
const processingAttendanceDates = new Set();

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

    let yesterdayKey;

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

        const yesterday = now().subtract(1, "day");
        yesterdayKey = yesterday.format("YYYY-MM-DD");

        if (processedAttendanceDates.has(yesterdayKey)) {

            console.log(`Midnight Attendance already processed for ${yesterdayKey}.`);

            return;

        }

        if (processingAttendanceDates.has(yesterdayKey)) {

            console.log(`Midnight Attendance processing already in progress for ${yesterdayKey}.`);

            return;

        }

        if (!(await isWorkingDay(yesterday))) {
            return;
        }

        processingAttendanceDates.add(yesterdayKey);

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
            await getMissedClockOutsYesterday(start, end);

        let missedClockOutCount = 0;

        for (const attendance of records) {

            try {

                await markMissedClockOut(attendance._id);

                const sent =
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

                if (sent)
                    missedClockOutCount++;

            } catch (err) {

                console.error(`Missed Clock Out Error (${attendance?.email || "unknown"}):`, err);

            }

        }

        /*
        |--------------------------------------------------------------------------
        | PART 2
        | Absent Users
        |--------------------------------------------------------------------------
        */

        const users =
            await getAbsentUsersYesterday(start, end);

        let absentCount = 0;

        for (const user of users) {

            try {

                const sent =
                    await sendNotification(

                        user,

                        absentMessage,

                        "ABSENT"

                    );

                if (sent)
                    absentCount++;

            } catch (err) {

                console.error(`Absent Reminder Error (${user?.email || "unknown"}):`, err);

            }

        }

        console.log("---------------------------------------");
        console.log(`Missed Clock Outs : ${missedClockOutCount}`);
        console.log(`Absent Users      : ${absentCount}`);
        console.log("Midnight Attendance Completed");
        console.log("---------------------------------------");

        processedAttendanceDates.add(yesterdayKey);
        processingAttendanceDates.delete(yesterdayKey);

    }

    catch (err) {

        console.error(

            "Midnight Attendance Error:",

            err

        );

        if (typeof yesterdayKey !== "undefined")
            processingAttendanceDates.delete(yesterdayKey);

    }

};

export default registerMidnightAttendanceJob;

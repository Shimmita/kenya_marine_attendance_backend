import cron from "node-cron";

import PlatformConfig from "../model/PlatformConfig.js";
import registerClockInReminder from "./clockInReminder.cron.js";
import registerClockOutReminder from "./clockOutReminder.cron.js";
import registerMidnightAttendanceJob from "./midnightAttendance.cron.js";



/*
|--------------------------------------------------------------------------
| Active Scheduled Tasks
|--------------------------------------------------------------------------
*/

let scheduledTasks = [];

/*
|--------------------------------------------------------------------------
| Convert HH:mm to Cron Expression
|--------------------------------------------------------------------------
*/

const timeToCron = (time) => {

    if (!isValidTime(time))
        throw new Error(`Invalid scheduler time: ${time}`);

    const [hour, minute] = time.split(":").map(Number);

    return `${minute} ${hour} * * *`;

};

/*
|--------------------------------------------------------------------------
| Add/Subtract Minutes
|--------------------------------------------------------------------------
*/

const offsetTime = (

    time,

    offsetMinutes

) => {

    if (!isValidTime(time))
        throw new Error(`Invalid scheduler time: ${time}`);

    const safeOffsetMinutes = Number(offsetMinutes || 0);

    if (!Number.isFinite(safeOffsetMinutes))
        throw new Error(`Invalid scheduler offset: ${offsetMinutes}`);

    let [hour, minute] = time.split(":").map(Number);

    let totalMinutes =
        hour * 60 +
        minute +
        safeOffsetMinutes;

    while (totalMinutes < 0)
        totalMinutes += 1440;

    totalMinutes =
        totalMinutes % 1440;

    const h = Math.floor(totalMinutes / 60);

    const m = totalMinutes % 60;

    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;

};

const isValidTime = (time) => {

    if (typeof time !== "string")
        return false;

    const match = time.match(/^([01]\d|2[0-3]):([0-5]\d)$/);

    return Boolean(match);

};

/*
|--------------------------------------------------------------------------
| Stop Existing Scheduler
|--------------------------------------------------------------------------
*/

const stopScheduler = () => {

    scheduledTasks.forEach(task => {

        try {

            task.stop();

            if (typeof task.destroy === "function")
                task.destroy();

        } catch (err) {

            console.error("Attendance Scheduler Stop Error:", err);

        }

    });

    scheduledTasks = [];

};

/*
|--------------------------------------------------------------------------
| Register Scheduler
|--------------------------------------------------------------------------
*/

export const startAttendanceScheduler = async () => {

    stopScheduler();

    const config =
        await PlatformConfig.getSingleton();

    const policy =
        config.attendancePolicy || {};

    /*
    |--------------------------------------------------------------------------
    | Calculate Schedule Times
    |--------------------------------------------------------------------------
    */

    const clockInReminderTime =
        offsetTime(

            policy.standardClockIn || "08:00",

            policy.clockInReminderOffsetMinutes

        );

    const clockOutReminderTime =
        offsetTime(

            policy.standardClockOut || "17:00",

            -policy.clockOutReminderOffsetMinutes

        );

    const midnightTime =
        policy.midnightProcessingTime || "00:00";

    /*
    |--------------------------------------------------------------------------
    | Register Clock In Reminder
    |--------------------------------------------------------------------------
    */

    scheduledTasks.push(

        cron.schedule(

            timeToCron(clockInReminderTime),

            registerClockInReminder,

            {

                timezone: "Africa/Nairobi"

            }

        )

    );

    /*
    |--------------------------------------------------------------------------
    | Register Clock Out Reminder
    |--------------------------------------------------------------------------
    */

    scheduledTasks.push(

        cron.schedule(

            timeToCron(clockOutReminderTime),

            registerClockOutReminder,

            {

                timezone: "Africa/Nairobi"

            }

        )

    );

    /*
    |--------------------------------------------------------------------------
    | Register Midnight Attendance Job
    |--------------------------------------------------------------------------
    */

    scheduledTasks.push(

        cron.schedule(

            timeToCron(midnightTime),

            registerMidnightAttendanceJob,

            {

                timezone: "Africa/Nairobi"

            }

        )

    );

    console.log("========================================");
    console.log("Attendance Scheduler Started");
    console.log("----------------------------------------");
    console.log("Clock In Reminder :", clockInReminderTime);
    console.log("Clock Out Reminder:", clockOutReminderTime);
    console.log("Midnight Job      :", midnightTime);
    console.log("========================================");

};

/*
|--------------------------------------------------------------------------
| Refresh Scheduler
|--------------------------------------------------------------------------
|
| Call this after PlatformConfig updates.
|
*/

export const refreshAttendanceScheduler = async () => {

    console.log("Refreshing Attendance Scheduler...");

    await startAttendanceScheduler();

};

export default startAttendanceScheduler;

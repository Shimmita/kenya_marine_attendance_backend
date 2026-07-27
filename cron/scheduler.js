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

    let [hour, minute] = time.split(":").map(Number);

    let totalMinutes =
        hour * 60 +
        minute +
        offsetMinutes;

    while (totalMinutes < 0)
        totalMinutes += 1440;

    totalMinutes =
        totalMinutes % 1440;

    const h = Math.floor(totalMinutes / 60);

    const m = totalMinutes % 60;

    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;

};

/*
|--------------------------------------------------------------------------
| Stop Existing Scheduler
|--------------------------------------------------------------------------
*/

const stopScheduler = () => {

    scheduledTasks.forEach(task => task.stop());

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
        config.attendancePolicy;

    /*
    |--------------------------------------------------------------------------
    | Calculate Schedule Times
    |--------------------------------------------------------------------------
    */

    const clockInReminderTime =
        offsetTime(

            policy.standardClockIn,

            policy.clockInReminderOffsetMinutes

        );

    const clockOutReminderTime =
        offsetTime(

            policy.standardClockOut,

            -policy.clockOutReminderOffsetMinutes

        );

    const midnightTime =
        policy.midnightProcessingTime;

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
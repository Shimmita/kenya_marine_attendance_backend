import Clocking from "../model/Clocking.js";
import PlatformConfig from "../model/PlatformConfig.js";
import User from "../model/User.js";

const TIMEZONE_OFFSET_HOURS = 3;

const getNairobiDateParts = (date = new Date()) => {
    const parts = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Africa/Nairobi",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
    }).formatToParts(date);

    return Object.fromEntries(parts.map((part) => [part.type, Number(part.value)]));
};

const getSystemClockOutTime = (clockIn, standardClockOut = "17:00") => {
    const [hours, minutes] = String(standardClockOut || "17:00").split(":").map(Number);
    const safeHours = Number.isFinite(hours) ? hours : 17;
    const safeMinutes = Number.isFinite(minutes) ? minutes : 0;
    const parts = getNairobiDateParts(clockIn);
    const systemClockOut = new Date(Date.UTC(
        parts.year,
        parts.month - 1,
        parts.day,
        safeHours - TIMEZONE_OFFSET_HOURS,
        safeMinutes,
        0,
        0
    ));

    if (systemClockOut > clockIn) return systemClockOut;

    return new Date(Date.UTC(parts.year, parts.month - 1, parts.day, 20, 59, 59, 999));
};

/**
 * Users eligible for attendance.
 */
export const getEligibleUsers = async () => {

    return User.find({

        isAccountActive: true,

        isOnLeave: false

    })
        .select("-password")
        .sort({ name: 1 })
        .lean();

};


/**
 * Users who clocked today.
 */
export const getTodayClockings = async (
    start,
    end
) => {

    return Clocking.find({

        clock_in: {

            $gte: start,

            $lte: end

        }

    })
        .select("email")
        .lean();

};


/**
 * Users who clocked yesterday.
 */
export const getYesterdayClockings = async (
    start,
    end
) => {

    return Clocking.find({

        clock_in: {

            $gte: start,

            $lte: end

        }

    })
        .select("email")
        .lean();

};


/**
 * Has this user clocked today?
 */
export const hasClockedToday = async (
    email,
    start,
    end
) => {

    return Clocking.exists({

        email,

        clock_in: {

            $gte: start,

            $lte: end

        }

    });

};


/**
 * Has this user clocked yesterday?
 */
export const hasClockedYesterday = async (
    email,
    start,
    end
) => {

    return Clocking.exists({

        email,

        clock_in: {

            $gte: start,

            $lte: end

        }

    });

};

const uniqueEmails = (records) =>
    new Set(records.map(record => record.email).filter(Boolean));


/**
 * Users currently inside office
 * but haven't clocked out.
 */
export const getUsersNotClockedOutToday = async (
    start,
    end
) => {

    return Clocking.find({

        clock_in: {

            $gte: start,

            $lte: end

        },

        clock_out: null

    }).lean();

};


/**
 * Users absent today.
 */
export const getAbsentUsersToday = async (
    start,
    end
) => {

    const [eligibleUsers, attendance] = await Promise.all([
        getEligibleUsers(),
        getTodayClockings(start, end)
    ]);

    const attendedEmails = uniqueEmails(attendance);

    return eligibleUsers.filter(

        user => !attendedEmails.has(user.email)

    );

};


/**
 * Users absent yesterday.
 */
export const getAbsentUsersYesterday = async (
    start,
    end
) => {

    const [eligibleUsers, attendance] = await Promise.all([
        getEligibleUsers(),
        getYesterdayClockings(start, end)
    ]);

    const attendedEmails = uniqueEmails(attendance);

    return eligibleUsers.filter(

        user => !attendedEmails.has(user.email)

    );

};


/**
 * Attendance records
 * missing clock out.
 */
export const getMissedClockOutsYesterday = async (
    start,
    end
) => {

    return Clocking.find({

        clock_in: {

            $gte: start,

            $lte: end

        },

        clock_out: null,

        missedClockOut: { $ne: true }

    }).lean();

};


/**
 * Mark missed clock out.
 */
export const markMissedClockOut = async (
    attendanceId
) => {

    const attendance = await Clocking.findById(attendanceId);
    if (!attendance) return null;

    const config = await PlatformConfig.getSingleton();
    if (config.attendancePolicy?.autoClockOutMissedSessions === false) {
        return attendance;
    }

    const standardClockOut = config.attendancePolicy?.standardClockOut || "17:00";

    attendance.clock_out = getSystemClockOutTime(attendance.clock_in, standardClockOut);
    attendance.clockOutLocationName = attendance.clockOutLocationName || "System";
    attendance.missedClockOut = true;
    attendance.isPresent = true;

    await attendance.save();

    await User.updateOne(
        { email: attendance.email },
        {
            $set: {
                hasClockedIn: false,
                isToClockOut: false,
            },
        }
    );

    return attendance;

};

export default {

    getEligibleUsers,

    getTodayClockings,

    getYesterdayClockings,

    hasClockedToday,

    hasClockedYesterday,

    getUsersNotClockedOutToday,

    getAbsentUsersToday,

    getAbsentUsersYesterday,

    getMissedClockOutsYesterday,

    markMissedClockOut

};

import Clocking from "../model/Clocking.js";
import User from "../model/User.js";

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

    return Clocking.findByIdAndUpdate(

        attendanceId,

        {

            missedClockOut: true

        },

        { new: true }

    );

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

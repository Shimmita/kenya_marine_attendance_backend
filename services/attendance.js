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

    }).lean();

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

    }).lean();

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

    return Clocking.findOne({

        email,

        clock_in: {

            $gte: start,

            $lte: end

        }

    });

};


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

    const eligibleUsers = await getEligibleUsers();

    const attendance = await getTodayClockings(
        start,
        end
    );

    const attendedEmails = new Set(

        attendance.map(a => a.email)

    );

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

    const eligibleUsers = await getEligibleUsers();

    const attendance = await getYesterdayClockings(
        start,
        end
    );

    const attendedEmails = new Set(

        attendance.map(a => a.email)

    );

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

        clock_out: null

    });

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

        }

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
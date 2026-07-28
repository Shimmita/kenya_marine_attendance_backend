import PlatformConfig from "../model/PlatformConfig.js";

export const isWeekend = async (date = now()) => {

    const cfg = await PlatformConfig.getSingleton();

    return !cfg.attendancePolicy.workingDays.includes(date.day());

};

export const isHoliday = async (date = now()) => {

    const cfg = await PlatformConfig.getSingleton();

    const holidays = cfg.holidays.filter(h => h.active);

    for (const holiday of holidays) {

        const holidayDate = dayjs(holiday.date);

        if (holiday.recurring) {

            if (
                holidayDate.month() === date.month() &&
                holidayDate.date() === date.date()
            ) {

                return true;

            }

        }

        else {

            if (
                holidayDate.format("YYYY-MM-DD") ===
                date.format("YYYY-MM-DD")
            ) {

                return true;

            }

        }

    }

    return false;

};

export const isWorkingDay = async (date = now()) => {

    if (await isWeekend(date))
        return false;

    if (await isHoliday(date))
        return false;

    return true;

};
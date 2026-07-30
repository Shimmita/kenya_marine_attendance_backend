import PlatformConfig from "../model/PlatformConfig.js";
import dayjs from "dayjs";
import { now, TIMEZONE } from "../util/Date.js";

const toNairobiDay = (date = now()) =>
    dayjs.isDayjs(date)
        ? date.tz(TIMEZONE)
        : dayjs(date).tz(TIMEZONE);

export const isWeekend = async (date = now()) => {

    const cfg = await PlatformConfig.getSingleton();

    const targetDate = toNairobiDay(date);

    const workingDays =
        cfg.attendancePolicy?.workingDays || [1, 2, 3, 4, 5];

    return !workingDays.includes(targetDate.day());

};

export const isHoliday = async (date = now()) => {

    const cfg = await PlatformConfig.getSingleton();

    const targetDate = toNairobiDay(date);

    const holidays = (cfg.holidays || []).filter(h => h.active);

    for (const holiday of holidays) {

        const holidayDate = toNairobiDay(holiday.date);

        if (holiday.recurring) {

            if (
                holidayDate.month() === targetDate.month() &&
                holidayDate.date() === targetDate.date()
            ) {

                return true;

            }

        }

        else {

            if (
                holidayDate.format("YYYY-MM-DD") ===
                targetDate.format("YYYY-MM-DD")
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

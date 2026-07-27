import dayjs from "dayjs";
import PlatformConfig from "../model/PlatformConfig.js";
import { now } from "../util/Date.js";

export const isWeekend = async () => {

    const cfg = await PlatformConfig.getSingleton();

    const today = now().day();

    return !cfg.attendancePolicy.workingDays.includes(today);

};

export const isHoliday = async () => {

    const cfg = await PlatformConfig.getSingleton();

    const today = now();

    const holidays = cfg.holidays.filter(h => h.active);

    for (const holiday of holidays) {

        const holidayDate = dayjs(holiday.date);

        if (holiday.recurring) {

            if (

                holidayDate.month() === today.month() &&

                holidayDate.date() === today.date()

            ) {

                return true;

            }

        } else {

            if (

                holidayDate.format("YYYY-MM-DD") ===

                today.format("YYYY-MM-DD")

            ) {

                return true;

            }

        }

    }

    return false;

};

export const isWorkingDay = async () => {

    if (await isWeekend())
        return false;

    if (await isHoliday())
        return false;

    return true;

};

export default {

    isWeekend,

    isHoliday,

    isWorkingDay

};
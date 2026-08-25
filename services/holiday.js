import PlatformConfig from "../model/PlatformConfig.js";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";

dayjs.extend(utc);
dayjs.extend(timezone);

const TIMEZONE = "Africa/Nairobi";

const toNairobiDay = (date) =>
    dayjs.isDayjs(date)
        ? date.tz(TIMEZONE)
        : date
            ? dayjs(date).tz(TIMEZONE)
            : dayjs().tz(TIMEZONE);

const toHolidayPayload = (holiday, targetDate = null) => {
    if (!holiday) return null;

    const target = targetDate ? toNairobiDay(targetDate) : null;
    const sourceDate = toNairobiDay(holiday.date);
    const displayDate = holiday.recurring && target
        ? sourceDate.year(target.year())
        : sourceDate;

    return {
        _id: holiday._id?.toString?.() || holiday._id,
        name: holiday.name,
        date: displayDate.format("YYYY-MM-DD"),
        recurring: holiday.recurring === true,
        active: holiday.active !== false,
        description: holiday.description || "",
    };
};

const getActiveHolidayList = (cfg) =>
    (cfg?.holidays || [])
        .filter((holiday) => holiday?.active !== false && holiday?.date && holiday?.name);

const matchesHolidayDate = (holiday, targetDate) => {
    const holidayDate = toNairobiDay(holiday.date);

    if (holiday.recurring) {
        return (
            holidayDate.month() === targetDate.month() &&
            holidayDate.date() === targetDate.date()
        );
    }

    return holidayDate.format("YYYY-MM-DD") === targetDate.format("YYYY-MM-DD");
};

export const getConfiguredHolidays = async () => {
    const cfg = await PlatformConfig.getSingleton();
    return getActiveHolidayList(cfg).map((holiday) => toHolidayPayload(holiday));
};

export const getHolidayForDate = async (date = new Date(), config = null) => {
    const cfg = config || await PlatformConfig.getSingleton();
    const targetDate = toNairobiDay(date);
    const holiday = getActiveHolidayList(cfg).find((item) => matchesHolidayDate(item, targetDate));
    return toHolidayPayload(holiday, targetDate);
};

export const isWeekend = async (date) => {

    const cfg = await PlatformConfig.getSingleton();

    const targetDate = toNairobiDay(date);

    const workingDays =
        cfg.attendancePolicy?.workingDays || [1, 2, 3, 4, 5];

    return !workingDays.includes(targetDate.day());

};

export const isHoliday = async (date) => {

    return Boolean(await getHolidayForDate(date));

};

export const isWorkingDay = async (date) => {

    if (await isWeekend(date))
        return false;

    if (await isHoliday(date))
        return false;

    return true;

};

export const getWorkingDateKeysInRange = async (start, end) => {
    const cfg = await PlatformConfig.getSingleton();
    const workingDays = cfg.attendancePolicy?.workingDays || [1, 2, 3, 4, 5];
    const keys = [];
    let current = toNairobiDay(start).startOf("day");
    const last = toNairobiDay(end).startOf("day");

    while (current.isSame(last) || current.isBefore(last)) {
        const isConfiguredWorkingDay = workingDays.includes(current.day());
        const holiday = getActiveHolidayList(cfg).find((item) => matchesHolidayDate(item, current));

        if (isConfiguredWorkingDay && !holiday) {
            keys.push(current.format("YYYY-MM-DD"));
        }

        current = current.add(1, "day");
    }

    return keys;
};

export const countWorkingDaysInRange = async (start, end) => {
    const keys = await getWorkingDateKeysInRange(start, end);
    return Math.max(keys.length, 1);
};

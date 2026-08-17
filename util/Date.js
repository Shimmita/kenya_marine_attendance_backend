import dayjs from "dayjs";
import utc from "dayjs/plugin/utc.js";
import timezone from "dayjs/plugin/timezone.js";

dayjs.extend(utc);
dayjs.extend(timezone);

export const TIMEZONE = "Africa/Nairobi";


export const now = () => dayjs().tz(TIMEZONE);

export const today = () => now().toDate();

export const startOfToday = () =>
    now().startOf("day").toDate();

export const endOfToday = () =>
    now().endOf("day").toDate();

export const startOfYesterday = () =>
    now().subtract(1, "day").startOf("day").toDate();

export const endOfYesterday = () =>
    now().subtract(1, "day").endOf("day").toDate();

export const todayString = () =>
    now().format("YYYY-MM-DD");

export const currentTime = () =>
    now().format("HH:mm");

export const formatDate = (date) =>
    dayjs(date).tz(TIMEZONE).format("YYYY-MM-DD");

export const formatTime = (date) =>
    dayjs(date).tz(TIMEZONE).format("HH:mm");

export const isSameDay = (date1, date2) =>
    formatDate(date1) === formatDate(date2);

export const subtractMinutes = (time, minutes) => {

    return dayjs(`2000-01-01 ${time}`)
        .subtract(minutes, "minute")
        .format("HH:mm");

};

export const addMinutes = (time, minutes) => {

    return dayjs(`2000-01-01 ${time}`)
        .add(minutes, "minute")
        .format("HH:mm");

};




export default {
    now,
    today,
    startOfToday,
    endOfToday,
    startOfYesterday,
    endOfYesterday,
    currentTime,
    formatDate,
    formatTime,
    subtractMinutes,
    addMinutes,
    todayString,
    isSameDay,
};
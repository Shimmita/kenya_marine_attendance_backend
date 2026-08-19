/**
 * Kenya Public Holidays
 *
 * YYYY-MM-DD
 *
 * Source:
 * https://www.publicholidays.africa/kenya/
 *
 * NOTE:
 * Good Friday
 * Easter Monday
 * Idd-ul-Fitr
 * Idd-ul-Adha
 * may change slightly depending on the official government gazette.
 */

export const KENYA_PUBLIC_HOLIDAYS = {

    2026: [

        "2026-01-01", // New Year's Day

        "2026-04-03", // Good Friday

        "2026-04-06", // Easter Monday

        "2026-05-01", // Labour Day

        "2026-06-01", // Madaraka Day

        "2026-06-17", // Eid al-Adha (estimated)

        "2026-10-10", // Huduma Day / Mazingira Day (subject to gazette)

        "2026-10-20", // Mashujaa Day

        "2026-12-12", // Jamhuri Day

        "2026-12-25", // Christmas Day

        "2026-12-26", // Boxing Day

    ]

};

const TIMEZONE = "Africa/Nairobi";
const UTC_OFFSET_HOURS = 3;

const getDateParts = (date) => {
    const parts = new Intl.DateTimeFormat("en-CA", {
        timeZone: TIMEZONE,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        weekday: "short",
    }).formatToParts(new Date(date));

    return Object.fromEntries(parts.map((part) => [part.type, part.value]));
};

/**
 * Returns all public holidays
 * for a given year.
 */
export const getKenyaPublicHolidays = (year) => {

    return KENYA_PUBLIC_HOLIDAYS[year] || [];

};


/**
 * Check whether a date
 * is a public holiday.
 */

export const isPublicHoliday = (date) => {

    const parts = getDateParts(date);
    const year = Number(parts.year);

    const holidays = getKenyaPublicHolidays(year);

    const formatted = formatDateKey(date);

    return holidays.includes(formatted);

};



/**
 * Format date to YYYY-MM-DD
 */
export const formatDateKey = (date) => {

    const parts = getDateParts(date);

    return `${parts.year}-${parts.month}-${parts.day}`;

};

/**
 * Returns true if Saturday or Sunday
 */
export const isWeekend = (date) => {

    const day = getDateParts(date).weekday;

    return day === "Sat" || day === "Sun";

};

/**
 * Returns every working date
 * in a given month.
 */
export const getWorkingDates = (year, month) => {

    const workingDates = [];

    const totalDays = new Date(
        year,
        month,
        0
    ).getDate();

    for (let day = 1; day <= totalDays; day++) {

        const current = new Date(Date.UTC(
            year,
            month - 1,
            day,
            -UTC_OFFSET_HOURS,
            0,
            0,
            0
        ));

        if (isWeekend(current))
            continue;

        if (isPublicHoliday(current))
            continue;

        workingDates.push(
            formatDateKey(current)
        );

    }

    return workingDates;

};

/**
 * Total working days
 */
export const getWorkingDays = (year, month) => {

    return getWorkingDates(
        year,
        month
    ).length;

};

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

    const d = new Date(date);

    const year = d.getFullYear();

    const holidays = getKenyaPublicHolidays(year);

    const formatted =
        d.toISOString().split("T")[0];

    return holidays.includes(formatted);

};



/**
 * Format date to YYYY-MM-DD
 */
export const formatDateKey = (date) => {

    const d = new Date(date);

    return d.toISOString().split("T")[0];

};

/**
 * Returns true if Saturday or Sunday
 */
export const isWeekend = (date) => {

    const day = new Date(date).getDay();

    return day === 0 || day === 6;

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

        const current = new Date(
            year,
            month - 1,
            day
        );

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
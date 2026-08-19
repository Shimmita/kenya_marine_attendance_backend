// utils/dateHelpers.js
const TIMEZONE = "Africa/Nairobi";

const getDateParts = (date) => {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: TIMEZONE,
    weekday: "short",
  }).formatToParts(new Date(date));

  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
};

export function countWeekdays(start, end) {
  let count = 0;
  const cur = new Date(start);
  const last = new Date(end);
  while (cur <= last) {
    const day = getDateParts(cur).weekday;
    if (day !== "Sat" && day !== "Sun") count++;
    cur.setUTCDate(cur.getUTCDate() + 1);
  }
  return Math.max(count, 1); // avoid division by zero
}

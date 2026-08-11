// utils/dateHelpers.js
export function countWeekdays(start, end) {
  let count = 0;
  const cur = new Date(start);
  const last = new Date(end);
  // Set to midnight to avoid timezone issues
  cur.setHours(0, 0, 0, 0);
  last.setHours(0, 0, 0, 0);
  while (cur <= last) {
    const day = cur.getDay();
    // Monday=1 ... Friday=5, Sunday=0, Saturday=6
    if (day !== 0 && day !== 6) count++;
    cur.setDate(cur.getDate() + 1);
  }
  return Math.max(count, 1); // avoid division by zero
}
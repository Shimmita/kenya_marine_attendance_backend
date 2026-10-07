export const parseMobileEventAt = (eventAt, now = new Date()) => {
  if (typeof eventAt !== "string") return null;

  const parsedEventAt = new Date(eventAt);
  if (
    Number.isNaN(parsedEventAt.getTime()) ||
    parsedEventAt > now
  ) {
    return null;
  }

  return parsedEventAt;
};

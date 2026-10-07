export const MOBILE_EVENT_FUTURE_SKEW_MS = 5 * 60 * 1000;

export const parseMobileEventAt = (
  eventAt,
  now = new Date(),
  maximumFutureSkewMs = MOBILE_EVENT_FUTURE_SKEW_MS,
) => {
  if (typeof eventAt !== "string") return null;

  const parsedEventAt = new Date(eventAt);
  if (
    Number.isNaN(parsedEventAt.getTime()) ||
    parsedEventAt.getTime() - now.getTime() > maximumFutureSkewMs
  ) {
    return null;
  }

  return parsedEventAt;
};

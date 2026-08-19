import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import bcrypt from "bcrypt";
import { default as connectMongoStore } from "connect-mongodb-session";
import cors from "cors";
import crypto from "crypto";
import "dotenv/config";
import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import os from "os";
import sharp from "sharp";
import validator from "validator";
import registerClockInReminder from "./cron/clockInReminder.cron.js";
import registerClockOutReminder from "./cron/clockOutReminder.cron.js";
import startAttendanceScheduler, { getAttendanceScheduleTimes, refreshAttendanceScheduler } from "./cron/scheduler.js";
import uploadAvatar from "./middleware/UploadFile.js";
import AuditLog from "./model/AuditLog.js";
import Clocking from "./model/Clocking.js";
import DeviceLost from "./model/deviceLost.js";
import Devices from "./model/Devices.js";
import Feedback from "./model/Feedback.js";
import Leave from "./model/Leave.js";
import MessageAdmin from "./model/MessageAdmin.js";
import MessageUser from "./model/MessageUser.js";
import PasswordReset from "./model/PasswordReset.js";
import PlatformConfig, { getDefaultPlatformConfig } from "./model/PlatformConfig.js";
import Supervisor from "./model/Supervisor.js";
import User from "./model/User.js";
import Verification from "./model/VerifyReport.js";
import {
  isPublicHoliday,
  isWeekend
} from "./util/Holiday.js";
import { SendMessageNow } from "./util/SendSMS.js";
import { countWeekdays } from "./util/WorkingDay.js";
const allowedOrigins = [
  process.env.CROSS_ORIGIN_ALLOWED,
  process.env.CROSS_ORIGIN_ALLOWED_PRODUCTION
];

const mongoDBSession = connectMongoStore(session);
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const PORT = process.env.PORT || 5000;
const BASE_ROUTE = process.env.BASE_ROUTE;
const environment = process.env.ENVIRONMENT_MODE;
const PRIVILEGED_AUDIT_RANKS = ["admin", "hr", "superadmin"];
const REMINDER_TRIGGER_SECRET = process.env.REMINDER_TRIGGER_SECRET || (environment !== "production" ? "kmfri-reminder-trigger-dev" : "");
const MAX_USER_DEVICES = 2;
const WEBAUTHN_TIMEOUT_MS = 60000;
const CLIENT_AUDIT_ACTIONS = {
  "attendance.history_exported": {
    category: "attendance",
    description: "Attendance history exported",
  },
};
const generateResetCode = (length = 8) => {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%";
  const bytes = crypto.randomBytes(length);

  return Array.from(bytes)
    .map(b => chars[b % chars.length])
    .join("");
};

const maskPhone = (phone) => {
  if (!phone) return "";

  const digits = String(phone).replace(/\D/g, "");

  if (digits.length < 8) return phone;

  return (
    digits.substring(0, 8) +
    "****" +
    digits.substring(digits.length - 2)
  );
};

const ANALYTICS_ACCESSIBLE_RANKS = ["admin", "hr", "ceo", "superadmin", "supervisor"];
const ANALYTICS_FULL_ACCESS_RANKS = ["admin", "hr", "ceo", "superadmin"];
const EAT_TIMEZONE = "Africa/Nairobi";
const EAT_UTC_OFFSET_HOURS = 3;

const getRequestedDateRange = (query = {}) => {
  const { startDate, endDate } = normalizeAnalyticsQuery(query);
  const { start, end } = getSafeDateRange(startDate, endDate);
  return { startDate: start, endDate: end };
};

const isReminderTriggerAuthorized = (req) => {
  if (!REMINDER_TRIGGER_SECRET) {
    return false;
  }

  const provided = String(req.get("x-reminder-trigger-secret") || req.query.secret || "");
  if (!provided) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(Buffer.from(REMINDER_TRIGGER_SECRET), Buffer.from(provided));
  } catch {
    return false;
  }
};



// PARSE DATES
const normalizeDateInput = (value, fieldName = "date") => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  if (Array.isArray(value)) {
    const normalized = value.map((entry) => String(entry ?? "").trim()).filter(Boolean);
    if (!normalized.length) return null;

    const preferred = fieldName === "endDate" || fieldName === "dateTo"
      ? normalized[normalized.length - 1]
      : normalized[0];

    return normalizeDateInput(preferred, fieldName);
  }

  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error(`Invalid ${fieldName}`);
    }

    return value;
  }

  const valueString = String(value).trim();

  if (!valueString || valueString === "Invalid Date" || valueString === "NaN") {
    throw new Error(`Invalid ${fieldName}: ${valueString || "empty"}`);
  }

  const parts = valueString.includes(",")
    ? valueString.split(",").map((part) => part.trim()).filter(Boolean)
    : null;
  const candidateString = parts
    ? parts[fieldName === "endDate" || fieldName === "dateTo" ? parts.length - 1 : 0]
    : valueString;

  if (!candidateString) {
    throw new Error(`Invalid ${fieldName}: ${valueString}`);
  }

  return candidateString;
};

const normalizeQueryValue = (value, fallback = "", preferLast = false) => {
  if (value === undefined || value === null) return fallback;

  if (Array.isArray(value)) {
    const values = value
      .map((entry) => normalizeQueryValue(entry, "", preferLast))
      .filter(Boolean);

    if (!values.length) return fallback;
    return preferLast ? values[values.length - 1] : values[0];
  }

  if (typeof value === "object") {
    return fallback;
  }

  const normalized = String(value).trim();
  if (!normalized) return fallback;

  const lowered = normalized.toLowerCase();
  if (lowered === "undefined" || lowered === "null") return fallback;

  return normalized;
};

const normalizeAnalyticsQuery = (query = {}) => ({
  startDate: normalizeQueryValue(query.startDate, "", false),
  endDate: normalizeQueryValue(query.endDate, "", true),
  station: normalizeQueryValue(query.station, "all"),
  department: normalizeQueryValue(query.department, "all"),
  role: normalizeQueryValue(query.role, "all").toLowerCase(),
  rank: normalizeQueryValue(query.rank, "all").toLowerCase(),
  limit: normalizeQueryValue(query.limit, "250", true),
});

const isAllQueryValue = (value) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  return (
    !normalized ||
    normalized === "all" ||
    normalized === "all stations" ||
    normalized === "all departments" ||
    normalized === "undefined" ||
    normalized === "null"
  );
};

const getNairobiDateParts = (date = new Date()) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: EAT_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);

  return Object.fromEntries(parts.map((part) => [part.type, Number(part.value)]));
};

const getNairobiDateTimeParts = (date = new Date()) => {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: EAT_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(date);

  return Object.fromEntries(parts.map((part) => [part.type, part.value]));
};

const padDatePart = (value) => String(value).padStart(2, "0");

const getNairobiDateKey = (date = new Date()) => {
  const parts = getNairobiDateParts(date);
  return `${parts.year}-${padDatePart(parts.month)}-${padDatePart(parts.day)}`;
};

const getNairobiHourDecimal = (date = new Date()) => {
  const parts = getNairobiDateTimeParts(date);
  return Number(parts.hour || 0) + Number(parts.minute || 0) / 60;
};

const getNairobiWeekdayName = (date = new Date()) => {
  const parts = getNairobiDateTimeParts(date);
  return parts.weekday || "";
};

const getNairobiWeekdayIndex = (date = new Date()) => {
  const weekday = getNairobiWeekdayName(date);
  return { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[weekday] ?? 0;
};

const getNairobiMonthStart = (date = new Date()) => {
  const parts = getNairobiDateParts(date);
  return new Date(Date.UTC(parts.year, parts.month - 1, 1, -EAT_UTC_OFFSET_HOURS, 0, 0, 0));
};

const getNairobiDayBoundary = (year, month, day, boundary = "start") => {
  const testDate = new Date(Date.UTC(year, month - 1, day, 12, 0, 0, 0));
  const testParts = getNairobiDateParts(testDate);

  if (testParts.year !== year || testParts.month !== month || testParts.day !== day) {
    throw new Error("Invalid date");
  }

  if (boundary === "end") {
    return new Date(Date.UTC(year, month - 1, day, 23 - EAT_UTC_OFFSET_HOURS, 59, 59, 999));
  }

  return new Date(Date.UTC(year, month - 1, day, -EAT_UTC_OFFSET_HOURS, 0, 0, 0));
};

const parseDateRangeBoundary = (value, fieldName = "date", boundary = "start") => {
  const normalized = normalizeDateInput(value, fieldName);
  if (!normalized) return null;

  if (normalized instanceof Date) {
    const parts = getNairobiDateParts(normalized);
    return getNairobiDayBoundary(parts.year, parts.month, parts.day, boundary);
  }

  const isoDateMatch = String(normalized).match(/^(\d{4})-(\d{2})-(\d{2})(?:[T\s].*)?$/);
  if (isoDateMatch) {
    return getNairobiDayBoundary(
      Number(isoDateMatch[1]),
      Number(isoDateMatch[2]),
      Number(isoDateMatch[3]),
      boundary
    );
  }

  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`Invalid ${fieldName}. Expected YYYY-MM-DD.`);
  }

  const parts = getNairobiDateParts(parsed);
  return getNairobiDayBoundary(parts.year, parts.month, parts.day, boundary);
};

const parseSafeDate = (value, fieldName = "date") => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  if (Array.isArray(value)) {
    const normalized = value.map((entry) => String(entry ?? "").trim()).filter(Boolean);
    if (!normalized.length) {
      return null;
    }

    const preferred = fieldName === "endDate" ? normalized[normalized.length - 1] : normalized[0];
    return parseSafeDate(preferred, fieldName);
  }

  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error(`Invalid ${fieldName}`);
    }

    return new Date(value.getTime());
  }

  const valueString = String(value).trim();

  if (!valueString || valueString === "Invalid Date" || valueString === "NaN") {
    throw new Error(`Invalid ${fieldName}: ${valueString || "empty"}`);
  }

  const parts = valueString.includes(",")
    ? valueString.split(",").map((part) => part.trim()).filter(Boolean)
    : null;
  const candidateString = parts
    ? parts[fieldName === "endDate" ? parts.length - 1 : 0]
    : valueString;

  if (!candidateString) {
    throw new Error(`Invalid ${fieldName}: ${valueString}`);
  }

  // YYYY-MM-DD should be treated explicitly to avoid OS/browser parsing drift.
  const dateOnlyMatch = candidateString.match(/^\d{4}-\d{2}-\d{2}$/);

  if (dateOnlyMatch) {
    const year = Number(dateOnlyMatch[0].slice(0, 4));
    const month = Number(dateOnlyMatch[0].slice(5, 7));
    const day = Number(dateOnlyMatch[0].slice(8, 10));
    const date = new Date(year, month - 1, day);

    if (
      date.getFullYear() !== year ||
      date.getMonth() !== month - 1 ||
      date.getDate() !== day
    ) {
      throw new Error(`Invalid ${fieldName}: ${valueString}`);
    }

    return date;
  }

  const date = new Date(candidateString);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`Invalid ${fieldName}: ${valueString}`);
  }

  return date;
};


const getSafeDateRange = (startDate, endDate) => {
  const now = new Date();

  let start;

  if (startDate !== undefined && startDate !== null && startDate !== "") {
    start = parseDateRangeBoundary(startDate, "startDate", "start");
  } else {
    start = getNairobiMonthStart(now);
  }

  let end;

  if (endDate !== undefined && endDate !== null && endDate !== "") {
    end = parseDateRangeBoundary(endDate, "endDate", "end");
  } else {
    const parts = getNairobiDateParts(now);
    end = getNairobiDayBoundary(parts.year, parts.month, parts.day, "end");
  }

  if (!start || Number.isNaN(start.getTime())) {
    throw new Error("Invalid startDate");
  }

  if (!end || Number.isNaN(end.getTime())) {
    throw new Error("Invalid endDate");
  }

  if (start > end) {
    throw new Error("startDate cannot be after endDate");
  }

  return {
    start,
    end,
  };
};


// 



const getAnalyticsContext = async (req) => {
  if (!req.session?.isOnline) {
    const error = new Error("Unauthorized Access");
    error.statusCode = 401;
    throw error;
  }

  const user = await User.findById(req.session.userID).lean();
  if (!user) {
    const error = new Error("User not found");
    error.statusCode = 404;
    throw error;
  }

  const rank = String(user.rank || "").toLowerCase();
  const role = String(user.role || "").toLowerCase();

  if (!ANALYTICS_ACCESSIBLE_RANKS.includes(rank)) {
    const error = new Error("Unauthorized Access");
    error.statusCode = 403;
    throw error;
  }

  return {
    user,
    rank,
    role,
    isSupervisor: rank === "supervisor",
    canAccessAll: ANALYTICS_FULL_ACCESS_RANKS.includes(rank),
    department: user.department || "",
    station: user.station || "",
  };
};

const buildAnalyticsUserFilter = (context, query = {}) => {
  const filters = normalizeAnalyticsQuery(query);
  const userFilter = {};

  if (context.isSupervisor) {
    if (context.department) userFilter.department = context.department;
    if (context.station) userFilter.station = context.station;
  } else {
    if (!isAllQueryValue(filters.department)) {
      userFilter.department = filters.department;
    }
    if (!isAllQueryValue(filters.station)) {
      userFilter.station = filters.station;
    }
  }

  if (!isAllQueryValue(filters.role)) {
    userFilter.role = filters.role;
  }

  if (!isAllQueryValue(filters.rank)) {
    userFilter.rank = filters.rank;
  }

  return userFilter;
};

const getWorkingDateKeysInRange = (start, end) => {
  const keys = [];
  const current = new Date(start);

  while (current <= end) {
    if (!isWeekend(current) && !isPublicHoliday(current)) {
      keys.push(getNairobiDateKey(current));
    }

    current.setUTCDate(current.getUTCDate() + 1);
  }

  return keys;
};

const countApprovedLeaveDaysByGroup = (leaveRecords, emailGroupMap, workingDateKeys) => {
  const groupedLeaveDays = {};

  leaveRecords.forEach((leave) => {
    if (String(leave.status || "").toLowerCase() !== "approved") return;

    const email = String(leave.email || "").toLowerCase();
    const group = emailGroupMap[email] || "Unassigned";

    if (!groupedLeaveDays[group]) groupedLeaveDays[group] = new Set();

    const leaveStart = parseDateRangeBoundary(leave.startDate, "startDate", "start");
    const leaveEnd = parseDateRangeBoundary(leave.endDate, "endDate", "end");

    workingDateKeys.forEach((dateKey) => {
      const dayStart = parseDateRangeBoundary(dateKey, "date", "start");
      if (dayStart >= leaveStart && dayStart <= leaveEnd) {
        groupedLeaveDays[group].add(`${email}:${dateKey}`);
      }
    });
  });

  return Object.entries(groupedLeaveDays).reduce((acc, [group, values]) => {
    acc[group] = values.size;
    return acc;
  }, {});
};

const buildAnalyticsDataset = async (context, query = {}) => {
  const { startDate, endDate } = getRequestedDateRange(query);
  const userFilter = buildAnalyticsUserFilter(context, query);

  const users = await User.find(
    userFilter,
    "email name department station role rank employeeId isAccountActive isOnLeave hasClockedIn isToClockOut canClockOutside outsideClockingDetails"
  )
    .lean();

  const emails = users.map((entry) => entry.email).filter(Boolean);

  const [records, leaveRecords] = await Promise.all([
    Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: startDate, $lte: endDate },
    }).lean(),
    Leave.find({
      email: { $in: emails },
      startDate: { $lte: endDate },
      endDate: { $gte: startDate },
    }).lean(),
  ]);

  return {
    users,
    records,
    leaveRecords,
    startDate,
    endDate,
    userFilter,
    context,
  };
};

const buildAnalyticsView = async (view, context, query = {}) => {
  const { users, records, leaveRecords, startDate, endDate } = await buildAnalyticsDataset(context, query);
  const totalStaff = users.length;
  const today = new Date();
  const todayKey = getNairobiDateKey(today);

  const employeeByEmail = new Map(users.map((user) => [user.email, user]));

  const recordGroups = records.reduce((acc, record) => {
    const key = record.email || "unknown";
    if (!acc[key]) acc[key] = [];
    acc[key].push(record);
    return acc;
  }, {});

  const todayRecords = records.filter((record) => record?.clock_in && getNairobiDateKey(record.clock_in) === todayKey);
  const todayPresent = new Set(todayRecords.map((record) => record.email).filter(Boolean));

  const approvedLeaveToday = leaveRecords.filter((leave) => {
    const status = String(leave.status || "").toLowerCase();
    const todayValue = parseDateRangeBoundary(getNairobiDateKey(today), "startDate", "start");
    const start = parseDateRangeBoundary(leave.startDate, "startDate", "start");
    const end = parseDateRangeBoundary(leave.endDate, "endDate", "end");
    return status === "approved" && todayValue >= start && todayValue <= end;
  });

  const onLeaveCount = new Set(approvedLeaveToday.map((leave) => leave.email)).size;
  const presentCount = todayPresent.size;
  const absentCount = Math.max(totalStaff - presentCount - onLeaveCount, 0);

  const lateRecords = records.filter((record) => record?.isLate);
  const earlyDepartureRecords = records.filter((record) => record?.clock_out && record?.clock_in && (new Date(record.clock_out) - new Date(record.clock_in)) / (1000 * 60 * 60) < 8);
  const outsideClockingRecords = records.filter((record) => record?.clockedOutSide || record?.outsideLocation);
  const missingClockOut = records.filter((record) => !record.clock_out);
  const missingClockIn = records.filter((record) => !record.clock_in);

  const departmentBreakdown = users.reduce((acc, user) => {
    const key = user.department || "Unassigned";
    if (!acc[key]) {
      acc[key] = { department: key, totalStaff: 0, present: 0, late: 0, hours: 0, overtime: 0 };
    }
    acc[key].totalStaff += 1;
    const userRecords = recordGroups[user.email] || [];
    const uniqueDays = new Set(userRecords.map((entry) => getNairobiDateKey(entry.clock_in)).filter(Boolean));
    acc[key].present += uniqueDays.size;
    acc[key].late += userRecords.filter((entry) => entry.isLate).length;
    acc[key].hours += userRecords.reduce((sum, entry) => {
      if (!entry.clock_out) return sum;
      return sum + (new Date(entry.clock_out) - new Date(entry.clock_in)) / (1000 * 60 * 60);
    }, 0);
    acc[key].overtime += userRecords.reduce((sum, entry) => {
      if (!entry.clock_out) return sum;
      const hours = (new Date(entry.clock_out) - new Date(entry.clock_in)) / (1000 * 60 * 60);
      return sum + Math.max(hours - 8, 0);
    }, 0);
    return acc;
  }, {});

  const rows = Object.values(departmentBreakdown).map((entry) => ({
    ...entry,
    attendanceRate: entry.totalStaff ? Number((entry.present / Math.max(entry.totalStaff, 1)) * 100).toFixed(1) : 0,
    overtimeHours: Number(entry.overtime).toFixed(1),
  }));

  const deptPerformance = rows.sort((a, b) => b.attendanceRate - a.attendanceRate);

  const topPerformers = users
    .map((user) => {
      const userRecords = recordGroups[user.email] || [];
      const hours = userRecords.reduce((sum, entry) => {
        if (!entry.clock_out) return sum;
        return sum + (new Date(entry.clock_out) - new Date(entry.clock_in)) / (1000 * 60 * 60);
      }, 0);
      const lateCount = userRecords.filter((entry) => entry.isLate).length;
      return {
        name: user.name,
        email: user.email,
        department: user.department || "Unassigned",
        station: user.station || "Unassigned",
        hours: Number(hours).toFixed(1),
        lateCount,
        score: Number(hours - lateCount * 1.5).toFixed(1),
      };
    })
    .sort((a, b) => Number(b.score) - Number(a.score))
    .slice(0, 8);

  const frequentAbsentees = users
    .map((user) => {
      const userRecords = recordGroups[user.email] || [];
      const presentDays = new Set(userRecords.map((entry) => getNairobiDateKey(entry.clock_in)).filter(Boolean)).size;
      const expectedDays = Math.max(1, Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24)) + 1);
      const absentDays = Math.max(expectedDays - presentDays, 0);
      return { name: user.name, email: user.email, department: user.department || "Unassigned", absentDays };
    })
    .filter((entry) => entry.absentDays > 0)
    .sort((a, b) => b.absentDays - a.absentDays)
    .slice(0, 8);

  const summary = {
    scope: context.isSupervisor ? "supervisor" : "organization",
    department: context.department || null,
    station: context.station || null,
    dateRange: {
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
    },
    overview: {
      totalStaff,
      presentToday: presentCount,
      absentToday: absentCount,
      onLeave: onLeaveCount,
      attendanceRate: totalStaff ? Number((presentCount / totalStaff) * 100).toFixed(1) : 0,
      punctualityRate: totalStaff ? Number(((presentCount - lateRecords.length) / Math.max(presentCount, 1)) * 100).toFixed(1) : 0,
      averageWorkingHours: records.length ? Number(records.reduce((sum, entry) => sum + (entry.clock_out ? (new Date(entry.clock_out) - new Date(entry.clock_in)) / (1000 * 60 * 60) : 0), 0) / records.length).toFixed(1) : 0,
      totalOvertime: Number(records.reduce((sum, entry) => {
        if (!entry.clock_out) return sum;
        const hours = (new Date(entry.clock_out) - new Date(entry.clock_in)) / (1000 * 60 * 60);
        return sum + Math.max(hours - 8, 0);
      }, 0)).toFixed(1),
    },
    departmentPerformance: deptPerformance,
    workforceBehaviour: {
      lateArrivals: lateRecords.slice(0, 8).map((entry) => ({
        name: employeeByEmail.get(entry.email)?.name || entry.name || entry.email,
        email: entry.email,
        department: employeeByEmail.get(entry.email)?.department || entry.department || "Unassigned",
        station: employeeByEmail.get(entry.email)?.station || entry.station || "Unassigned",
        clockIn: entry.clock_in,
      })),
      earlyDepartures: earlyDepartureRecords.slice(0, 8).map((entry) => ({
        name: employeeByEmail.get(entry.email)?.name || entry.name || entry.email,
        email: entry.email,
        department: employeeByEmail.get(entry.email)?.department || entry.department || "Unassigned",
        station: employeeByEmail.get(entry.email)?.station || entry.station || "Unassigned",
        clockOut: entry.clock_out,
      })),
      absenteeism: frequentAbsentees,
      outsideClocking: outsideClockingRecords.slice(0, 8).map((entry) => ({
        name: employeeByEmail.get(entry.email)?.name || entry.name || entry.email,
        email: entry.email,
        department: employeeByEmail.get(entry.email)?.department || entry.department || "Unassigned",
        station: employeeByEmail.get(entry.email)?.station || entry.station || "Unassigned",
        clockIn: entry.clock_in,
      })),
    },
    compliance: {
      missingClockIns: missingClockIn.slice(0, 8),
      missingClockOuts: missingClockOut.slice(0, 8),
      missingBiometrics: users.filter((user) => !user.doneBiometric).slice(0, 8),
      openSessions: records.filter((record) => !record.clock_out).slice(0, 8),
      outsideClockingAuthorization: users.filter((user) => user.canClockOutside).slice(0, 8),
    },
    employeeRankings: {
      topPerformers,
      mostImproved: topPerformers.slice(0, 4),
      repeatLateEmployees: lateRecords.reduce((acc, record) => {
        const existing = acc.find((entry) => entry.email === record.email);
        if (existing) existing.count += 1; else acc.push({ email: record.email, name: employeeByEmail.get(record.email)?.name || record.name || record.email, count: 1 });
        return acc;
      }, []).sort((a, b) => b.count - a.count).slice(0, 8),
      frequentAbsentees,
    },
    reports: {
      availableFormats: ["PDF", "Excel", "CSV", "Print"],
      scopeLabel: context.isSupervisor ? `${context.department} / ${context.station}` : "Entire organization",
    },
  };

  if (view === "kpis") return summary.overview;
  if (view === "trends") return { data: summary.departmentPerformance };
  if (view === "departments") return summary.departmentPerformance;
  if (view === "stations") return { stations: summary.departmentPerformance };
  if (view === "late-arrivals") return summary.workforceBehaviour.lateArrivals;
  if (view === "early-departures") return summary.workforceBehaviour.earlyDepartures;
  if (view === "absenteeism") return summary.workforceBehaviour.absenteeism;
  if (view === "compliance") return summary.compliance;
  if (view === "outside-clocking") return summary.workforceBehaviour.outsideClocking;
  if (view === "workforce") return summary.workforceBehaviour;
  if (view === "productivity") return summary.employeeRankings.topPerformers;
  if (view === "executive") return summary;

  return summary;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const getRpID = () =>
  environment === "SANDBOX"
    // "localhost or domain names in production"
    ? process.env.DOMAIN_NAME_LOCAL
    : process.env.DOMAIN_NAME_PROD;

const getExpectedOrigin = () =>
  environment === "SANDBOX"
    ? process.env.ORIGIN_LOCAL || "http://localhost:5173"
    : process.env.ORIGIN_PROD;

const snapshotUser = (user) => ({
  userId: user?._id?.toString?.() || user?.userId || "",
  name: user?.name || "",
  email: user?.email || "",
  rank: user?.rank || "",
  role: user?.role || "",
  department: user?.department || "",
  station: user?.station || "",
});

const sanitizeUserResponse = (user) => {
  const safeUser = user?.toObject?.() || { ...user };
  delete safeUser.password;
  delete safeUser.authenticator;
  delete safeUser.authenticators;
  return safeUser;
};



const buildAuditRequestContext = (req) => ({
  ipAddress:
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    "",
  userAgent: req.get("user-agent") || "",
});

const createAuditLog = async ({
  req,
  category,
  action,
  description,
  actor,
  target = null,
  metadata = {},
  status = "success",
}) => {
  try {
    const context = buildAuditRequestContext(req);
    await AuditLog.create({
      category,
      action,
      description,
      status,
      actor: snapshotUser(actor),
      target: target ? snapshotUser(target) : null,
      metadata,
      ...context,
      occurredAt: new Date(),
    });
  } catch (error) {
    console.error("Audit log creation failed:", error);
  }
};

const formatLeaveDate = (date) => {
  if (!date) return "";
  return new Date(date).toLocaleDateString("en-KE", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "Africa/Nairobi",
  });
};

const sendLeaveSms = async (user, message) => {
  try {
    if (!user?.phone) {
      console.warn(`Leave SMS skipped (${user?.email || "unknown"}): missing phone`);
      return false;
    }

    await SendMessageNow(user, message);
    return true;
  } catch (error) {
    console.error(`Leave SMS failed (${user?.email || "unknown"}):`, error?.message || error);
    return false;
  }
};

const buildLeaveSmsMessage = (user, leave, event) => {
  const firstName = user?.name?.split(" ")?.[0] || "User";
  const leaveType = leave?.type || "leave";
  const start = formatLeaveDate(leave?.startDate);
  const end = formatLeaveDate(leave?.endDate);
  const range = start && end ? ` from ${start} to ${end}` : "";

  if (event === "submitted") {
    return `Dear ${firstName}, your ${leaveType} request${range} has been submitted successfully and is awaiting review.`;
  }

  if (event === "approved") {
    return `Dear ${firstName}, your ${leaveType} request${range} has been approved.`;
  }

  if (event === "rejected") {
    return `Dear ${firstName}, your ${leaveType} request${range} has been rejected. Please contact your supervisor or HR for clarification.`;
  }

  if (event === "cancelled") {
    return `Dear ${firstName}, your ${leaveType} request${range} has been cancelled successfully.`;
  }

  return `Dear ${firstName}, your leave request has been updated.`;
};


const getUserAuthenticators = (user) => {
  const authenticators = Array.isArray(user?.authenticators) ? [...user.authenticators] : [];

  if (user?.authenticator?.credentialID) {
    const hasLegacyCredential = authenticators.some(
      (authenticator) => authenticator.credentialID === user.authenticator.credentialID
    );

    if (!hasLegacyCredential) {
      authenticators.push(user.authenticator);
    }
  }

  return authenticators;
};

const getActiveUserDevices = async (email) =>
  Devices.find({ user_email: email, device_lost: { $ne: true } }).sort({ createdAt: 1 });

const getAuthenticatorDeviceFingerprint = (authenticator) =>
  authenticator?.deviceFingerprint || authenticator?.device_fingerprint || "";

const getAuthenticatorCredentialID = (authenticator) =>
  authenticator?.credentialID || authenticator?.credentialId || authenticator?.id || "";

const getDeviceBiometricState = async (user, deviceFingerprint = "") => {
  const activeDevices = await getActiveUserDevices(user.email);
  const activeDeviceFingerprints = activeDevices.map((device) => device.device_fingerprint);
  const authenticators = getUserAuthenticators(user).filter((authenticator) => {
    const authDeviceFingerprint = getAuthenticatorDeviceFingerprint(authenticator);
    return !authDeviceFingerprint || activeDeviceFingerprints.includes(authDeviceFingerprint);
  });

  const currentDevice = deviceFingerprint
    ? activeDevices.find((device) => device.device_fingerprint === deviceFingerprint)
    : null;

  const currentDeviceAuthenticators = deviceFingerprint
    ? authenticators.filter((authenticator) => getAuthenticatorDeviceFingerprint(authenticator) === deviceFingerprint)
    : [];

  return {
    activeDevices,
    authenticators,
    currentDevice,
    currentDeviceAuthenticators,
    accountRegistered: authenticators.length > 0 && activeDevices.length > 0,
    currentDeviceRegistered: Boolean(currentDevice && currentDeviceAuthenticators.length > 0),
  };
};

const syncUserDeviceFlags = async (user) => {
  const activeDevices = await getActiveUserDevices(user.email);
  user.hasDevices = activeDevices.length > 1;
  user.doneBiometric = getUserAuthenticators(user).length > 0 && activeDevices.length > 0;
  user.deviceLost = activeDevices.length === 0 && user.deviceLost;
  await user.save();
  return activeDevices;
};

const ensureSinglePrimaryDevice = async (email) => {
  const activeDevices = await getActiveUserDevices(email);
  if (!activeDevices.length) return [];

  const primaryDevice =
    activeDevices.find((device) => device.device_primary) || activeDevices[0];

  await Devices.updateMany(
    { user_email: email },
    { $set: { device_primary: false } }
  );
  await Devices.updateOne(
    { _id: primaryDevice._id },
    { $set: { device_primary: true, device_lost: false } }
  );

  return getActiveUserDevices(email);
};

const getCurrentTime = () => new Date();

const formatEATDateTime = (date = new Date()) => {
  const formattedDate = date.toLocaleDateString("en-KE", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: EAT_TIMEZONE,
  });

  const formattedTime = date.toLocaleTimeString("en-KE", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: EAT_TIMEZONE,
  });

  return {
    formattedDate,
    formattedTime,
  };
};





// ─────────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────────

mongoose
  .connect(

    environment === "SANDBOX"

      ? process.env.MONGO_CONNECTION_URI

      : process.env.MONGO_CONNECTION_URI_CLOUD

  )

  .then(async () => {

    console.log(
      `Connected to MongoDB (${environment === "SANDBOX" ? "LOCAL" : "CLOUD"})`
    );

    /*
    |--------------------------------------------------------------------------
    | Start Attendance Scheduler
    |--------------------------------------------------------------------------
    */

    try {

      await startAttendanceScheduler();

    } catch (err) {

      console.error("Attendance scheduler failed to start:", err);

    }

    /*
    |--------------------------------------------------------------------------
    | Start Express Server
    |--------------------------------------------------------------------------
    */

    app.listen(PORT, () => {

      console.log(
        `Server running on http://localhost:${PORT}`
      );

    });

  })

  .catch((err) => {

    console.error(
      "Database connection failed:",
      err
    );

  });

// ─── Session ──────────────────────────────────────────────────────────────────

const store = new mongoDBSession({
  uri:
    environment === "SANDBOX"
      ? process.env.MONGO_CONNECTION_URI
      : process.env.MONGO_CONNECTION_URI_CLOUD,
  collection: process.env.SESSION_STORE_NAME,
});

app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    rolling: true,
    saveUninitialized: false,
    name: process.env.SESSION_NAME,
    store,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      secure: environment !== "SANDBOX",
      sameSite: environment === "SANDBOX" ? "lax" : "none",
    },
  })
);

// ─── Auth check ───────────────────────────────────────────────────────────────

app.use(BASE_ROUTE, clearExpiredTemporaryAccountForSession);

app.post(`${BASE_ROUTE}/notifications/trigger-reminders`, async (req, res) => {
  if (!isReminderTriggerAuthorized(req)) {
    return res.status(401).json({ success: false, message: "Unauthorized reminder trigger" });
  }

  try {
    const results = await Promise.allSettled([
      registerClockInReminder(),
      registerClockOutReminder(),
    ]);

    const failures = results.filter((result) => result.status === "rejected");

    return res.json({
      success: true,
      triggered: true,
      results: results.map((result, index) => ({
        job: index === 0 ? "clock_in_reminder" : "clock_out_reminder",
        status: result.status,
        reason: result.status === "rejected" ? result.reason?.message || "Unknown error" : null,
      })),
      failures: failures.length,
    });
  } catch (error) {
    console.error("Reminder trigger failed:", error);
    return res.status(500).json({ success: false, message: "Reminder trigger failed" });
  }
});

app.use(`${BASE_ROUTE}/valid`, async (req, res) => {
  if (req.session?.isOnline) {
    res.status(200).json({ valid: true });
  } else {
    res.status(200).json({ valid: false });
  }
});



// ─── Sign Up ──────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signup`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const currentUser = await User.findById(req.session.userID);
    if (!["hr", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Access denied, only HR or Superadmin personnel can create accounts." });
    }

    const data = req.body.formData;
    const { email, role } = data;
    // password randomly generated for new users, they can reset it later
    const randomPassword = generateResetCode();
    data.password = randomPassword;

    const { password } = data;

    if (!validator.isEmail(email)) throw new Error("Provided email is malformed!");
    if (!data.phone?.trim()) throw new Error("Phone number is required.");

    if (['intern', 'attachee'].includes(role)) {
      const normalizedPhone = normalizeKenyaPhone(data.phone, true);
      if (!normalizedPhone) {
        throw new Error("Intern/Attaché phone must be in Kenyan mobile format with 254 followed by 9 digits.");
      }
      data.phone = normalizedPhone;
    } else {
      data.phone = data.phone.trim();
    }

    if (['intern', 'attachee'].includes(role)) {
      if (!data.startDate) throw new Error("Start date is required for interns and attaches.");
      if (!data.endDate) throw new Error("End date is required for interns and attaches.");

      let startDate;
      let endDate;

      try {
        startDate = parseSafeDate(data.startDate, "startDate");
        endDate = parseSafeDate(data.endDate, "endDate");
      } catch (dateError) {
        throw new Error(dateError.message);
      }

      if (startDate > endDate) {
        throw new Error("End date cannot be before start date.");
      }
    }


    const normalizedPhone = normalizeKenyaPhone(data.phone, true);

    if (!normalizedPhone) {
      throw new Error(
        "Phone number must begin with 254 followed by 9 digits."
      );
    }

    const duplicate = await User.findOne({
      $or: [
        { email },
        { phone: normalizedPhone },

      ]
    });

    if (duplicate) {
      if (duplicate.email === email)
        throw new Error("User already registered!");

      if (duplicate.phone === normalizedPhone)
        throw new Error("Phone number already exists.");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const createdUser = await User.create({ ...data, password: hashedPassword });
    // Create audit log for single user registration by HR
    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user.create",
      description: `HR created a new user account for ${createdUser.name}`,
      actor: currentUser,
      target: createdUser,
      metadata: {
        registeredUser: {
          name: createdUser.name,
          department: createdUser.department || "",
          station: createdUser.station || "",
          email: createdUser.email || "",
          employeeId: createdUser.employeeId || "",
        },
      },
    });


    // send sms to the intern or attache
    await SendMessageNow(createdUser, "", password)

    // return the success response
    return res.status(200).json({ message: "Account created successfully", user: createdUser });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(400).json({ message: error.message });
  }
});


// single staff registration
app.post(`${BASE_ROUTE}/auth/staffsignup`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);

    if (!currentUser) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (!["hr", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({
        message: "Only HR or Superadmin can register staff."
      });
    }

    const {
      name,
      email,
      phone,
      role,
      department,
      station,
      employeeId,
    } = req.body.formData;

    if (!name?.trim())
      throw new Error("Full name is required.");

    if (!employeeId?.trim())
      throw new Error("Employee Staff Number is required.");

    if (!department?.trim())
      throw new Error("Department is required.");

    if (!station?.trim())
      throw new Error("Station is required.");

    if (!validator.isEmail(email))
      throw new Error("Invalid email address.");

    const normalizedPhone = normalizeKenyaPhone(phone, true);

    if (!normalizedPhone) {
      throw new Error(
        "Phone number must begin with 254 followed by 9 digits."
      );
    }

    const duplicate = await User.findOne({
      $or: [
        { email },
        { phone: normalizedPhone },
        { employeeId },
      ]
    });

    if (duplicate) {
      if (duplicate.email === email)
        throw new Error("Email already exists.");

      if (duplicate.phone === normalizedPhone)
        throw new Error("Phone number already exists.");

      if (duplicate.employeeId === employeeId)
        throw new Error("Employee Staff Number already exists.");
    }


    // randomly generate a password for the new staff member
    const randomPassword = generateResetCode();

    const hashedPassword = await bcrypt.hash(randomPassword, 10);

    const createdUser = await User.create({
      name,
      email,
      phone: normalizedPhone,
      role: role || "employee",
      department,
      station,
      employeeId,
      password: hashedPassword
    });

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user.create",
      description: `Registered ${createdUser.name}`,
      actor: currentUser,
      target: createdUser,
      metadata: {
        registeredUser: {
          name: createdUser.name,
          department: createdUser.department,
          station: createdUser.station,
          email: createdUser.email,
          employeeId: createdUser.employeeId,
        }
      }
    });


    // send message to the reg staff
    await SendMessageNow(createdUser, "", randomPassword);

    // return response
    return res.status(201).json({
      message: "Staff registered successfully.",
      user: createdUser
    });

  } catch (error) {
    console.error(error);

    return res.status(400).json({
      message: error.message
    });
  }
});



// ─── Batch User Registration (HR Only) ────────────────────────────────────────

app.post(`${BASE_ROUTE}/admin/batch-register`, async (req, res) => {
  try {
    //  1. Check if user is authenticated
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized. Please log in first." });
    }

    //  2. Verify user has HR rank
    const currentUser = await User.findById(req.session.userID);
    if (!currentUser || !["hr", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Only HR or Superadmin personnel can perform this operation." });
    }

    //  3. Validate request body
    const { users } = req.body;
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(400).json({ message: "Please provide at least one record of data" });
    }


    // 5. Validate and prepare user data
    const validatedUsers = [];
    const errors = [];

    // O(1) duplicate detection
    const emailSet = new Set();
    const employeeIdSet = new Set();
    const phoneSet = new Set();

    const emails = [];
    const employeeIds = [];
    const phones = [];

    // --------------------
    // First Pass - Validate & Detect Batch Duplicates
    // --------------------
    for (let i = 0; i < users.length; i++) {
      const row = i + 1;
      const user = users[i];

      try {
        const email = user.email?.trim().toLowerCase();
        const name = user.name?.trim();
        const employeeId = user.employeeId?.toString().trim();
        const role = (user.role || "employee").toLowerCase().trim();
        const phone = normalizeKenyaPhone(user.phone?.trim(), true);

        if (!email || !validator.isEmail(email)) {
          errors.push(`Row ${row}: Invalid or missing email.`);
          continue;
        }

        if (!name) {
          errors.push(`Row ${row}: Name is required.`);
          continue;
        }

        if (!phone) {
          errors.push(`Row ${row}: Invalid phone number.`);
          continue;
        }

        if (!employeeId) {
          errors.push(`Row ${row}: Employee ID is required.`);
          continue;
        }

        if (!["employee", "staff"].includes(role)) {
          errors.push(`Row ${row}: Only employee or staff roles are allowed.`);
          continue;
        }

        // Duplicate checks inside uploaded file
        if (emailSet.has(email)) {
          errors.push(`Row ${row}: Duplicate email in uploaded file.`);
          continue;
        }

        if (employeeIdSet.has(employeeId)) {
          errors.push(`Row ${row}: Duplicate Employee ID in uploaded file.`);
          continue;
        }


        if (phoneSet.has(phone)) {
          errors.push(`Row ${row}: Duplicate phone number in uploaded file.`);
          continue;
        }

        emailSet.add(email);
        employeeIdSet.add(employeeId);
        phoneSet.add(phone);

        emails.push(email);
        employeeIds.push(employeeId);
        phones.push(phone);

        validatedUsers.push({
          row,
          employeeId,
          name,
          email,
          phone,
          role: "employee",
          station: user.station?.trim() || "",
          department: user.department?.trim() || "",
        });

      } catch (err) {
        errors.push(`Row ${row}: ${err.message}`);
      }
    }

    // Stop immediately if upload itself has errors
    if (errors.length) {
      return res.status(400).json({
        message: `Validation failed. ${errors.length} error(s) found.`,
        errors,
        totalErrors: errors.length
      });
    }

    // --------------------
    // Single Database Query
    // --------------------
    const existingUsers = await User.find({
      $or: [
        { email: { $in: emails } },
        { employeeId: { $in: employeeIds } },
        { phone: { $in: phones } }
      ]
    }).lean();

    const existingEmails = new Set(existingUsers.map(u => u.email));
    const existingEmployeeIds = new Set(existingUsers.map(u => u.employeeId));
    const existingPhones = new Set(existingUsers.map(u => u.phone));

    // --------------------
    // Database Duplicate Check
    // --------------------
    const finalUsers = [];

    for (const user of validatedUsers) {

      if (existingEmails.has(user.email)) {
        errors.push(`Row ${user.row}: Email already registered.`);
        continue;
      }

      if (existingEmployeeIds.has(user.employeeId)) {
        errors.push(`Row ${user.row}: Employee Staff Number already exists.`);
        continue;
      }


      if (existingPhones.has(user.phone)) {
        errors.push(`Row ${user.row}: Phone number already exists.`);
        continue;
      }

      finalUsers.push(user);
    }

    // Stop if database duplicates exist
    if (errors.length) {
      return res.status(400).json({
        message: `Validation failed. ${errors.length} error(s) found.`,
        errors,
        totalErrors: errors.length
      });
    }

    // --------------------
    // Hash Passwords Concurrently
    // --------------------
    // 6. Generate unique random passwords and hash them
    const usersWithPasswords = finalUsers.map(user => ({
      user,
      plainPassword: generateResetCode()
    }));

    await Promise.all(
      usersWithPasswords.map(async ({ user, plainPassword }) => {
        user.password = await bcrypt.hash(plainPassword, 10);
        user.isPasswordReset = false;
      })
    );

    // 7. Batch insert all validated users
    const createdUsers = await User.insertMany(finalUsers, {
      ordered: false
    });

    // 8. Send each user their actual generated password
    await Promise.allSettled(
      createdUsers.map((user, index) =>
        SendMessageNow(
          user,
          "",
          usersWithPasswords[index].plainPassword
        )
      )
    );

    // Build registered users summary for audit metadata
    const registeredSummary = createdUsers.map((user) => ({
      id: user._id?.toString?.() || null,
      name: user.name || "",
      email: user.email || "",
      employeeId: user.employeeId || "",
      department: user.department || "",
      station: user.station || "",
    }));

    // Create audit log for batch registration
    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.batch_register",
      description: `HR batch-registered ${createdUsers.length} users`,
      actor: currentUser,
      metadata: { registeredUsers: registeredSummary },
    });

    return res.status(200).json({
      message: `Successfully registered ${createdUsers.length} users.`,
      count: createdUsers.length,
      registeredUsers: createdUsers.map(u => ({
        id: u._id,
        email: u.email,
        name: u.name,
        employeeId: u.employeeId
      }))
    });

  } catch (error) {
    // Handle MongoDB duplicate key errors
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return res.status(400).json({
        message: `Duplicate value for ${field}. Batch registration partially failed.`
      });
    }

    return res.status(400).json({ message: error.message || "Batch registration failed." });
  }
});

// ─── Sign In ──────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signin`, async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!validator.isEmail(email)) throw new Error("Provided email is malformed!");
    if (!password || password.length < 6) throw new Error("Password must be at least 6 characters!");

    const user = await User.findOne({ email });
    if (!user) throw new Error("Access not granted contact HR!");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error("Invalid credentials!");

    if (!user.email_verified) throw new Error("Email not verified. Contact admin.");

    // init user session
    req.session.isOnline = true;
    req.session.userID = user._id.toString();

    await createAuditLog({
      req,
      category: "authentication",
      action: "auth.signin",
      description: "User signed in",
      actor: user,
      metadata: { signInMethod: "password" },
    });

    const refreshedUser = await finalizeStaleClocking(user);

    return res.status(200).json(sanitizeUserResponse(refreshedUser));
  } catch (error) {
    console.error("Signin error:", error);
    return res.status(400).json({ message: error.message });
  }
});


// ─── Staff Authentication Helper ──────────────────────────────────────────────

const authenticateStaffCredentials = async (userId, password) => {
  try {
    const user = await User.findOne({
      employeeId: userId.trim(),
    }).select("+password");

    if (!user) {
      throw new Error("Invalid credentials!");
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      throw new Error("Invalid credentials!");
    }

    return {
      success: true,
      method: "LOCAL",
    };

  } catch (error) {
    console.error(
      "Local staff authentication failed:",
      error.message
    );

    throw new Error("Invalid credentials!");
  }
};


// ─── Sign In (Staff) ──────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signin-staff`, async (req, res) => {
  const { userId, password } = req.body;

  try {

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Validate input
    // ─────────────────────────────────────────────────────────────────────────

    if (!userId || !userId.trim()) {
      throw new Error("User ID is required");
    }

    if (!password || !password.trim()) {
      throw new Error("Password is required");
    }


    // ─────────────────────────────────────────────────────────────────────────
    // 2. Authenticate staff
    // ─────────────────────────────────────────────────────────────────────────

    const isValidStaff = await authenticateStaffCredentials(
      userId,
      password
    );

    if (!isValidStaff.success) {
      throw new Error("Invalid credentials!");
    }


    // ─────────────────────────────────────────────────────────────────────────
    // 3. Find user in DB
    // ─────────────────────────────────────────────────────────────────────────

    const user = await User.findOne({
      employeeId: userId.trim(),
    });

    if (!user) {
      throw new Error(
        "You don't have access contact HR !"
      );
    }


    // ─────────────────────────────────────────────────────────────────────────
    // 4. Create session for currently logged-in user
    // ─────────────────────────────────────────────────────────────────────────

    req.session.isOnline = true;
    req.session.userID = user._id.toString();


    // ─────────────────────────────────────────────────────────────────────────
    // 5. Save session
    // ─────────────────────────────────────────────────────────────────────────

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          return reject(err);
        }

        resolve();
      });
    });


    // ─────────────────────────────────────────────────────────────────────────
    // 6. Audit login
    // ─────────────────────────────────────────────────────────────────────────

    await createAuditLog({
      req,
      category: "authentication",
      action: "auth.signin",
      description: "User signed in",
      actor: user,
      metadata: {
        signInMethod: isValidStaff.method,
      },
    });


    // ─────────────────────────────────────────────────────────────────────────
    // 7. Return sanitized user
    // ─────────────────────────────────────────────────────────────────────────

    const refreshedUser = await finalizeStaleClocking(user);

    return res
      .status(200)
      .json(sanitizeUserResponse(refreshedUser));

  } catch (error) {

    console.error(
      "Staff signin error:",
      error
    );

    let message =
      error.message || "Authentication failed";

    let statusCode = 400;


    // ─────────────────────────────────────────────────────────────────────────
    // LDAP / Active Directory errors
    //
    // These are kept because they will be used automatically
    // once the LDAP section is enabled.
    // ─────────────────────────────────────────────────────────────────────────

    if (
      error.code === "ETIMEDOUT" ||
      message?.includes("ETIMEDOUT") ||
      message?.includes("timeout")
    ) {

      message =
        "Active Directory server is currently unavailable. Please try again later or contact your administrator.";

      statusCode = 503;

    } else if (
      error.code === "ECONNREFUSED" ||
      message?.includes("ECONNREFUSED")
    ) {

      message =
        "Active Directory server is unreachable. Please try again later or contact your administrator.";

      statusCode = 503;

    } else if (
      error.code === "ENOTFOUND" ||
      message?.includes("ENOTFOUND")
    ) {

      message =
        "Active Directory server address not found. Please contact your administrator.";

      statusCode = 503;

    } else if (
      message?.includes("Invalid credentials") ||
      message?.includes("User not found")
    ) {

      message =
        "Invalid credentials. Please check your Staff Number and Password.";

      statusCode = 401;

    } else if (
      message?.includes("don't have access")
    ) {

      statusCode = 403;
    }


    return res
      .status(statusCode)
      .json({
        message,
      });
  }
});




// PASSWORD RESET REQUEST
app.post(`${BASE_ROUTE}/auth/request-password-reset`, async (req, res) => {
  try {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    if (!email)
      throw new Error("Email is required");

    if (!validator.isEmail(email))
      throw new Error("Invalid email address.");

    const user = await User.findOne({ email });

    if (!user) {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.request_rejected",
        description: "Password reset requested for unknown email.",
        actor: {
          email,
          name: email,
        },
        metadata: {
          reason: "user_not_found",
        },
        status: "failed",
      });

      throw new Error("No account was found for that email address.");
    }
    // if user profile ispassword reset flag is true, then they cannot request another password reset
    if (user.isPasswordReset) {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.request_rejected",
        description: "Password reset requested while a temporary password is still active.",
        actor: user,
        target: user,
        metadata: {
          reason: "temporary_password_active",
        },
        status: "failed",
      });

      return res.status(403).json({
        message:
          "A temporary password has already been issued for this account. Please check your messages or contact ICT support.",
      });
    }


    // Generate temporary password
    const temporaryPassword = generateResetCode();

    // Save new password
    user.password = await bcrypt.hash(temporaryPassword, 10);

    // Force change on login
    user.isPasswordReset = true;

    await user.save();

    // SMS
    const sms = `Dear ${user.name}, Your temporary Password is ${temporaryPassword} use this password to sign in.You are required to change your password immediately after login.`;

    await SendMessageNow(user, sms);

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.temp_password_generated",
      description:
        "Temporary password generated by the system and sent via SMS.",
      actor: user,
      target: user,
      metadata: {
        email,
        phone: maskPhone(user.phone),
      },
      status: "success",
    });

    const maskedphone = maskPhone(user.phone);

    res.status(200).json({
      message: `A temporary password has been sent to your registered phone number (${maskedphone}). Please check your messages.`,
    });

  } catch (error) {
    console.error("Password reset error:", error);

    return res.status(400).json({
      message: error.message || "Password reset failed.",
    });
  }
});





// UPDATE USER PROFILE
app.put(
  `${BASE_ROUTE}/user/update-profile`,
  uploadAvatar.single("avatar"),
  async (req, res) => {
    try {

      if (!req.session?.userID) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const { phone, newPassword } = req.body;
      const userId = req.session.userID;

      const updateData = {};

      /* update phone */
      if (phone) {
        updateData.phone = phone.trim();
      }

      /* update password */
      if (newPassword) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        updateData.password = hashedPassword;
      }

      /* update avatar */
      if (req.file) {

        const compressed = await sharp(req.file.buffer)
          .resize(400, 400, { fit: "cover" })
          .jpeg({ quality: 70 })
          .toBuffer();

        const base64Image =
          `data:image/jpeg;base64,${compressed.toString("base64")}`;

        updateData.avatar = base64Image;
      }

      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ message: "No changes provided" });
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, select: "-password" }
      );

      if (updateData.phone) {
        await createAuditLog({
          req,
          category: "profile",
          action: "profile.phone_updated",
          description: "User updated phone number",
          actor: updatedUser,
          metadata: { changedFields: ["phone"] },
        });
      }

      if (updateData.password) {
        await createAuditLog({
          req,
          category: "profile",
          action: "profile.password_updated",
          description: "User updated password",
          actor: updatedUser,
          metadata: { changedFields: ["password"] },
        });
      }

      if (updateData.avatar) {
        await createAuditLog({
          req,
          category: "profile",
          action: "profile.avatar_updated",
          description: "User updated profile avatar",
          actor: updatedUser,
          metadata: { changedFields: ["avatar"] },
        });
      }

      res.status(200).json({
        user: updatedUser,
      });

    } catch {
      res.status(500).json({ message: "Failed to update profile" });
    }
  }
);



// ─── Biometrics ───────────────────────────────────────────────────────────────

app.get(`${BASE_ROUTE}/biometric/status`, async (req, res) => {
  try {
    if (!req.session.isOnline) {
      return res.status(401).json({ message: "session expired, logout and login again to proceed!" });
    }

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const deviceFingerprint = String(req.query.device_fingerprint || "");
    const state = await getDeviceBiometricState(user, deviceFingerprint);

    const syncedDoneBiometric = Boolean(state.accountRegistered);
    const syncedHasDevices = state.activeDevices.length > 1;
    if (user.doneBiometric !== syncedDoneBiometric || user.hasDevices !== syncedHasDevices) {
      user.doneBiometric = syncedDoneBiometric;
      user.hasDevices = syncedHasDevices;
      await user.save();
    }

    res.json({
      registered: syncedDoneBiometric,
      accountRegistered: syncedDoneBiometric,
      currentDeviceRegistered: state.currentDeviceRegistered,
      activeDeviceCount: state.activeDevices.length,
      maxDevices: MAX_USER_DEVICES,
      canEnrollDevice: state.currentDeviceRegistered || state.activeDevices.length < MAX_USER_DEVICES,
    });
  } catch (err) {
    console.error("Biometric status error:", err);
    res.status(400).json({ message: err.message });
  }
});

/**
 * 1. Generate Registration Challenge
 */
app.get(`${BASE_ROUTE}/biometric/register/challenge`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "session expired, logout and login again to proceed!" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const deviceFingerprint = String(req.query.device_fingerprint || "");
    const state = await getDeviceBiometricState(user, deviceFingerprint);

    if (deviceFingerprint) {
      const existingOtherDevice = await Devices.findOne({
        device_fingerprint: deviceFingerprint,
        user_email: { $ne: user.email },
      });

      if (existingOtherDevice) {
        throw new Error("This device is already enrolled by another account.");
      }
    }

    if (state.currentDeviceRegistered) {
      return res.json({
        registered: true,
        alreadyRegistered: true,
        message: "This device biometric is already registered. You can clock in or out now.",
      });
    }

    if (!state.currentDevice && state.activeDevices.length >= MAX_USER_DEVICES) {
      throw new Error(`You can only enroll up to ${MAX_USER_DEVICES} devices. Report a lost device or contact admin to clear one.`);
    }

    const existingAuthenticators = state.authenticators;

    const options = await generateRegistrationOptions({
      rpName: "KMFRI Attendance",
      rpID: getRpID(),

      userID: Uint8Array.from(Buffer.from(user._id.toString())),
      userName: user.email,

      attestationType: "none",

      supportedAlgorithmIDs: [-7, -257],

      authenticatorSelection: {
        authenticatorAttachment: "platform", // force device authenticator
        residentKey: "preferred", // preserve laptop compatibility
        userVerification: "required",
      },

      // improves Android/Pixel reliability
      timeout: WEBAUTHN_TIMEOUT_MS,

      // prevents duplicate registrations
      excludeCredentials: existingAuthenticators.map((authenticator) => ({
        id: getAuthenticatorCredentialID(authenticator),
        type: "public-key",
        transports: ["internal"],
      })).filter((credential) => credential.id),
    });


    req.session.registrationChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    console.error("Register challenge error:", err);
    res.status(400).json({ message: err.message });
  }
});

/**
 * 2. Verify Registration & Save Credential
 *
 * KEY FIX — In @simplewebauthn/server v10+, credential.id is ALREADY a base64url
 * string. Wrapping it in Buffer.from() corrupts it (treats the b64url chars as
 * UTF-8 bytes, then re-encodes — producing a completely different string).
 *
 *   ❌ WRONG:   Buffer.from(credential.id).toString("base64url")
 *   ✅ CORRECT: credential.id  (store directly — it's already base64url)
 *
 * credential.publicKey IS raw bytes (Uint8Array), so Buffer conversion is correct there.
 */
app.post(`${BASE_ROUTE}/biometric/register/verify`, async (req, res) => {
  try {
    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const expectedChallenge = req.session.registrationChallenge;
    if (!expectedChallenge) throw new Error("No registration challenge found. Please restart.");

    const { credential: credentialResponse, device = {} } = req.body;
    const response = credentialResponse || req.body;
    const {
      device_name,
      device_os,
      device_browser,
      device_fingerprint,
    } = device;

    if (!device_fingerprint || !device_name || !device_os || !device_browser) {
      throw new Error("Device details are required to complete enrollment.");
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
    });

    if (!verification.verified) return res.status(400).json({ registered: false });

    const { credential } = verification.registrationInfo;
    const activeDevices = await getActiveUserDevices(user.email);
    const existingOwnDevice = activeDevices.find(
      (deviceRecord) => deviceRecord.device_fingerprint === device_fingerprint
    );
    const existingOtherDevice = await Devices.findOne({
      device_fingerprint,
      user_email: { $ne: user.email },
    });

    if (existingOtherDevice) {
      throw new Error("This device is already enrolled by another account.");
    }

    if (!existingOwnDevice && activeDevices.length >= MAX_USER_DEVICES) {
      throw new Error(`You can only enroll up to ${MAX_USER_DEVICES} devices.`);
    }

    const credentialRecord = {
      credentialID: credential.id,
      credentialPublicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      deviceFingerprint: device_fingerprint,
      deviceName: device_name,
      deviceOS: device_os,
      deviceBrowser: device_browser,
      registeredAt: new Date(),
    };

    const authenticators = getUserAuthenticators(user).filter(
      (authenticator) =>
        authenticator.deviceFingerprint !== device_fingerprint
    );
    authenticators.push(credentialRecord);

    user.authenticators = authenticators;
    user.authenticator = undefined;

    await Devices.updateMany(
      { user_email: user.email },
      { $set: { device_primary: false } }
    );

    const devicePayload = {
      device_name,
      user_email: user.email,
      device_os,
      device_browser,
      device_primary: activeDevices.length === 0,
      device_lost: false,
      device_fingerprint,
    };

    if (existingOwnDevice) {
      await Devices.updateOne(
        { _id: existingOwnDevice._id },
        { $set: { ...devicePayload, device_primary: existingOwnDevice.device_primary || activeDevices.length === 0 } }
      );
    } else {
      await Devices.create(devicePayload);
    }

    await ensureSinglePrimaryDevice(user.email);

    // update user to mark biometric registration complete
    user.doneBiometric = true;
    user.hasDevices = (await getActiveUserDevices(user.email)).length > 1;
    user.deviceLost = false;

    await user.save();
    delete req.session.registrationChallenge;

    await createAuditLog({
      req,
      category: "device",
      action: "device.enrolled",
      description: "User enrolled a clocking device",
      actor: user,
      metadata: {
        deviceName: device_name,
        deviceOS: device_os,
        deviceBrowser: device_browser,
        deviceFingerprint: device_fingerprint,
        credentialID: credential.id,
      },
    });

    res.json({ registered: true });
  } catch (err) {
    console.error("Register verify error:", err);
    res.status(400).json({ registered: false, message: err.message });
  }
});

/**
 * 3. Generate Authentication Challenge
 *
 * credentialID is stored as a base64url string — pass it directly to allowCredentials.
 */
app.get(`${BASE_ROUTE}/biometric/auth/challenge`, async (req, res) => {
  try {

    if (!req.session.isOnline) return res.status(401).json({ message: "session expired, logout and login again to proceed!" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");
    const deviceFingerprint = String(req.query.device_fingerprint || "");
    const state = await getDeviceBiometricState(user, deviceFingerprint);
    const preferredAuthenticators = deviceFingerprint
      ? state.authenticators.filter(
        (authenticator) =>
          getAuthenticatorDeviceFingerprint(authenticator) === deviceFingerprint ||
          !getAuthenticatorDeviceFingerprint(authenticator)
      )
      : [];
    const authenticators = preferredAuthenticators.length
      ? preferredAuthenticators
      : state.authenticators;

    if (!user || authenticators.length === 0) {
      return res.status(400).json({
        message: state.accountRegistered
          ? "This browser does not have an enrolled biometric credential. Please add this device from Device Management."
          : "Biometric not registered for this account",
      });
    }

    const allowCredentials = [...new Map(
      authenticators.map((authenticator) => {
        const credentialID = getAuthenticatorCredentialID(authenticator);
        return [
          credentialID,
          {
            id: credentialID,
            type: "public-key",

            // force device/platform auth only
            transports: ["internal"],
          },
        ];
      })
    ).values()].filter((credential) => credential.id);

    if (allowCredentials.length === 0) {
      return res.status(400).json({ message: "No usable biometric credentials found for this account" });
    }

    const options = await generateAuthenticationOptions({
      rpID: getRpID(),

      userVerification: "required",

      // improves auth reliability across devices
      timeout: WEBAUTHN_TIMEOUT_MS,

      allowCredentials,
    });

    req.session.authChallenge = options.challenge;
    req.session.biometricVerified = false;

    res.json(options);
  } catch (error) {
    console.error("Auth challenge error:", error);
    res.status(500).json({ message: "Failed to generate authentication options" });
  }
});

const isOutsideClockingAuthorizedNow = (user, now = new Date()) => {
  if (!user?.canClockOutside || !user?.outsideClockingDetails) return false;

  try {
    const start = new Date(user.outsideClockingDetails.startDate);
    const end = new Date(user.outsideClockingDetails.endDate);
    return now >= start && now <= end;
  } catch (e) {
    console.warn('Outside clocking date validation failed:', e.message);
    return false;
  }
};

const parseAttendanceTime = (timeString, referenceDate = new Date()) => {
  if (!timeString || typeof timeString !== 'string') return null;
  const [hours, minutes] = timeString.split(':').map((value) => Number(value));
  if (Number.isNaN(hours) || Number.isNaN(minutes)) return null;
  return new Date(referenceDate.getFullYear(), referenceDate.getMonth(), referenceDate.getDate(), hours, minutes, 0, 0);
};

const getAttendancePolicy = async () => {
  const cfg = await PlatformConfig.getSingleton();
  return cfg.attendancePolicy || {};
};

const getSystemClockOutTime = (clockIn, standardClockOut = "17:00") => {
  const [hours, minutes] = String(standardClockOut || "17:00").split(":").map(Number);
  const safeHours = Number.isFinite(hours) ? hours : 17;
  const safeMinutes = Number.isFinite(minutes) ? minutes : 0;
  const parts = getNairobiDateParts(clockIn);
  const systemClockOut = new Date(Date.UTC(parts.year, parts.month - 1, parts.day, safeHours - 3, safeMinutes, 0, 0));

  if (systemClockOut > clockIn) return systemClockOut;

  return new Date(Date.UTC(parts.year, parts.month - 1, parts.day, 20, 59, 59, 999));
};

const normalizeKenyaPhone = (phone) => {
  if (!phone) return null;

  let digits = String(phone).replace(/\D/g, "");

  if (digits.startsWith("0")) {
    digits = "254" + digits.slice(1);
  } else if (digits.length === 9 && /^[71]/.test(digits)) {
    digits = "254" + digits;
  }

  if (/^254[71]\d{8}$/.test(digits)) {
    return digits;
  }

  return null;
};

const clearExpiredOutsideClocking = async (user, now = new Date()) => {
  if (!user?.canClockOutside || !user?.outsideClockingDetails?.endDate) return user;

  const end = new Date(user.outsideClockingDetails.endDate);
  if (now <= end) return user;

  user.canClockOutside = false;
  user.outsideClockingDetails = {
    startDate: null,
    endDate: null,
    reason: "",
    authorizedBy: "",
    authorizedByRole: "",
  };

  await user.save();
  return user;
};

const clearExpiredTemporaryAccount = async (user, now = new Date()) => {
  if (!user) return user;
  if (!['intern', 'attachee'].includes(user.role)) return user;
  if (!user.endDate) return user;

  const expiry = new Date(user.endDate);
  expiry.setHours(23, 59, 59, 999);
  if (now <= expiry) return user;

  user.isAccountActive = false;
  user.doneBiometric = false;
  user.authenticator = null;
  user.authenticators = [];

  await user.save();
  return user;
};

async function clearExpiredTemporaryAccountForSession(req, res, next) {
  if (req.session?.userID) {
    const user = await User.findById(req.session.userID);
    if (user) {
      await clearExpiredTemporaryAccount(user);
    }
  }
  return next();
};

const getNairobiLocalDate = (date = new Date()) => {
  const local = new Date(date.toLocaleString("en-US", { timeZone: "Africa/Nairobi" }));
  return new Date(local.getFullYear(), local.getMonth(), local.getDate());
};

const isBeforeNairobiDate = (date, compareDate = new Date()) => {
  const d = getNairobiLocalDate(date);
  const now = getNairobiLocalDate(compareDate);
  return d < now;
};

const finalizeStaleClocking = async (user, now = new Date()) => {
  if (!user) return user;

  const staleOpenClockings = await Clocking.find({
    email: user.email,
    clock_out: null,
  }).sort({ clock_in: 1 });

  const recordsToClose = staleOpenClockings.filter((record) =>
    isBeforeNairobiDate(record.clock_in, now)
  );

  if (!recordsToClose.length) return user;

  const attendancePolicy = await getAttendancePolicy();

  await Promise.all(recordsToClose.map(async (record) => {
    record.clock_out = getSystemClockOutTime(
      record.clock_in,
      attendancePolicy.standardClockOut || "17:00"
    );
    record.clockOutLocationName = record.clockOutLocationName || "System";
    record.missedClockOut = true;
    record.isPresent = true;
    await record.save();
  }));

  user.hasClockedIn = false;
  user.isToClockOut = false;
  await user.save();

  return user;
};

/**
 * 4. Verify Authentication Response
 *
 * KEY FIX — @simplewebauthn/server v10+ replaced the `authenticator` param with
 * a `credential` param using different field names:
 *
 *   ❌ Old shape (v9):
 *      authenticator: {
 *        credentialID:        Buffer,
 *        credentialPublicKey: Buffer,
 *        counter:             number,
 *      }
 *
 *   ✅ New shape (v10+):
 *      credential: {
 *        id:        string     — base64url (pass stored string directly)
 *        publicKey: Uint8Array — decoded from stored base64url
 *        counter:   number
 *      }
 */



// ─────────────────────────────────────────────────────────────────────────────
// BIOMETRIC AUTHENTICATION + CLOCK IN / CLOCK OUT
// ─────────────────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/biometric/auth/verify`, async (req, res) => {
  try {
    // ───────────────────────────────────────────────────────────────────────
    // 1. SESSION AUTHORIZATION
    // ───────────────────────────────────────────────────────────────────────

    if (!req.session.isOnline) {
      return res.status(401).json({
        verified: false,
        message: "Unauthorized",
      });
    }


    // ───────────────────────────────────────────────────────────────────────
    // 2. LOAD USER
    // ───────────────────────────────────────────────────────────────────────

    let user = await User.findById(req.session.userID);

    if (!user) {
      return res.status(404).json({
        verified: false,
        message: "User not found",
      });
    }

    user = await clearExpiredOutsideClocking(user);
    user = await finalizeStaleClocking(user);

    const authenticators = getUserAuthenticators(user);

    if (!authenticators || authenticators.length === 0) {
      return res.status(400).json({
        verified: false,
        message: "Fingerprint not registered",
      });
    }


    // ───────────────────────────────────────────────────────────────────────
    // 3. AUTHENTICATION CHALLENGE
    // ───────────────────────────────────────────────────────────────────────

    const expectedChallenge = req.session.authChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({
        verified: false,
        message: "No auth challenge found. Please restart.",
      });
    }


    // ───────────────────────────────────────────────────────────────────────
    // 4. REQUEST DATA
    // ───────────────────────────────────────────────────────────────────────

    const {
      selectedStation,
      userCoords,
      device_fingerprint,
      outsideLocation,
      ...authResponse
    } = req.body;


    // ───────────────────────────────────────────────────────────────────────
    // 5. FIND MATCHING AUTHENTICATOR
    // ───────────────────────────────────────────────────────────────────────

    const matchedAuthenticator =
      authenticators.find(
        (authenticator) =>
          getAuthenticatorCredentialID(authenticator) === authResponse.id &&
          getAuthenticatorDeviceFingerprint(authenticator) === device_fingerprint
      ) ||
      authenticators.find(
        (authenticator) =>
          getAuthenticatorCredentialID(authenticator) === authResponse.id &&
          !getAuthenticatorDeviceFingerprint(authenticator)
      ) ||
      authenticators.find(
        (authenticator) =>
          getAuthenticatorCredentialID(authenticator) === authResponse.id
      );

    if (!matchedAuthenticator) {
      return res.status(401).json({
        verified: false,
        message:
          "This device is not enrolled for clocking.",
      });
    }


    // ───────────────────────────────────────────────────────────────────────
    // 6. VERIFY DEVICE APPROVAL
    // ───────────────────────────────────────────────────────────────────────

    let matchedDevice = await Devices.findOne({
      user_email: user.email,

      device_fingerprint:
        getAuthenticatorDeviceFingerprint(matchedAuthenticator) ||
        device_fingerprint,

      device_lost: {
        $ne: true,
      },
    });

    if (!matchedDevice) {
      return res.status(403).json({
        verified: false,
        message:
          "This device has not been approved for clocking.",
      });
    }


    // ───────────────────────────────────────────────────────────────────────
    // 7. VERIFY WEBAUTHN RESPONSE
    // ───────────────────────────────────────────────────────────────────────

    const verification =
      await verifyAuthenticationResponse({
        response: authResponse,

        expectedChallenge,

        expectedOrigin:
          getExpectedOrigin(),

        expectedRPID:
          getRpID(),

        credential: {
          id: matchedAuthenticator.credentialID,

          publicKey: new Uint8Array(
            Buffer.from(
              matchedAuthenticator.credentialPublicKey,
              "base64url"
            )
          ),

          counter:
            matchedAuthenticator.counter,
        },

        requireUserVerification: true,
      });


    // ───────────────────────────────────────────────────────────────────────
    // 8. BIOMETRIC VERIFICATION FAILED
    // ───────────────────────────────────────────────────────────────────────

    if (!verification.verified) {
      return res.status(401).json({
        verified: false,
        message: "Biometric verification failed.",
      });
    }

    const verifiedDeviceFingerprint = String(device_fingerprint || "");
    const matchedAuthenticatorDeviceFingerprint = getAuthenticatorDeviceFingerprint(matchedAuthenticator);
    let nextDeviceFingerprint = matchedAuthenticatorDeviceFingerprint || verifiedDeviceFingerprint;

    if (
      verifiedDeviceFingerprint &&
      matchedAuthenticatorDeviceFingerprint &&
      verifiedDeviceFingerprint !== matchedAuthenticatorDeviceFingerprint
    ) {
      const conflictingDevice = await Devices.findOne({
        device_fingerprint: verifiedDeviceFingerprint,
        user_email: { $ne: user.email },
      });

      if (conflictingDevice) {
        return res.status(403).json({
          verified: false,
          message: "This device is already enrolled by another account.",
        });
      }

      const currentDevice = await Devices.findOne({
        user_email: user.email,
        device_fingerprint: verifiedDeviceFingerprint,
        device_lost: { $ne: true },
      });

      if (currentDevice) {
        matchedDevice = currentDevice;
        nextDeviceFingerprint = verifiedDeviceFingerprint;
      } else if (matchedDevice) {
        await Devices.updateOne(
          { _id: matchedDevice._id },
          { $set: { device_fingerprint: verifiedDeviceFingerprint } }
        );
        matchedDevice.device_fingerprint = verifiedDeviceFingerprint;
        nextDeviceFingerprint = verifiedDeviceFingerprint;
      }
    } else if (verifiedDeviceFingerprint && !matchedAuthenticatorDeviceFingerprint) {
      nextDeviceFingerprint = verifiedDeviceFingerprint;
    }


    // ───────────────────────────────────────────────────────────────────────
    // 9. UPDATE AUTHENTICATOR COUNTER
    // ───────────────────────────────────────────────────────────────────────

    user.authenticators = authenticators.map(
      (authenticator) => {

        const sameCredential =
          getAuthenticatorCredentialID(authenticator) ===
          getAuthenticatorCredentialID(matchedAuthenticator);

        const sameDevice =
          getAuthenticatorDeviceFingerprint(authenticator) ===
          getAuthenticatorDeviceFingerprint(matchedAuthenticator);

        if (
          sameCredential &&
          sameDevice
        ) {
          return {
            ...(authenticator.toObject?.() ||
              authenticator),

            counter:
              verification
                .authenticationInfo
                .newCounter,

            deviceFingerprint:
              nextDeviceFingerprint,

            lastUsedAt:
              new Date(),
          };
        }

        return authenticator;
      }
    );

    // Clear legacy single authenticator
    user.authenticator = undefined;

    await user.save();


    // ───────────────────────────────────────────────────────────────────────
    // 10. GET FRESH CLOCKING TIMESTAMP
    //
    // IMPORTANT:
    // This is deliberately created AFTER successful biometric verification.
    // MongoDB receives the actual Date object.
    // ───────────────────────────────────────────────────────────────────────

    const clockingTime = getCurrentTime();

    const {
      formattedDate,
      formattedTime,
    } = formatEATDateTime(
      clockingTime
    );


    // Debugging
    console.log(
      `[CLOCKING] ${user.email}`
    );

    console.log(
      `UTC: ${clockingTime.toISOString()}`
    );

    console.log(
      `EAT: ${formattedDate} ${formattedTime}`
    );


    // ───────────────────────────────────────────────────────────────────────
    // 11. FIND LATEST CLOCKING RECORD
    //
    // Database is the source of truth.
    // ───────────────────────────────────────────────────────────────────────

    const latestClocking =
      await Clocking
        .findOne({
          email: user.email,
        })
        .sort({
          clock_in: -1,
        });


    // An open record means the user has clocked in
    // but has not yet clocked out.

    const hasOpenClocking =
      latestClocking &&
      !latestClocking.clock_out;


    // ───────────────────────────────────────────────────────────────────────
    // 12. DETERMINE ACTION
    // ───────────────────────────────────────────────────────────────────────

    const isClockingIn =
      !hasOpenClocking;


    // ───────────────────────────────────────────────────────────────────────
    // 13. RESPONSE METADATA
    // ───────────────────────────────────────────────────────────────────────

    const verifyResultMeta = {
      action: isClockingIn
        ? "clock_in"
        : "clock_out",

      clockedOutside: false,

      outsideLocation: null,

      date: formattedDate,

      time: formattedTime,

      timezone: EAT_TIMEZONE,
    };


    // ═════════════════════════════════════════════════════════════════════════
    // CLOCK IN
    // ═════════════════════════════════════════════════════════════════════════

    if (isClockingIn) {

      // ─────────────────────────────────────────────────────────────────────
      // ATTENDANCE POLICY
      // ─────────────────────────────────────────────────────────────────────

      const attendancePolicy =
        await getAttendancePolicy();


      /*
       * Your parseAttendanceTime function should interpret
       * standardClockIn in Africa/Nairobi.
       *
       * We do NOT convert Date -> string -> Date.
       */

      const targetClockIn =
        parseAttendanceTime(
          attendancePolicy.standardClockIn ||
          "08:00",

          clockingTime
        ) || clockingTime;


      const graceMinutes =
        Number(
          attendancePolicy.gracePeriodMinutes ??
          15
        );


      const graceDeadline =
        new Date(
          targetClockIn.getTime() +
          graceMinutes * 60 * 1000
        );


      const isLate =
        clockingTime >
        graceDeadline;


      const isEmployee =
        user.role === "employee";


      // ─────────────────────────────────────────────────────────────────────
      // CLOCKING DATA
      // ─────────────────────────────────────────────────────────────────────

      const clockingData = {

        name:
          user.name,

        email:
          user.email,

        department:
          user.department,

        supervisor:
          isEmployee
            ? ""
            : user.supervisor,

        station:
          selectedStation ||
          user.station ||
          "",

        phone:
          user.phone,

        // Store actual Date.
        // MongoDB stores the instant in UTC.
        clock_in:
          clockingTime,

        clock_out:
          null,

        isLate:
          isLate,

        isPresent:
          false,

        userLocation: {

          latitude:
            userCoords?.latitude ??
            null,

          longitude:
            userCoords?.longitude ??
            null,
        },
      };


      // ─────────────────────────────────────────────────────────────────────
      // OUTSIDE CLOCKING
      // ─────────────────────────────────────────────────────────────────────

      const canClockOutsideNow =
        isOutsideClockingAuthorizedNow(
          user,
          clockingTime
        );


      if (canClockOutsideNow) {

        clockingData.outsideLocation =
          outsideLocation || "";

        clockingData.clockInLocationName =
          outsideLocation || "";

        clockingData.clockedOutSide =
          true;

        clockingData.outSideReason =
          user.outsideClockingDetails?.reason ||
          "";

        verifyResultMeta.clockedOutside =
          true;

        verifyResultMeta.outsideLocation =
          outsideLocation || null;
      }
      else if (outsideLocation) {

        console.debug(
          "outsideLocation provided but user not authorized",
          {
            email: user.email,

            canClockOutside:
              user.canClockOutside,

            outsideClockingDetails:
              user.outsideClockingDetails,
          }
        );
      }


      // ─────────────────────────────────────────────────────────────────────
      // CREATE CLOCK-IN
      // ─────────────────────────────────────────────────────────────────────

      const createdClocking =
        await Clocking.create(
          clockingData
        );


      // ─────────────────────────────────────────────────────────────────────
      // UPDATE USER STATE
      // ─────────────────────────────────────────────────────────────────────

      user.hasClockedIn =
        true;

      user.isToClockOut =
        true;

      await user.save();


      // ─────────────────────────────────────────────────────────────────────
      // SEND CLOCK-IN MESSAGE
      // ─────────────────────────────────────────────────────────────────────

      await SendMessageNow(
        user,

        `Dear ${user.name}, you have successfully checked in at ${clockingData.station} on ${formattedDate} at ${formattedTime} EAT.`
      );


      // ─────────────────────────────────────────────────────────────────────
      // AUDIT LOG
      // ─────────────────────────────────────────────────────────────────────

      await createAuditLog({

        req,

        category:
          "attendance",

        action:
          "attendance.clock_in",

        description:
          "User clocked in",

        actor:
          user,

        metadata: {

          clockingId:
            createdClocking._id,

          station:
            clockingData.station,

          clockIn:
            clockingTime.toISOString(),

          clockedOutside:
            verifyResultMeta.clockedOutside,

          outsideLocation:
            verifyResultMeta.outsideLocation,

          userLocation:
            clockingData.userLocation,

          isLate:
            isLate,
        },
      });
    }


    // ═════════════════════════════════════════════════════════════════════════
    // CLOCK OUT
    // ═════════════════════════════════════════════════════════════════════════

    else {

      // ─────────────────────────────────────────────────────────────────────
      // GET FRESH CLOCK-OUT TIME
      //
      // This is intentionally created immediately before updating
      // the clock-out record.
      // ─────────────────────────────────────────────────────────────────────

      const clockOutTime =
        getCurrentTime();


      const {
        formattedDate:
        clockOutDate,

        formattedTime:
        clockOutFormattedTime,
      } = formatEATDateTime(
        clockOutTime
      );


      // ─────────────────────────────────────────────────────────────────────
      // CALCULATE WORKED TIME
      // ─────────────────────────────────────────────────────────────────────

      const clockInTime =
        latestClocking.clock_in;


      const diffMs =
        clockOutTime.getTime() -
        clockInTime.getTime();


      const diffHours =
        diffMs /
        (1000 * 60 * 60);


      // Prevent negative values caused by invalid data
      const safeDiffHours =
        Math.max(
          0,
          diffHours
        );


      // Present if worked 5 hours or more
      latestClocking.isPresent =
        safeDiffHours >= 5;


      // ─────────────────────────────────────────────────────────────────────
      // SET CLOCK-OUT
      // ─────────────────────────────────────────────────────────────────────

      latestClocking.clock_out =
        clockOutTime;


      // ─────────────────────────────────────────────────────────────────────
      // OUTSIDE CLOCKING
      // ─────────────────────────────────────────────────────────────────────

      const canClockOutsideNow =
        isOutsideClockingAuthorizedNow(
          user,
          clockOutTime
        );


      if (canClockOutsideNow) {

        latestClocking.clockOutLocationName =
          outsideLocation || "";

        latestClocking.outsideLocation =
          latestClocking.outsideLocation ||
          outsideLocation ||
          "";

        latestClocking.clockedOutSide =
          true;

        latestClocking.outSideReason =
          user.outsideClockingDetails?.reason ||
          latestClocking.outSideReason ||
          "";

        verifyResultMeta.clockedOutside =
          true;

        verifyResultMeta.outsideLocation =
          outsideLocation || null;

      }
      else if (outsideLocation) {

        console.debug(
          "outsideLocation provided at clock-out but user not authorized",
          {
            email: user.email,

            canClockOutside:
              user.canClockOutside,

            outsideClockingDetails:
              user.outsideClockingDetails,
          }
        );
      }


      // ─────────────────────────────────────────────────────────────────────
      // SAVE CLOCK-OUT
      // ─────────────────────────────────────────────────────────────────────

      await latestClocking.save();


      // ─────────────────────────────────────────────────────────────────────
      // UPDATE USER STATE
      // ─────────────────────────────────────────────────────────────────────

      user.hasClockedIn =
        false;

      user.isToClockOut =
        false;

      await user.save();


      // ─────────────────────────────────────────────────────────────────────
      // SEND CLOCK-OUT MESSAGE
      // ─────────────────────────────────────────────────────────────────────

      await SendMessageNow(
        user,

        `Dear ${user.name}, you have successfully checked out from ${latestClocking.station} on ${clockOutDate} at ${clockOutFormattedTime} EAT.`
      );


      // ─────────────────────────────────────────────────────────────────────
      // AUDIT LOG
      // ─────────────────────────────────────────────────────────────────────

      await createAuditLog({

        req,

        category:
          "attendance",

        action:
          "attendance.clock_out",

        description:
          "User clocked out",

        actor:
          user,

        metadata: {

          clockingId:
            latestClocking._id,

          station:
            latestClocking.station,

          clockIn:
            clockInTime.toISOString(),

          clockOut:
            clockOutTime.toISOString(),

          workedHours:
            Number(
              safeDiffHours.toFixed(2)
            ),

          isPresent:
            latestClocking.isPresent,

          clockedOutside:
            verifyResultMeta.clockedOutside,

          outsideLocation:
            verifyResultMeta.outsideLocation,
        },
      });


      // Update response time to the exact clock-out time
      verifyResultMeta.date =
        clockOutDate;

      verifyResultMeta.time =
        clockOutFormattedTime;
    }


    // ───────────────────────────────────────────────────────────────────────
    // BIOMETRIC SESSION
    // ───────────────────────────────────────────────────────────────────────

    req.session.biometricVerified =
      true;

    req.session.biometricVerifiedAt =
      Date.now();

    delete req.session.authChallenge;


    // ───────────────────────────────────────────────────────────────────────
    // RESPONSE
    // ───────────────────────────────────────────────────────────────────────

    return res.json({

      verified:
        true,

      meta:
        verifyResultMeta,

      timestamp: {

        utc:
          new Date().toISOString(),

        date:
          verifyResultMeta.date,

        time:
          verifyResultMeta.time,

        timezone:
          EAT_TIMEZONE,
      },
    });

  } catch (err) {

    console.error(
      "Auth verify error:",
      err
    );

    return res.status(401).json({

      verified:
        false,

      message:
        err.message,
    });
  }
});



// ─── Attendance ──────────────

app.post(`${BASE_ROUTE}/attendance/clockin`, async (req, res) => {
  const BIOMETRIC_WINDOW_MS = 2 * 60 * 1000;
  const verified =
    req.session.biometricVerified &&
    Date.now() - req.session.biometricVerifiedAt < BIOMETRIC_WINDOW_MS;

  if (!verified) {
    return res.status(403).json({
      message: "Biometric verification required or expired. Please re-verify.",
    });
  }

  try {
    req.session.biometricVerified = false; // one-shot — clear after use
    res.json({ message: "Clock-in successful", timestamp: new Date() });
  } catch (err) {
    console.error("Clock-in error:", err);
    res.status(500).json({ message: "Clock-in failed" });
  }
});


// User related routes (e.g. profile update) would go here, ensuring to check req.session.isOnline and req.session.userID for authentication

// get user profile
app.get(`${BASE_ROUTE}/user/profile`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    let user = await clearExpiredOutsideClocking(
      await User.findById(req.session.userID).select("-password").select("-authenticator").select("-authenticators")
    );
    user = await finalizeStaleClocking(user);
    if (!user) throw new Error("User not found");

    res.json(user);
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(400).json({ message: err.message });
  }
});

// update user profile
app.post(`${BASE_ROUTE}/user/profile`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    const { name, department, supervisor, phone, startDate, endDate } = req.body;

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    user.name = name || user.name;
    user.department = department || user.department;
    user.supervisor = supervisor || user.supervisor;
    user.phone = phone || user.phone;
    user.startDate = startDate || user.startDate;
    user.endDate = endDate || user.endDate;

    await user.save();
    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(400).json({ message: err.message });
  }
});




// fetch top 3 clocking data for the logged-in user, if no limit is specified, fetch all clocking data
app.get(`${BASE_ROUTE}/user/attendance/history`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    let user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");
    user = await finalizeStaleClocking(user);

    const limit = parseInt(req.query.limit) || 0;
    if (limit == 0) {
      const clockingData = await Clocking.find({ email: user.email }).sort({ clock_in: -1 });
      res.json(clockingData);
      return;
    } else {
      const clockingData = await Clocking.find({ email: user.email }).sort({ clock_in: -1 }).limit(limit);
      res.json(clockingData);
    }
  } catch (err) {
    console.error("Fetch clocking data error:", err);
    res.status(400).json({ message: err.message });
  }
});



// attendance stats User
app.get(`${BASE_ROUTE}/user/attendance/stats`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    let user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");
    user = await finalizeStaleClocking(user);

    const userEmail = user.email;
    const now = new Date();

    // Date Ranges
    const startOfMonth = getNairobiMonthStart(now);
    const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

    const startOfWeek = parseDateRangeBoundary(getNairobiDateKey(now), "startDate", "start");
    const dayOfWeek = getNairobiWeekdayIndex(now);
    startOfWeek.setUTCDate(startOfWeek.getUTCDate() + (dayOfWeek === 0 ? -6 : 1 - dayOfWeek));

    const records = await Clocking.find({
      email: userEmail,
      clock_in: { $gte: startOfMonth, $lte: endOfMonth }
    });

    // Helper: Calculate working days excluding weekends
    const getWorkingDays = (start, end) => {
      let count = 0;
      let cur = new Date(start);
      while (cur <= end && cur <= now) {
        const day = getNairobiWeekdayIndex(cur);
        if (day !== 0 && day !== 6) count++;
        cur.setDate(cur.getDate() + 1);
      }
      return count || 1;
    };

    const processStats = (filteredRecords, totalExpectedDays) => {
      const dailyMap = {};

      filteredRecords.forEach(rec => {
        const dateKey = getNairobiDateKey(rec.clock_in);
        if (!dailyMap[dateKey]) {
          dailyMap[dateKey] = { hours: 0, isLateAny: false, isEarlyAny: false, clockings: 0, missedClockOut: false };
        }

        if (rec.missedClockOut) {
          dailyMap[dateKey].missedClockOut = true;
        }

        if (rec.clock_out) {
          const duration = (new Date(rec.clock_out) - new Date(rec.clock_in)) / (1000 * 60 * 60);
          dailyMap[dateKey].hours += duration;
        } else if (rec.missedClockOut) {
          dailyMap[dateKey].missedClockOut = true;
        }

        // Punctuality: If any clock-in today was early, the day counts as early
        if (rec.isLate) dailyMap[dateKey].isLateAny = true;
        else dailyMap[dateKey].isEarlyAny = true;

        dailyMap[dateKey].clockings++;
      });

      let totalHours = 0;
      let totalOvertime = 0;
      let presentDays = 0;
      let halfDays = 0;
      let lateDays = 0;
      let earlyDays = 0;

      Object.values(dailyMap).forEach(day => {
        totalHours += day.hours;
        if (day.hours > 9) totalOvertime += (day.hours - 9);

        // Logical Classification
        if (day.missedClockOut) presentDays++;
        else if (day.hours >= 5) presentDays++;
        else if (day.hours > 0) halfDays++;

        // Punctuality Strategy: Early trump's Late for the day
        if (day.isEarlyAny) earlyDays++;
        else if (day.isLateAny) lateDays++;
      });

      const attendanceRate = ((presentDays / totalExpectedDays) * 100).toFixed(1);
      const punctualityRate = (presentDays + halfDays > 0)
        ? ((earlyDays / (earlyDays + lateDays)) * 100).toFixed(1)
        : 0;

      return {
        totalHours: totalHours.toFixed(2),
        overtimeHours: totalOvertime.toFixed(2),
        presentDays,
        halfDays,
        absentDays: Math.max(0, totalExpectedDays - presentDays - halfDays),
        lateDays,
        earlyDays,
        attendanceRate: Number(attendanceRate),
        punctualityRate: Number(punctualityRate),
        avgHoursPerDay: (totalHours / (presentDays + halfDays || 1)).toFixed(2)
      };
    };

    const weeklyStats = processStats(
      records.filter(r => new Date(r.clock_in) >= startOfWeek),
      getWorkingDays(startOfWeek, now)
    );

    const monthlyStats = processStats(
      records,
      getWorkingDays(startOfMonth, now)
    );

    res.status(200).json({
      weekly: weeklyStats,
      monthly: monthlyStats,
      summary: `You have worked ${monthlyStats.totalHours} hours this month with ${monthlyStats.overtimeHours} hours of overtime.`
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// ANALYTICS
// GET /overall/attendance/analytics/kpis
app.get(`${BASE_ROUTE}/overall/attendance/analytics/kpis`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const {
      startDate,
      endDate,
      department,
      station,
      role,
      rank,
    } = normalizeAnalyticsQuery(req.query);
    const userFilter = buildAnalyticsUserFilter(context, {
      department,
      station,
      role,
      rank,
    });
    const users = await User.find(userFilter, 'email isAccountActive isOnLeave');
    const emails = users.map(u => u.email);

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);

      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    };



    // Fetch all clockings in range
    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: start, $lte: end }
    });

    // Today's date for present/absent counts
    const today = getNairobiDateKey(new Date());

    let startToday;
    let endToday;

    try {
      const range = getSafeDateRange(today, today);

      startToday = range.start;
      endToday = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    }


    // Today's clockings and approved leave
    const [todayRecords, leaveTodayRecords] = await Promise.all([
      Clocking.find({
        email: { $in: emails },
        clock_in: { $gte: startToday, $lte: endToday }
      }).lean(),
      Leave.find({
        email: { $in: emails },
        status: "approved",
        startDate: { $lte: endToday },
        endDate: { $gte: startToday },
      }).lean(),
    ]);

    const totalEmployees = users.length;
    const activeEmployeesToday = new Set(todayRecords.map(r => r.email)).size;
    const onLeaveToday = new Set(leaveTodayRecords.map(r => r.email)).size;
    const presentToday = activeEmployeesToday;
    const absentToday = Math.max(totalEmployees - activeEmployeesToday - onLeaveToday, 0);

    // Attendance rate: present days / total working days in period
    const workingDays = countWeekdays(start, end); // helper to count weekdays
    const presentDaysMap = {};
    records.forEach(r => {
      if (!presentDaysMap[r.email]) presentDaysMap[r.email] = new Set();
      presentDaysMap[r.email].add(getNairobiDateKey(r.clock_in));
    });
    const totalPresentDays = Object.values(presentDaysMap).reduce((sum, set) => sum + set.size, 0);
    const attendanceRate = totalEmployees > 0 ? (totalPresentDays / (totalEmployees * workingDays)) * 100 : 0;

    // Punctuality: early vs late (based on isLate flag)
    let earlyCount = 0, lateCount = 0;
    records.forEach(r => {
      if (r.isLate) lateCount++;
      else earlyCount++;
    });
    const punctualityRate = (earlyCount + lateCount) > 0 ? (earlyCount / (earlyCount + lateCount)) * 100 : 0;

    // Productivity index: average hours per employee (capped at 8h/day)
    let totalHours = 0;
    records.forEach(r => {
      if (r.clock_out) {
        let hours = (r.clock_out - r.clock_in) / (1000 * 60 * 60);
        hours = Math.min(hours, 8); // cap at 8h
        totalHours += hours;
      }
    });
    const avgHours = totalEmployees > 0 ? totalHours / totalEmployees : 0;
    const productivityIndex = (avgHours / 8) * 100;

    // Absenteeism rate = 1 - attendance rate
    const absenteeismRate = 100 - attendanceRate;

    // Average working hours (for CEO)
    const totalClockedHours = records.reduce((sum, r) => sum + (r.clock_out ? (r.clock_out - r.clock_in) / (1000 * 60 * 60) : 0), 0);
    const averageWorkingHours = records.length > 0 ? totalClockedHours / records.length : 0;

    // For filters dropdown
    const config = await PlatformConfig.getSingleton();
    const allDepartments = config.departments || [];
    const allStations = config.stations.filter(s => s.active).map(s => s.name);

    res.json({
      totalEmployees,
      presentToday,
      absentToday,
      onLeaveToday,
      attendanceRate: parseFloat(attendanceRate.toFixed(1)),
      punctualityRate: parseFloat(punctualityRate.toFixed(1)),
      productivityIndex: parseFloat(productivityIndex.toFixed(1)),
      averageWorkingHours: parseFloat(averageWorkingHours.toFixed(1)),
      activeEmployeesToday,
      employeesOnLeave: onLeaveToday,
      workforceSize: totalEmployees,
      absenteeismRate: parseFloat(absenteeismRate.toFixed(1)),
      departments: allDepartments,
      stations: allStations
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




// GET /overall/attendance/analytics/trends
app.get(`${BASE_ROUTE}/overall/attendance/analytics/trends`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, { department, station, role, rank });
    const users = await User.find(userFilter, 'email');
    const emails = users.map(u => u.email);

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    const [records, leaveRecords] = await Promise.all([
      Clocking.find({
        email: { $in: emails },
        clock_in: { $gte: start, $lte: end }
      }).lean(),
      Leave.find({
        email: { $in: emails },
        startDate: { $lte: end },
        endDate: { $gte: start },
      }).lean(),
    ]);

    const workingDateKeys = getWorkingDateKeysInRange(start, end);
    const totalStaff = users.length;
    const dailyMap = workingDateKeys.reduce((acc, dateKey) => {
      acc[dateKey] = {
        date: dateKey,
        presentEmails: new Set(),
        lateEmails: new Set(),
        leaveEmails: new Set(),
      };
      return acc;
    }, {});

    records.forEach((record) => {
      const key = getNairobiDateKey(record.clock_in);
      if (!dailyMap[key]) return;
      if (record.email) dailyMap[key].presentEmails.add(record.email);
      if (record.isLate && record.email) dailyMap[key].lateEmails.add(record.email);
    });

    leaveRecords.forEach((leave) => {
      if (String(leave.status || "").toLowerCase() !== "approved") return;

      const leaveStart = parseDateRangeBoundary(leave.startDate, "startDate", "start");
      const leaveEnd = parseDateRangeBoundary(leave.endDate, "endDate", "end");

      workingDateKeys.forEach((dateKey) => {
        const dayStart = parseDateRangeBoundary(dateKey, "date", "start");
        if (dayStart >= leaveStart && dayStart <= leaveEnd) {
          dailyMap[dateKey]?.leaveEmails.add(leave.email);
        }
      });
    });

    const daily = Object.values(dailyMap).map((entry) => {
      const present = entry.presentEmails.size;
      const late = entry.lateEmails.size;
      const onLeave = entry.leaveEmails.size;
      const absent = Math.max(totalStaff - present - onLeave, 0);

      return {
        date: entry.date,
        present,
        absent,
        late,
        onLeave,
        totalStaff,
        attendance: totalStaff > 0 ? parseFloat(((present / totalStaff) * 100).toFixed(1)) : 0,
      };
    }).sort((a, b) => a.date.localeCompare(b.date));

    // Weekly aggregation
    const weeklyMap = {};
    daily.forEach(d => {
      const week = getWeekNumber(parseDateRangeBoundary(d.date, "date", "start"));
      const key = `${d.date.substring(0, 4)}-W${String(week).padStart(2, '0')}`;
      if (!weeklyMap[key]) weeklyMap[key] = { total: 0, sum: 0 };
      weeklyMap[key].total++;
      weeklyMap[key].sum += d.attendance;
    });
    const weekly = Object.keys(weeklyMap).map(week => ({
      week,
      attendance: weeklyMap[week].sum / weeklyMap[week].total
    })).sort((a, b) => a.week.localeCompare(b.week));

    // Monthly
    const monthlyMap = {};
    daily.forEach(d => {
      const month = d.date.substring(0, 7);
      if (!monthlyMap[month]) monthlyMap[month] = { total: 0, sum: 0 };
      monthlyMap[month].total++;
      monthlyMap[month].sum += d.attendance;
    });
    const monthly = Object.keys(monthlyMap).map(month => ({
      month,
      attendance: monthlyMap[month].sum / monthlyMap[month].total
    })).sort((a, b) => a.month.localeCompare(b.month));

    // Yearly
    const yearlyMap = {};
    daily.forEach(d => {
      const year = d.date.substring(0, 4);
      if (!yearlyMap[year]) yearlyMap[year] = { total: 0, sum: 0 };
      yearlyMap[year].total++;
      yearlyMap[year].sum += d.attendance;
    });
    const yearly = Object.keys(yearlyMap).map(year => ({
      year,
      attendance: yearlyMap[year].sum / yearlyMap[year].total
    })).sort((a, b) => a.year.localeCompare(b.year));

    res.json({ daily, weekly, monthly, yearly });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Helper: get ISO week number
function getWeekNumber(d) {
  const parts = getNairobiDateParts(d);
  const date = new Date(Date.UTC(parts.year, parts.month - 1, parts.day));
  date.setUTCDate(date.getUTCDate() + 3 - (date.getUTCDay() + 6) % 7);
  const week1 = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  return 1 + Math.round(((date - week1) / 86400000 - 3 + (week1.getUTCDay() + 6) % 7) / 7);
}



// late arrivals analytics
// GET /overall/attendance/analytics/late-arrivals
app.get(`${BASE_ROUTE}/overall/attendance/analytics/late-arrivals`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, { department, station, role, rank });
    const users = await User.find(userFilter, 'email department');
    const emails = users.map(u => u.email);
    const userDeptMap = {};
    users.forEach(u => userDeptMap[u.email] = u.department);

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: start, $lte: end }
    });

    // Employees late today
    const today = getNairobiDateKey(new Date());
    const { start: todayStart, end: todayEnd } = getSafeDateRange(today, today);
    const lateToday = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: todayStart, $lte: todayEnd },
      isLate: true
    });
    const employeesLateToday = new Set(lateToday.map(r => r.email)).size;

    // Average lateness (minutes) – assume late means clock_in > 8:00 AM
    let totalLateMinutes = 0, lateCount = 0;
    records.forEach(r => {
      if (r.isLate) {
        const hours = getNairobiHourDecimal(r.clock_in);
        const lateMins = Math.max(0, (hours - 8) * 60);
        totalLateMinutes += lateMins;
        lateCount++;
      }
    });
    const averageLatenessMinutes = lateCount > 0 ? totalLateMinutes / lateCount : 0;

    // Most punctual departments (avg lateness)
    const deptLateMap = {};
    records.forEach(r => {
      const dept = userDeptMap[r.email] || 'Unknown';
      if (!deptLateMap[dept]) deptLateMap[dept] = { total: 0, count: 0 };
      if (r.isLate) {
        const hours = getNairobiHourDecimal(r.clock_in);
        const mins = Math.max(0, (hours - 8) * 60);
        deptLateMap[dept].total += mins;
        deptLateMap[dept].count++;
      }
    });
    const deptAvg = Object.keys(deptLateMap).map(dept => ({
      department: dept,
      avgLateness: deptLateMap[dept].count > 0 ? deptLateMap[dept].total / deptLateMap[dept].count : 0
    }));
    const mostPunctual = [...deptAvg].sort((a, b) => a.avgLateness - b.avgLateness).slice(0, 5);
    const highestLateness = [...deptAvg].sort((a, b) => b.avgLateness - a.avgLateness).slice(0, 5);

    // Late by weekday
    const weekdayMap = { Mon: 0, Tue: 0, Wed: 0, Thu: 0, Fri: 0 };
    records.forEach(r => {
      if (r.isLate) {
        const day = getNairobiWeekdayName(r.clock_in);
        if (weekdayMap[day] !== undefined) weekdayMap[day]++;
      }
    });
    const lateByWeekday = Object.keys(weekdayMap).map(day => ({ weekday: day, count: weekdayMap[day] }));

    // Late by department
    const deptLateCount = {};
    records.forEach(r => {
      if (r.isLate) {
        const dept = userDeptMap[r.email] || 'Unknown';
        deptLateCount[dept] = (deptLateCount[dept] || 0) + 1;
      }
    });
    const lateByDepartment = Object.keys(deptLateCount).map(dept => ({ department: dept, count: deptLateCount[dept] }));

    // Heatmap – arrival times (hour vs day)
    const heatmapData = [];
    records.forEach(r => {
      const hour = Math.floor(getNairobiHourDecimal(r.clock_in));
      const day = getNairobiWeekdayName(r.clock_in);
      if (hour >= 6 && hour <= 12) {
        heatmapData.push({ hour, day, value: 1 });
      }
    });

    res.json({
      employeesLateToday,
      averageLatenessMinutes: parseFloat(averageLatenessMinutes.toFixed(1)),
      mostPunctualDepartments: mostPunctual,
      highestLatenessDepartments: highestLateness,
      lateByWeekday,
      lateByDepartment,
      heatmapData
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// early departures analytics
// GET /overall/attendance/analytics/early-departures
app.get(`${BASE_ROUTE}/overall/attendance/analytics/early-departures`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, { department, station, role, rank });
    const users = await User.find(userFilter, 'email department');
    const emails = users.map(u => u.email);
    const userDeptMap = {};
    users.forEach(u => userDeptMap[u.email] = u.department);

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: start, $lte: end },
      clock_out: { $ne: null }
    });

    // Count early departures (clock_out < 17:00)
    let earlyCount = 0;
    let totalEarlyMins = 0;
    const userEarlyMap = {};
    const deptEarlyMap = {};

    records.forEach(r => {
      const hours = getNairobiHourDecimal(r.clock_out);
      if (hours < 17) {
        earlyCount++;
        const earlyMins = (17 - hours) * 60;
        totalEarlyMins += earlyMins;
        const email = r.email;
        userEarlyMap[email] = (userEarlyMap[email] || 0) + 1;
        const dept = userDeptMap[email] || 'Unknown';
        deptEarlyMap[dept] = (deptEarlyMap[dept] || 0) + 1;
      }
    });

    const averageEarlyDepartureMinutes = earlyCount > 0 ? totalEarlyMins / earlyCount : 0;

    const frequentEarlyDepartures = Object.keys(userEarlyMap)
      .map(email => ({ email, count: userEarlyMap[email] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const earlyByDepartment = Object.keys(deptEarlyMap).map(dept => ({
      department: dept,
      count: deptEarlyMap[dept]
    }));

    res.json({
      employeesLeavingEarly: earlyCount,
      averageEarlyDepartureMinutes: parseFloat(averageEarlyDepartureMinutes.toFixed(1)),
      frequentEarlyDepartures,
      earlyByDepartment
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// absenteeism analytics
// GET /overall/attendance/analytics/absenteeism
app.get(`${BASE_ROUTE}/overall/attendance/analytics/absenteeism`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, {
      department,
      station,
      role,
      rank,
    });

    const users = await User.find(
      userFilter,
      'email department'
    );

    const emails = users.map(u => u.email);

    const userDeptMap = {};
    users.forEach(u => {
      userDeptMap[u.email] = u.department;
    });

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: {
        $gte: start,
        $lte: end
      }
    });

    // ---------------------------------------------------------
    // TOTAL WORKING DAYS
    // ---------------------------------------------------------
    const workingDays = countWeekdays(start, end);

    // ---------------------------------------------------------
    // PER-MONTH / DEPARTMENT DATA
    // ---------------------------------------------------------
    const deptAbsenteeism = {};

    // ---------------------------------------------------------
    // PRESENT DAYS PER USER
    // ---------------------------------------------------------
    const userPresent = {};

    records.forEach(r => {
      if (!r.clock_in) return;

      const email = r.email;

      if (!userPresent[email]) {
        userPresent[email] = new Set();
      }

      userPresent[email].add(
        getNairobiDateKey(r.clock_in)
      );
    });

    // ---------------------------------------------------------
    // OVERALL ABSENTEEISM
    // ---------------------------------------------------------
    let totalAbsenteeism = 0;

    users.forEach(u => {
      const present = userPresent[u.email]
        ? userPresent[u.email].size
        : 0;

      const rate = workingDays > 0
        ? 1 - (present / workingDays)
        : 0;

      totalAbsenteeism += rate;

      // Department aggregation
      const dept = u.department || 'Unknown';

      if (!deptAbsenteeism[dept]) {
        deptAbsenteeism[dept] = {
          total: 0,
          count: 0
        };
      }

      deptAbsenteeism[dept].total += rate;
      deptAbsenteeism[dept].count += 1;
    });

    const avgAbsenteeism =
      users.length > 0
        ? (totalAbsenteeism / users.length) * 100
        : 0;

    // ---------------------------------------------------------
    // MONTHLY ABSENTEEISM
    // ---------------------------------------------------------
    const monthPresent = {};

    records.forEach(r => {
      if (!r.clock_in) return;

      const monthKey = r.clock_in
        .toISOString()
        .slice(0, 7); // YYYY-MM

      if (!monthPresent[monthKey]) {
        monthPresent[monthKey] = {};
      }

      const email = r.email;

      if (!monthPresent[monthKey][email]) {
        monthPresent[monthKey][email] = new Set();
      }

      monthPresent[monthKey][email].add(
        getNairobiDateKey(r.clock_in)
      );
    });

    const monthlyAbsData = Object.keys(monthPresent)
      .map(monthKey => {
        /*
         * monthKey is a STRING:
         * "2026-08"
         *
         * Convert it into an actual Date first.
         */
        const monthStart = new Date(
          `${monthKey}-01T00:00:00`
        );

        /*
         * First day of the NEXT month.
         *
         * IMPORTANT:
         * Do not use monthKey.getMonth()
         * because monthKey is a string.
         */
        const nextMonthStart = new Date(
          monthStart.getFullYear(),
          monthStart.getMonth() + 1,
          1
        );

        /*
         * Last day of the current month.
         */
        const monthEnd = new Date(
          nextMonthStart.getTime() - 1
        );

        /*
         * Respect the selected analytics date range.
         *
         * Example:
         * If the user selects Aug 10 - Aug 20,
         * don't calculate August using Aug 1 - Aug 31.
         */
        const effectiveStart =
          monthStart < start
            ? start
            : monthStart;

        const effectiveEnd =
          monthEnd > end
            ? end
            : monthEnd;

        const workingDaysMonth =
          effectiveStart <= effectiveEnd
            ? countWeekdays(
              effectiveStart,
              effectiveEnd
            )
            : 0;

        const emailsInMonth =
          Object.keys(monthPresent[monthKey]);

        let sum = 0;

        emailsInMonth.forEach(email => {
          const presentDays =
            monthPresent[monthKey][email].size;

          const rate =
            workingDaysMonth > 0
              ? 1 - (
                presentDays /
                workingDaysMonth
              )
              : 0;

          sum += rate;
        });

        const rate =
          emailsInMonth.length > 0
            ? (sum / emailsInMonth.length) * 100
            : 0;

        return {
          month: monthKey,
          rate: parseFloat(rate.toFixed(1))
        };
      })
      .sort((a, b) =>
        a.month.localeCompare(b.month)
      );

    // ---------------------------------------------------------
    // DEPARTMENT ABSENTEEISM
    // ---------------------------------------------------------
    const deptAbs = Object.keys(deptAbsenteeism)
      .map(dept => ({
        department: dept,
        rate: parseFloat(
          (
            (
              deptAbsenteeism[dept].total /
              deptAbsenteeism[dept].count
            ) * 100
          ).toFixed(1)
        )
      }));

    // ---------------------------------------------------------
    // RESPONSE
    // ---------------------------------------------------------
    res.json({
      averageAbsenteeismRate: parseFloat(
        avgAbsenteeism.toFixed(1)
      ),
      monthlyAbsenteeism: monthlyAbsData,
      departmentAbsenteeism: deptAbs
    });

  } catch (error) {
    console.error(
      'Absenteeism analytics error:',
      error
    );

    res.status(500).json({
      message: error.message
    });
  }
});


// department-level analytics
// GET /overall/attendance/analytics/departments
app.get(`${BASE_ROUTE}/overall/attendance/analytics/departments`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, station, department, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, { station, department, role, rank });
    const users = await User.find(userFilter, 'email department');
    const emails = users.map(u => u.email);
    const deptMap = {};
    users.forEach(u => deptMap[String(u.email || "").toLowerCase()] = u.department || "Unassigned");

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);

      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    }

    const [records, leaveRecords] = await Promise.all([
      Clocking.find({
        email: { $in: emails },
        clock_in: { $gte: start, $lte: end }
      }).lean(),
      Leave.find({
        email: { $in: emails },
        startDate: { $lte: end },
        endDate: { $gte: start },
      }).lean(),
    ]);

    const workingDateKeys = getWorkingDateKeysInRange(start, end);
    const workingDays = workingDateKeys.length;
    const deptStats = {};

    // Initialize departments from all users
    const allDepts = new Set(users.map(u => u.department || 'Unassigned'));
    allDepts.forEach(d => {
      deptStats[d] = {
        staffCount: 0,
        presentDays: new Set(),
        totalLate: 0,
      };
    });

    // Count staff per department
    users.forEach(u => {
      const dept = u.department || 'Unassigned';
      deptStats[dept].staffCount++;
    });

    // Process records
    records.forEach(r => {
      const email = String(r.email || "").toLowerCase();
      const dept = deptMap[email] || 'Unassigned';
      if (!deptStats[dept]) return;
      deptStats[dept].presentDays.add(`${email}:${getNairobiDateKey(r.clock_in)}`);
      if (r.isLate) deptStats[dept].totalLate++;
    });

    const leaveDaysByDept = countApprovedLeaveDaysByGroup(leaveRecords, deptMap, workingDateKeys);

    // Compute rates
    const result = Object.keys(deptStats).map(dept => {
      const staff = deptStats[dept].staffCount;
      const presentDays = deptStats[dept].presentDays.size;
      const onLeaveDays = leaveDaysByDept[dept] || 0;
      const maxPossibleDays = staff * workingDays;
      const absentDays = Math.max(maxPossibleDays - presentDays - onLeaveDays, 0);
      const attendanceRate = maxPossibleDays > 0 ? (presentDays / maxPossibleDays) * 100 : 0;
      const latenessRate = staff > 0 ? (deptStats[dept].totalLate / staff) : 0; // average late per staff
      const absenteeismRate = maxPossibleDays > 0 ? (absentDays / maxPossibleDays) * 100 : 0;
      return {
        department: dept,
        staffCount: staff,
        presentDays,
        absentDays,
        onLeaveDays,
        totalLateCount: deptStats[dept].totalLate,
        attendanceRate: parseFloat(attendanceRate.toFixed(1)),
        latenessRate: parseFloat(latenessRate.toFixed(1)),
        absenteeismRate: parseFloat(absenteeismRate.toFixed(1))
      };
    });

    res.json({ departments: result });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// station-level analytics
// GET /overall/attendance/analytics/stations
app.get(`${BASE_ROUTE}/overall/attendance/analytics/stations`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    // Build user filter – includes department if provided
    const userFilter = buildAnalyticsUserFilter(context, { department, station, role, rank });
    const users = await User.find(userFilter, 'email station department');
    const emailStationMap = {};
    users.forEach((user) => {
      emailStationMap[String(user.email || "").toLowerCase()] = user.station || "Unassigned";
    });

    // Group users by station
    const stationMap = {};
    users.forEach(u => {
      const st = u.station || 'Unassigned';
      if (!stationMap[st]) stationMap[st] = {
        staff: [],
        departments: new Set(),
        emails: []
      };
      stationMap[st].staff.push(u);
      stationMap[st].emails.push(String(u.email || "").toLowerCase());
      if (u.department) stationMap[st].departments.add(u.department);
    });

    const stationsList = Object.keys(stationMap);
    if (stationsList.length === 0) {
      return res.json({ stations: [] });
    }

    // Get all emails
    const allEmails = users.map(u => u.email);

    // Date range
    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);

      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    }

    // Fetch all clockings in range for these users
    const [records, leaveRecords] = await Promise.all([
      Clocking.find({
        email: { $in: allEmails },
        clock_in: { $gte: start, $lte: end }
      }).lean(),
      Leave.find({
        email: { $in: allEmails },
        startDate: { $lte: end },
        endDate: { $gte: start },
      }).lean(),
    ]);

    // Compute working days
    const workingDateKeys = getWorkingDateKeysInRange(start, end);
    const workingDays = workingDateKeys.length;

    // Per‑station aggregation
    const stationStats = {};

    stationsList.forEach(st => {
      stationStats[st] = {
        staffCount: stationMap[st].staff.length,
        departments: Array.from(stationMap[st].departments),
        totalHours: 0,
        totalOvertime: 0,
        lateCount: 0,
        presentDays: new Set(),
        employeeMetrics: {},
      };
      // Initialize per‑employee present days sets
      stationMap[st].emails.forEach(email => {
        if (email) stationStats[st].employeeMetrics[email] = new Set();
      });
    });

    // Process records
    records.forEach(r => {
      const email = String(r.email || "").toLowerCase();
      const st = emailStationMap[email] || 'Unassigned';
      if (!stationStats[st]) return; // should not happen, but guard

      const metric = stationStats[st];

      // Add present day
      const dateKey = getNairobiDateKey(r.clock_in);
      if (metric.employeeMetrics[email]) {
        metric.employeeMetrics[email].add(dateKey);
      }

      // Total hours
      if (r.clock_out) {
        const hours = (r.clock_out - r.clock_in) / (1000 * 60 * 60);
        metric.totalHours += hours;
        if (hours > 9) metric.totalOvertime += (hours - 9);
      }

      // Late count
      if (r.isLate) metric.lateCount++;
    });

    const leaveDaysByStation = countApprovedLeaveDaysByGroup(leaveRecords, emailStationMap, workingDateKeys);

    // Compute station-level rates
    const result = stationsList.map(st => {
      const stats = stationStats[st];
      const staffCount = stats.staffCount;
      const totalPresentDays = Object.values(stats.employeeMetrics).reduce((sum, set) => sum + set.size, 0);
      const maxPossibleDays = staffCount * workingDays;
      const onLeaveDays = leaveDaysByStation[st] || 0;
      const absentDays = Math.max(maxPossibleDays - totalPresentDays - onLeaveDays, 0);
      const attendanceRate = maxPossibleDays > 0 ? (totalPresentDays / maxPossibleDays) * 100 : 0;

      // Average hours per employee
      const avgHours = staffCount > 0 ? stats.totalHours / staffCount : 0;

      // Overtime per employee
      const avgOvertime = staffCount > 0 ? stats.totalOvertime / staffCount : 0;

      // Lateness rate: average late per employee
      const latenessRate = staffCount > 0 ? (stats.lateCount / staffCount) : 0;

      const absenteeismRate = maxPossibleDays > 0 ? (absentDays / maxPossibleDays) * 100 : 0;

      // Top performers (simplified: by total hours)
      const employeeHours = {};
      records.forEach(r => {
        const email = String(r.email || "").toLowerCase();
        if (emailStationMap[email] === st && r.clock_out) {
          const hours = (r.clock_out - r.clock_in) / (1000 * 60 * 60);
          employeeHours[email] = (employeeHours[email] || 0) + hours;
        }
      });
      const topPerformers = Object.keys(employeeHours)
        .map(email => ({ email, hours: employeeHours[email] }))
        .sort((a, b) => b.hours - a.hours)
        .slice(0, 5);

      return {
        station: st,
        staffCount,
        departments: stats.departments,
        presentDays: totalPresentDays,
        absentDays,
        onLeaveDays,
        attendanceRate: parseFloat(attendanceRate.toFixed(1)),
        latenessRate: parseFloat(latenessRate.toFixed(1)),
        absenteeismRate: parseFloat(absenteeismRate.toFixed(1)),
        averageWorkingHours: parseFloat(avgHours.toFixed(1)),
        averageOvertime: parseFloat(avgOvertime.toFixed(1)),
        totalHours: parseFloat(stats.totalHours.toFixed(1)),
        totalOvertime: parseFloat(stats.totalOvertime.toFixed(1)),
        totalLateCount: stats.lateCount,
        topPerformers
      };
    });

    res.json({ stations: result });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// compliance analytics
// GET /overall/attendance/analytics/compliance
app.get(`${BASE_ROUTE}/overall/attendance/analytics/compliance`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const { startDate, endDate, department, station, role, rank } = normalizeAnalyticsQuery(req.query);

    const userFilter = buildAnalyticsUserFilter(context, { department, station, role, rank });
    const users = await User.find(userFilter, 'email');
    const emails = users.map(u => u.email);

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);

      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    }

    // Find all clockings in range
    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: start, $lte: end }
    });

    // For each day, check if user clocked in and out
    const missingClockIns = [];
    const missingClockOuts = [];

    // Group by day and email
    const dailyMap = {};
    records.forEach(r => {
      const dateKey = getNairobiDateKey(r.clock_in);
      const email = r.email;
      const key = `${dateKey}|${email}`;
      if (!dailyMap[key]) dailyMap[key] = { clockIn: false, clockOut: false };
      dailyMap[key].clockIn = true;
      if (r.clock_out) dailyMap[key].clockOut = true;
    });

    // For each working day in range, check all employees
    let current = new Date(start);
    while (current <= end) {
      const currentDay = getNairobiWeekdayIndex(current);
      if (currentDay !== 0 && currentDay !== 6) {
        const dateKey = getNairobiDateKey(current);
        emails.forEach(email => {
          const key = `${dateKey}|${email}`;
          if (!dailyMap[key]) {
            missingClockIns.push({ email, date: dateKey });
          } else if (!dailyMap[key].clockOut) {
            missingClockOuts.push({ email, date: dateKey });
          }
        });
      }
      current.setDate(current.getDate() + 1);
    }

    res.json({
      missingClockIns: missingClockIns.slice(0, 50),
      missingClockOuts: missingClockOuts.slice(0, 50),
      totalMissingClockIns: missingClockIns.length,
      totalMissingClockOuts: missingClockOuts.length
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




app.get(`${BASE_ROUTE}/overall/attendance/analytics/outside-clocking`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const payload = await buildAnalyticsView("outside-clocking", context, normalizeAnalyticsQuery(req.query));
    res.status(200).json(payload);
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message || "Unable to load analytics" });
  }
});

app.get(`${BASE_ROUTE}/overall/attendance/analytics/workforce`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const payload = await buildAnalyticsView("workforce", context, normalizeAnalyticsQuery(req.query));
    res.status(200).json(payload);
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message || "Unable to load analytics" });
  }
});

app.get(`${BASE_ROUTE}/overall/attendance/analytics/productivity`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const payload = await buildAnalyticsView("productivity", context, normalizeAnalyticsQuery(req.query));
    res.status(200).json(payload);
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message || "Unable to load analytics" });
  }
});

app.get(`${BASE_ROUTE}/overall/attendance/analytics/executive`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);
    const payload = await buildAnalyticsView("executive", context, normalizeAnalyticsQuery(req.query));
    res.status(200).json(payload);
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message || "Unable to load analytics" });
  }
});



// ADMIN, SUPERVISOR,CEO,HR LEVEL overall org stats

// Admin Overall Stats
app.get(`${BASE_ROUTE}/overall/attendance/stats`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);

    // get the query
    const {
      station,
      department,
      role,
      rank,
    } = normalizeAnalyticsQuery(req.query);

    // get config for stations and depart from platform config
    const config = await PlatformConfig.getSingleton();

    const now = new Date();
    const startOfMonth = getNairobiMonthStart(now);

    const workingDaysSoFar = Math.max(countWeekdays(startOfMonth, now), 1);

    const userFilter = buildAnalyticsUserFilter(context, {
      station,
      department,
      role,
      rank,
    });

    const allUsers = await User.find(
      userFilter,
      "email name department station isAccountActive role"
    ).lean();

    const emails = allUsers.map((u) => u.email);

    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: startOfMonth, $lte: now },
    }).lean();

    const totalStaff = allUsers.length;



    const stats = {
      orgTotalHours: 0,
      orgTotalOvertime: 0,
      stations: {},
      employeeMetrics: {},
      employeesWithRecords: new Set(),
      inactiveUsers: allUsers.filter(u => !u.isAccountActive).length
    };

    const normalizeEmailKey = (email) => String(email || "").trim().toLowerCase();
    const userByEmail = new Map(allUsers.map((user) => [normalizeEmailKey(user.email), user]));

    const ensureStationStats = (stationName) => {
      const key = stationName || "Unassigned";
      if (!stats.stations[key]) {
        stats.stations[key] = {
          totalHours: 0,
          totalOvertime: 0,
          totalCheckins: 0,
          lateCount: 0,
          staffSet: new Set(),
          departments: {},
          employeeScores: []
        };
      }
      return stats.stations[key];
    };

    const ensureDepartmentStats = (stationObj, departmentName) => {
      const key = departmentName || "Unassigned";
      if (!stationObj.departments[key]) {
        stationObj.departments[key] = {
          totalHours: 0,
          totalOvertime: 0,
          lateCount: 0,
          staffSet: new Set(),
          employeeScores: []
        };
      }
      return stationObj.departments[key];
    };

    allUsers.forEach((user) => {
      const email = normalizeEmailKey(user.email);
      if (!email) return;

      const stationName = user.station || "Unassigned";
      const departmentName = user.department || "Unassigned";
      const stationObj = ensureStationStats(stationName);
      const deptObj = ensureDepartmentStats(stationObj, departmentName);

      stationObj.staffSet.add(email);
      deptObj.staffSet.add(email);

      stats.employeeMetrics[email] = {
        hours: 0,
        overtime: 0,
        lateCount: 0,
        earlyCount: 0,
        daysPresent: new Set()
      };
    });

    // -----------------------------------
    // PROCESS RECORDS
    // -----------------------------------

    records.forEach(rec => {
      const email = normalizeEmailKey(rec.email);
      const user = userByEmail.get(email);
      if (!email || !user || !stats.employeeMetrics[email]) return;

      const station = user.station || rec.station || "Unassigned";
      const department = user.department || rec.department || "Unassigned";
      stats.employeesWithRecords.add(email);

      let hoursWorked = 0;

      if (rec.clock_out) {
        hoursWorked =
          (rec.clock_out - rec.clock_in) / (1000 * 60 * 60);

        stats.employeeMetrics[email].hours += hoursWorked;

        if (hoursWorked > 9) {
          stats.employeeMetrics[email].overtime += hoursWorked - 9;
        }

        stats.employeeMetrics[email].daysPresent.add(
          getNairobiDateKey(rec.clock_in)
        );
      }

      if (rec.isLate) stats.employeeMetrics[email].lateCount++;
      else stats.employeeMetrics[email].earlyCount++;

      // -----------------------------------
      // STATION INIT
      // -----------------------------------

      const stationObj = ensureStationStats(station);

      stationObj.totalHours += hoursWorked;
      stationObj.totalCheckins++;
      stationObj.staffSet.add(email);
      if (rec.isLate) stationObj.lateCount++;

      if (hoursWorked > 9) {
        stationObj.totalOvertime += hoursWorked - 9;
      }

      // -----------------------------------
      // DEPARTMENT INIT
      // -----------------------------------

      const deptObj = ensureDepartmentStats(stationObj, department);

      deptObj.totalHours += hoursWorked;
      deptObj.staffSet.add(email);
      if (rec.isLate) deptObj.lateCount++;

      if (hoursWorked > 9) {
        deptObj.totalOvertime += hoursWorked - 9;
      }
    });



    // -----------------------------------
    // BUILD EMPLOYEE SCORES
    // -----------------------------------

    const employeeScores = [];

    Object.entries(stats.employeeMetrics).forEach(([email, data]) => {

      const attendanceRate =
        (data.daysPresent.size / workingDaysSoFar) * 100;

      const productivityScore =
        (data.hours * 0.6) +
        (data.earlyCount * 2) -
        (data.lateCount * 1.5) +
        (data.overtime * 0.5);

      let burnoutLevel = "Low";
      if (data.overtime > 20) burnoutLevel = "High";
      else if (data.overtime > 10) burnoutLevel = "Moderate";

      stats.orgTotalHours += data.hours;
      stats.orgTotalOvertime += data.overtime;

      employeeScores.push({
        email,
        hours: data.hours.toFixed(1),
        overtime: data.overtime.toFixed(1),
        attendanceRate: attendanceRate.toFixed(1) + "%",
        burnoutLevel,
        score: productivityScore
      });

      // assign to station & department
      const user = userByEmail.get(email);
      if (!user) return;

      const station = user.station || "Unassigned";
      const department = user.department || "Unassigned";

      if (stats.stations[station]) {
        stats.stations[station].employeeScores.push({
          email,
          score: productivityScore
        });

        if (stats.stations[station].departments[department]) {
          stats.stations[station].departments[department].employeeScores.push({
            email,
            score: productivityScore
          });
        }
      }
    });

    // -----------------------------------
    // FINALIZE STATION & DEPT METRICS
    // -----------------------------------

    Object.values(stats.stations).forEach(station => {

      station.headcount = station.staffSet.size;
      station.averageHoursPerStaff =
        station.headcount > 0
          ? (station.totalHours / station.headcount).toFixed(1)
          : 0;

      station.efficiencyScore =
        ((station.totalHours / (station.headcount * 160)) * 100).toFixed(1) + "%";

      station.disciplineRate =
        station.totalCheckins > 0
          ? ((station.lateCount / station.totalCheckins) * 100).toFixed(1) + "%"
          : "0.0%";

      station.topPerformers =
        station.employeeScores
          .sort((a, b) => b.score - a.score)
          .slice(0, 5);

      delete station.staffSet;
      delete station.employeeScores;

      Object.values(station.departments).forEach(dept => {

        dept.headcount = dept.staffSet.size;
        dept.averageHoursPerStaff =
          dept.headcount > 0
            ? (dept.totalHours / dept.headcount).toFixed(1)
            : 0;

        dept.overworked =
          dept.averageHoursPerStaff > 160 ? true : false;

        dept.disciplineRate =
          dept.headcount > 0
            ? ((dept.lateCount / dept.headcount) * 100).toFixed(1) + "%"
            : "0.0%";

        dept.topPerformers =
          dept.employeeScores
            .sort((a, b) => b.score - a.score)
            .slice(0, 5);

        delete dept.staffSet;
        delete dept.employeeScores;
      });
    });

    // -----------------------------------
    // FINAL RESPONSE
    // -----------------------------------
    res.status(200).json({
      overview: {
        totalStaff,
        activeStaffThisMonth: stats.employeesWithRecords.size,
        inactiveAccounts: stats.inactiveUsers,
        totalOrgHours: stats.orgTotalHours.toFixed(1),
        totalOrgOvertime: stats.orgTotalOvertime.toFixed(1),
        averageStaffEfficiency:
          totalStaff > 0
            ? ((stats.orgTotalHours / (totalStaff * 160)) * 100).toFixed(1) + "%"
            : "0.0%"
      },
      topPerformersOverall:
        employeeScores
          .sort((a, b) => b.score - a.score)
          .slice(0, 5),
      stations: stats.stations,
      filters: {
        stations: config.stations
          .filter(s => s.active)
          .map(s => s.name),

        departments: config.departments
      },

    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// biometric analytics
// GET /overall/attendance/analytics/biometric
app.get(`${BASE_ROUTE}/overall/attendance/analytics/biometric`, async (req, res) => {
  try {
    // --- 1. Admin-only access ---
    const context = await getAnalyticsContext(req);
    if (!['admin', 'superadmin'].includes(context.user?.rank)) {
      return res.status(403).json({ message: 'Admin access required' });
    }

    // --- 2. Date range (optional) – filters users & devices by creation ---
    const { startDate, endDate } = normalizeAnalyticsQuery(req.query);
    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate || new Date(0), endDate || new Date());
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    // --- 3. Biometric enrollment stats from User ---
    const usersWithBiometric = await User.countDocuments({
      doneBiometric: true,
      createdAt: { $gte: start, $lte: end }
    });

    // --- 4. Authenticators & successful verifications ---
    // Unwind the authenticators array to count credentials and sum counters
    const [authAgg] = await User.aggregate([
      { $match: { createdAt: { $gte: start, $lte: end } } },
      { $project: { authenticators: 1 } },
      { $unwind: { path: '$authenticators', preserveNullAndEmptyArrays: false } },
      {
        $group: {
          _id: null,
          totalAuthenticators: { $sum: 1 },
          totalSuccessfulVerifications: { $sum: '$authenticators.counter' }
        }
      }
    ]);

    const totalAuthenticators = authAgg?.totalAuthenticators || 0;
    const totalSuccessfulVerifications = authAgg?.totalSuccessfulVerifications || 0;

    // --- 5. Device stats ---
    const totalDevices = await Devices.countDocuments({
      createdAt: { $gte: start, $lte: end }
    });

    // Active = updated in the last 7 days
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const activeDevices = await Devices.countDocuments({
      updatedAt: { $gte: sevenDaysAgo },
      createdAt: { $gte: start, $lte: end }
    });

    const inactiveDevices = totalDevices - activeDevices;

    // Average offline minutes for inactive devices
    let avgOfflineMinutes = 0;
    if (inactiveDevices > 0) {
      const inactiveDocs = await Devices.find(
        {
          updatedAt: { $lt: sevenDaysAgo },
          createdAt: { $gte: start, $lte: end }
        },
        'updatedAt'
      );
      const totalOfflineMs = inactiveDocs.reduce((sum, d) => sum + (Date.now() - d.updatedAt.getTime()), 0);
      avgOfflineMinutes = totalOfflineMs / inactiveDocs.length / (1000 * 60);
    }

    const uptime = totalDevices > 0 ? (activeDevices / totalDevices) * 100 : 0;

    // --- 6. Lost devices (from Device collection) ---
    const lostDevices = await Devices.countDocuments({
      device_lost: true,
      createdAt: { $gte: start, $lte: end }
    });

    // --- 7. Users who reported a lost device ---
    const usersWithLostDevice = await User.countDocuments({
      deviceLost: true,
      createdAt: { $gte: start, $lte: end }
    });

    // --- 8. Primary devices ---
    const primaryDevices = await Devices.countDocuments({
      device_primary: true,
      createdAt: { $gte: start, $lte: end }
    });

    // --- 9. OS & Browser distribution (for extra insight) ---
    const osDistribution = await Devices.aggregate([
      { $match: { createdAt: { $gte: start, $lte: end } } },
      { $group: { _id: '$device_os', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const browserDistribution = await Devices.aggregate([
      { $match: { createdAt: { $gte: start, $lte: end } } },
      { $group: { _id: '$device_browser', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    // --- 10. Enrollment rate (users with biometric / total users) ---
    const totalUsers = await User.countDocuments({
      createdAt: { $gte: start, $lte: end }
    });
    const enrollmentRate = totalUsers > 0 ? (usersWithBiometric / totalUsers) * 100 : 0;

    // --- 11. Response ---
    res.json({
      // Biometric enrollment
      usersWithBiometric,
      totalAuthenticators,
      totalSuccessfulVerifications,
      enrollmentRate: parseFloat(enrollmentRate.toFixed(1)),

      // Device uptime / activity
      totalDevices,
      activeDevices,
      inactiveDevices,
      deviceUptime: parseFloat(uptime.toFixed(1)),
      deviceOfflineDuration: Math.round(avgOfflineMinutes), // minutes

      // Lost / primary devices
      lostDevices,
      usersWithLostDevice,
      primaryDevices,

      // Distributions
      osDistribution,
      browserDistribution,
    });
  } catch (error) {
    console.error('Biometric analytics error:', error);
    res.status(500).json({ message: error.message });
  }
});



// ============================================================================
// ADMIN - ATTENDANCE RECORDS
// ============================================================================

app.get(`${BASE_ROUTE}/overall/attendance/records`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);

    const {
      station,
      department,
      role,
      rank,
      startDate,
      endDate,
    } = normalizeAnalyticsQuery(req.query);

    //----------------------------------------------------
    // Attendance Query
    //----------------------------------------------------

    const attendanceQuery = {};

    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);
      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    attendanceQuery.clock_in = {
      $gte: start,
      $lte: end
    };

    //----------------------------------------------------
    // User Query
    //----------------------------------------------------

    const userQuery = buildAnalyticsUserFilter(context, {
      role,
      rank,
      station,
      department,
    });

    const users = await User.find(
      userQuery,
      `
      email
      employeeId
      role
      rank
      name
      department
      station
      `
    ).lean();

    const userLookup = {};

    users.forEach((user) => {
      userLookup[user.email] = user;
    });

    attendanceQuery.email = {
      $in: users.map((u) => u.email)
    };

    //----------------------------------------------------
    // Fetch Attendance Records
    //----------------------------------------------------

    const records = await Clocking.find(attendanceQuery)
      .sort({ name: 1, clock_in: -1 })
      .lean();

    //----------------------------------------------------
    // Merge User Details
    //----------------------------------------------------

    const mergedRecords = records.map((record) => {

      const user = userLookup[record.email] || {};

      return {

        ...record,

        employeeId: user.employeeId || "",

        role: user.role || "",
        rank: user.rank || "",

        name: user.name || record.name,

        department:
          user.department || record.department,

        station:
          user.station || record.station

      };

    })

    res.status(200).json(mergedRecords);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: error.message
    });

  }
});


// ============================================================================
// ADMIN - MONTHLY / DATE RANGE ATTENDANCE SUMMARY
// ============================================================================

app.get(`${BASE_ROUTE}/overall/attendance/summary`, async (req, res) => {
  try {
    const context = await getAnalyticsContext(req);

    const {
      startDate,
      endDate,
      station,
      department,
      role,
      rank,
    } = normalizeAnalyticsQuery(req.query);

    //---------------------------------------------------------
    // Date Range
    //---------------------------------------------------------
    let start;
    let end;

    try {
      const range = getSafeDateRange(startDate, endDate);

      start = range.start;
      end = range.end;
    } catch (dateError) {
      return res.status(400).json({
        message: dateError.message,
      });
    }

    //---------------------------------------------------------
    // Working Days
    //---------------------------------------------------------

    const workingDates = [];

    const current = new Date(start);

    while (current <= end) {

      if (
        !isWeekend(current) &&
        !isPublicHoliday(current)
      ) {
        workingDates.push(
          getNairobiDateKey(current)
        );
      }

      current.setDate(current.getDate() + 1);
    }

    const totalWorkingDays = workingDates.length;

    //---------------------------------------------------------
    // User Filters
    //---------------------------------------------------------

    const userQuery = buildAnalyticsUserFilter(context, {
      station,
      department,
      role,
      rank,
    });

    //---------------------------------------------------------
    // Users
    //---------------------------------------------------------

    const users = await User.find(
      userQuery,
      `
      name
      email
      employeeId
      role
      rank
      station
      department
      `
    ).lean().sort({ name: 1, clock_in: -1 });

    //---------------------------------------------------------
    // Attendance Records
    //---------------------------------------------------------

    const attendanceRecords = await Clocking.find({

      email: {
        $in: users.map(u => u.email)
      },

      clock_in: {
        $gte: start,
        $lte: end
      }

    }).lean();

    //---------------------------------------------------------
    // Present Days
    //---------------------------------------------------------

    const attendanceMap = {};

    attendanceRecords.forEach(record => {

      if (!attendanceMap[record.email]) {
        attendanceMap[record.email] = new Set();
      }

      const dateKey = getNairobiDateKey(record.clock_in);

      if (!workingDates.includes(dateKey))
        return;

      attendanceMap[record.email].add(dateKey);

    });

    //---------------------------------------------------------
    // Summary
    //---------------------------------------------------------

    const summary = users.map(user => {

      // attendance rate
      const presentDays =
        attendanceMap[user.email]
          ? attendanceMap[user.email].size
          : 0;





      return {

        employeeId: user.employeeId || "",

        name: user.name || "",

        role: user.role || "",
        rank: user.rank || "",

        station: user.station || "",

        department: user.department || "",

        daysPresent: presentDays,

        daysAbsent: Math.max(
          totalWorkingDays - presentDays,
          0
        ),
      };

    });

    //---------------------------------------------------------

    return res.status(200).json(summary);

  } catch (error) {

    console.error(error);

    return res.status(500).json({
      message: error.message,
    });

  }
});



// departmental stats
app.get(`${BASE_ROUTE}/supervisor/department/stats`, async (req, res) => {
  try {
    if (!req.session?.isOnline)
      return res.status(401).json({ message: "Unauthorized Access" });

    const currentSupervisor = await User.findById(req.session.userID);
    if (!currentSupervisor)
      return res.status(404).json({ message: "User not found" });

    if (!["supervisor", "superadmin"].includes(currentSupervisor.rank))
      return res.status(403).json({
        message: "Unauthorized Access",
      });

    // A supervisor only ever sees the records of their own station, for
    // their own department. Supervisors of another station cannot view
    // records of other stations even if they share the same department.
    const department = currentSupervisor.department;
    const station = currentSupervisor.station;

    const dateKey = getNairobiDateKey;
    const hourDecimal = getNairobiHourDecimal;
    const hourLabel = (value) => {
      if (value == null || Number.isNaN(value)) return "—";
      const h = Math.floor(value);
      const m = Math.round((value - h) * 60);
      return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
    };

    // -----------------------------------
    // FETCH STAFF (scoped to supervisor's own department + station)
    // -----------------------------------
    const staff = await User.find(
      { department, station },
      "email name department station isAccountActive role isOnLeave hasClockedIn isToClockOut canClockOutside outsideClockingDetails"
    ).lean();

    if (!staff.length)
      return res.status(404).json({
        message: "No staff found in this department",
      });

    const emails = staff.map((u) => u.email);

    const now = new Date();
    const startOfMonth = getNairobiMonthStart(now);
    const workingDaysSoFar = countWeekdays(startOfMonth, now);
    const todayKey = dateKey(now);

    // -----------------------------------
    // FETCH CLOCKING RECORDS (already implicitly scoped to this station,
    // since every email in `emails` belongs to it)
    // -----------------------------------
    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: startOfMonth },
    }).lean();

    const deptStats = {
      totalHours: 0,
      totalOvertime: 0,
      lateCount: 0,
      employeeMetrics: [],
    };

    const metricsMap = {};
    const dailyMap = {};
    const employeesWithRecords = new Set();
    let outsideClockingCount = 0;
    let outsideClockingStaff = new Set();
    let completedSessions = 0;
    let totalClockInHour = 0;
    let totalClockOutHour = 0;
    let totalPresentDays = 0;
    let halfDayCount = 0;

    staff.forEach((u) => {
      metricsMap[u.email] = {
        name: u.name,
        email: u.email,
        station: u.station,
        role: u.role,
        isAccountActive: u.isAccountActive,
        isOnLeave: u.isOnLeave,
        hasClockedIn: u.hasClockedIn,
        canClockOutside: u.canClockOutside,
        outsideClockingDetails: u.outsideClockingDetails,
        hours: 0,
        overtime: 0,
        lateCount: 0,
        outsideClockingCount: 0,
        openSessions: 0,
        presentCount: 0,
        halfDayCount: 0,
        daysPresent: new Set(),
      };
    });

    // -----------------------------------
    // PROCESS RECORDS
    // -----------------------------------
    records.forEach((rec) => {
      const metric = metricsMap[rec.email];
      if (!metric) return;

      let hoursWorked = 0;
      const key = dateKey(rec.clock_in);
      employeesWithRecords.add(rec.email);

      if (!dailyMap[key]) {
        dailyMap[key] = {
          date: key,
          clockIns: 0,
          clockOuts: 0,
          present: 0,
          halfDays: 0,
          late: 0,
          outsideClocking: 0,
        };
      }

      dailyMap[key].clockIns++;
      totalClockInHour += hourDecimal(rec.clock_in);

      if (rec.clock_out) {
        hoursWorked = (rec.clock_out - rec.clock_in) / (1000 * 60 * 60);

        metric.hours += hoursWorked;
        dailyMap[key].clockOuts++;
        completedSessions++;
        totalClockOutHour += hourDecimal(rec.clock_out);

        if (hoursWorked > 9) metric.overtime += hoursWorked - 9;

        metric.daysPresent.add(getNairobiDateKey(rec.clock_in));

        if (rec.isPresent) {
          metric.presentCount++;
          dailyMap[key].present++;
          totalPresentDays++;
        } else {
          metric.halfDayCount++;
          dailyMap[key].halfDays++;
          halfDayCount++;
        }
      } else {
        metric.openSessions++;
      }

      if (rec.isLate) {
        metric.lateCount++;
        dailyMap[key].late++;
      }

      if (rec.clockedOutSide || rec.outsideLocation) {
        metric.outsideClockingCount++;
        dailyMap[key].outsideClocking++;
        outsideClockingCount++;
        outsideClockingStaff.add(rec.email);
      }
    });

    // -----------------------------------
    // BUILD EMPLOYEE METRICS
    // -----------------------------------
    Object.values(metricsMap).forEach((m) => {
      deptStats.totalHours += m.hours;
      deptStats.totalOvertime += m.overtime;
      deptStats.lateCount += m.lateCount;

      const attendanceRate = (m.daysPresent.size / workingDaysSoFar) * 100;

      const productivityScore =
        m.hours * 0.6 + m.overtime * 0.5 - m.lateCount * 1.5;

      let burnoutLevel = "Low";
      if (m.overtime > 20) burnoutLevel = "High";
      else if (m.overtime > 10) burnoutLevel = "Moderate";

      deptStats.employeeMetrics.push({
        name: m.name,
        email: m.email,
        station: m.station,
        role: m.role,
        isAccountActive: m.isAccountActive,
        isOnLeave: m.isOnLeave,
        hasClockedIn: m.hasClockedIn,
        canClockOutside: m.canClockOutside,
        hours: m.hours.toFixed(1),
        overtime: m.overtime.toFixed(1),
        lateCount: m.lateCount,
        outsideClockingCount: m.outsideClockingCount,
        openSessions: m.openSessions,
        presentCount: m.presentCount,
        halfDayCount: m.halfDayCount,
        daysPresent: m.daysPresent.size,
        attendanceRate: attendanceRate.toFixed(1) + "%",
        productivityScore,
        burnoutLevel,
      });
    });

    // -----------------------------------
    // SORT + TOP PERFORMERS
    // -----------------------------------
    const sortedEmployees = [...deptStats.employeeMetrics].sort(
      (a, b) => b.productivityScore - a.productivityScore
    );

    const topPerformers = sortedEmployees.slice(0, 4);

    const burnoutCounts = {
      Low: deptStats.employeeMetrics.filter((e) => e.burnoutLevel === "Low").length,
      Moderate: deptStats.employeeMetrics.filter((e) => e.burnoutLevel === "Moderate").length,
      High: deptStats.employeeMetrics.filter((e) => e.burnoutLevel === "High").length,
    };

    // -----------------------------------
    // RESPONSE
    // -----------------------------------
    res.json({
      department,
      station, // NEW — lets the UI/PDF confirm this is a single-station view
      totalStaff: staff.length,
      activeStaffThisMonth: employeesWithRecords.size,
      inactiveStaffThisMonth: staff.length - employeesWithRecords.size,
      onLeaveCount: staff.filter((u) => u.isOnLeave).length,
      clockedInNow: staff.filter((u) => u.hasClockedIn && u.isToClockOut).length,
      outsideAuthorizedCount: staff.filter((u) => u.canClockOutside).length,
      totalHours: deptStats.totalHours.toFixed(1),
      totalOvertime: deptStats.totalOvertime.toFixed(1),
      totalLateCount: deptStats.lateCount,
      outsideClockingCount,
      outsideClockingStaffCount: outsideClockingStaff.size,
      presentDays: totalPresentDays,
      halfDays: halfDayCount,
      burnoutCounts, // NEW — powers the burnout distribution chart
      avgClockIn: hourLabel(records.length ? totalClockInHour / records.length : null),
      avgClockOut: hourLabel(completedSessions ? totalClockOutHour / completedSessions : null),
      today: {
        clockIns: dailyMap[todayKey]?.clockIns || 0,
        clockOuts: dailyMap[todayKey]?.clockOuts || 0,
        present: dailyMap[todayKey]?.present || 0,
        late: dailyMap[todayKey]?.late || 0,
        outsideClocking: dailyMap[todayKey]?.outsideClocking || 0,
      },
      // NOTE: dailyTrend and per-station breakdowns were removed — a
      // supervisor only ever sees one station, so grouping by station
      // was dead weight, and the daily-trend chart was never rendered.
      topPerformers,
      employeeMetrics: sortedEmployees,
    });
  } catch (error) {
    console.error("Department stats error:", error);
    res.status(500).json({ message: "Server error" });
  }
});






// DEVICE LOST 
app.post(`${BASE_ROUTE}/device/lost/request`, async (req, res) => {

  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const { description, startDate, endDate, device_fingerprint } = req.body;

    if (!description || !startDate || !endDate)
      throw new Error("All fields are required");


    // fetch recent clocking document of the user then pick the station from it
    const latestStation = await Clocking.findOne({ email: user.email })
      .sort({ clock_in: -1 })
      .select("station")
      .lean();

    // for saving in the admin message notifications
    const title = "Lost My Device"
    const name = user.name
    const phone = user.phone
    const email = user.email
    const department = user.department
    const role = user.role
    // Check if station exists and extract the value
    const stationName = latestStation?.station;

    // 2. Format Role (Capitalize first letter)
    const formattedRole = role.charAt(0).toUpperCase() + role.slice(1);


    const message = `Hello Admin Team, ${formattedRole} ${name} (Phone: ${phone} and Email: ${email}) from ${stationName} - ${department} department has reported a lost device. 
Please navigate to the lost device section to review this case and resolve the issue by deregistering the stolen device from the system for security reasons.`;

    const userDevices = await Devices.find({ user_email: user.email })

    const existingPending = await DeviceLost.findOne({
      user_email: user.email,
      status: "pending",
      device_fingerprint
    });

    if (existingPending)
      throw new Error("You already have a pending request");

    const reportedDevice = userDevices.find(
      (device) => device.device_fingerprint === device_fingerprint
    );
    if (!reportedDevice) {
      throw new Error("Selected device is not enrolled on your profile.");
    }

    const lostRequest = await DeviceLost.create({
      description,
      user_email: user.email,
      startDate,
      endDate,
      device_fingerprint
    });


    // send message/notification to the admin+hr+supervisor
    await MessageAdmin.create({
      title,
      message,
      label: "urgent",
      status: 'pending',
      user_email: email,
      device_fingerprint
    })


    // Mark user as having an open lost-device report. Access is changed only after approval.
    user.deviceLost = true;
    await user.save();

    await createAuditLog({
      req,
      category: "device",
      action: "device.lost_reported",
      description: "User reported a lost device",
      actor: user,
      metadata: {
        startDate,
        endDate,
        deviceFingerprint: device_fingerprint,
        latestStation: stationName || "",
      },
    });


    res.json({
      message: "Lost device request submitted",
      data: lostRequest
    });

  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// view all lost devices
app.get(`${BASE_ROUTE}/device/lost/all`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    if (!["admin", "hr", "superadmin"].includes(user.rank))
      return res.status(403).json({ message: "Access denied" });

    const requests = await DeviceLost.find()
      .sort({ createdAt: -1 });

    res.json(requests);

  } catch (err) {
    console.error("Fetch lost requests error:", err);
    res.status(400).json({ message: err.message });
  }
});



//  respond to the lost device

app.post(`${BASE_ROUTE}/device/lost/respond`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const responder = await User.findById(req.session.userID);
    if (!responder) throw new Error("User not found");

    if (!["admin", "hr", "superadmin"].includes(responder.rank))
      return res.status(403).json({ message: "Access denied" });

    const { requestId, action } = req.body;

    if (!["granted", "rejected", "success"].includes(action))
      throw new Error("Invalid action");

    const request = await DeviceLost.findById(requestId);
    if (!request) throw new Error("Request not found");

    if (request.status !== "pending")
      throw new Error("Request already processed");

    request.status = action;
    request.responded = responder.rank;
    await request.save();

    const affectedUser = await User.findOne({ email: request.user_email });
    if (!affectedUser) throw new Error("User not found");

    if (action === "granted" || action === "success") {
      const reportedDevice = await Devices.findOne({
        user_email: affectedUser.email,
        device_fingerprint: request.device_fingerprint,
      });

      await Devices.deleteOne({
        user_email: affectedUser.email,
        device_fingerprint: request.device_fingerprint,
      });

      const authenticators = getUserAuthenticators(affectedUser).filter(
        (authenticator) =>
          authenticator.deviceFingerprint !== request.device_fingerprint &&
          !(reportedDevice?.device_primary && !authenticator.deviceFingerprint)
      );
      affectedUser.authenticators = authenticators;
      affectedUser.authenticator = undefined;
      affectedUser.deviceLost = false;

      await ensureSinglePrimaryDevice(affectedUser.email);
      await syncUserDeviceFlags(affectedUser);
    } else {
      affectedUser.deviceLost = false;
      await affectedUser.save();
    }

    // update the admin message
    const messageAdmin = await MessageAdmin.findOne({ device_fingerprint: request.device_fingerprint })
    if (messageAdmin) {
      messageAdmin.status = action
      messageAdmin.responded = responder.rank
      messageAdmin.respondedName = responder.name
      await messageAdmin.save()
    }

    const message = generateAdminResponse(affectedUser, responder, action)

    // send message notification to the user (specific email)
    await MessageUser.create({
      label: 'none',
      message,
      title: "Lost Device Request",
      status: action,
      user_email: affectedUser.email
    })

    await createAuditLog({
      req,
      category: "device",
      action: "device.lost_request_responded",
      description: "Lost device request reviewed",
      actor: responder,
      target: affectedUser,
      metadata: {
        requestId: request._id.toString(),
        response: action,
        deviceFingerprint: request.device_fingerprint,
      },
    });

    res.json({
      message: `Request ${action} successfully`,
      data: request
    });

  } catch (err) {
    console.error("Respond lost device error:", err);
    res.status(400).json({ message: err.message });
  }
});



// add device
app.post(`${BASE_ROUTE}/device/add`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const { device_name, device_os, device_browser, device_fingerprint } = req.body;


    if (!device_fingerprint || !device_os || !device_browser || !device_name) {
      throw new Error('Something went wrong!')
    }


    const existingDevice = await Devices.findOne({
      device_fingerprint
    });


    if (existingDevice)
      throw new Error("device alreday registered in the system!");

    const newDevice = await Devices.create({
      device_name,
      user_email: user.email,
      device_os,
      device_browser,
      device_primary: true,
      device_lost: false,
      device_fingerprint
    });

    // list devices linked to the email, if two or more then user has multiple devices
    const currentUserDevices = await Devices.find({
      user_email: user.email
    }).sort({ createdAt: -1 });

    // user has mu
    if (currentUserDevices.length > 1) {
      user.hasDevices = true;
      await user.save();
    }

    res.json({
      message: "New device added successfully",
      data: newDevice
    });

  } catch (err) {
    console.error("Add device error:", err);
    res.status(400).json({ message: err.message });
  }
});


// get user devices
app.get(`${BASE_ROUTE}/device/my-devices`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const devices = await Devices.find({
      user_email: user.email
    }).sort({ createdAt: -1 });

    res.json(devices);

  } catch (err) {
    console.error("Fetch devices error:", err);
    res.status(400).json({ message: err.message });
  }
});



// get my lost device requests
app.get(`${BASE_ROUTE}/device/lost/my-requests`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const requests = await DeviceLost.find({
      user_email: user.email
    }).sort({ createdAt: -1 });

    res.json(requests);

  } catch (err) {
    console.error("Fetch my lost requests error:", err);
    res.status(400).json({ message: err.message });
  }
});


// remove device
app.delete(`${BASE_ROUTE}/device/remove/:deviceId`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { deviceId } = req.params;
    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    // Find device and verify it belongs to the user
    const device = await Devices.findById(deviceId);
    if (!device)
      return res.status(404).json({ message: "Device not found" });

    if (device.user_email !== user.email)
      return res.status(403).json({ message: "You can only remove your own devices" });

    // Prevent removal of primary device
    if (device.device_primary)
      return res.status(400).json({ message: "Cannot remove your primary device" });

    // Store device info for audit log
    const deviceInfo = `${device.device_name} (${device.device_os} - ${device.device_browser})`;

    // Delete the device
    await Devices.findByIdAndDelete(deviceId);

    // Remove associated biometric authenticator from user
    if (device.device_fingerprint && user.authenticators) {
      user.authenticators = user.authenticators.filter(
        auth => auth.deviceFingerprint !== device.device_fingerprint
      );
      await user.save();
    }

    // Sync device flags after removal
    await syncUserDeviceFlags(user);

    // Create audit log
    await createAuditLog({
      req,
      category: 'device',
      action: 'device_removed',
      description: `User removed device: ${deviceInfo}`,
      actor: snapshotUser(user),
      target: null,
      metadata: {
        deviceName: device.device_name,
        deviceOS: device.device_os,
        deviceBrowser: device.device_browser,
        deviceFingerprint: device.device_fingerprint,
      },
      status: 'success',
    });

    res.json({ message: "Device removed successfully" });

  } catch (err) {
    console.error("Remove device error:", err);
    res.status(400).json({ message: err.message });
  }
});


// notifications

// HIGH RANK NOTIF
app.get(`${BASE_ROUTE}/admin/notification`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const acceptableRanks = ['admin', 'hr', 'supervisor', "superadmin"]

    if (!acceptableRanks.includes(user.rank)) {
      throw new Error("unauthorized")
    }

    const messages = MessageAdmin.find({}).sort({ createdAt: -1 });
    res.json(messages)

  } catch (error) {
    res.status(400).send(error.message);
  }
});


// USER LEVEL NOTIF

app.get(`${BASE_ROUTE}/user/notification`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");


    const messages = MessageUser.find({ user_email: user.email }).sort({ createdAt: -1 });
    res.json(messages)

  } catch (error) {
    res.status(400).send(error.message);
  }
});


// delete user level notification
app.delete(`${BASE_ROUTE}/user/notification/:id`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) return res.status(404).json({ message: "User not found" });

    const deleted = await MessageUser.findOneAndDelete({
      _id: req.params.id,
      user_email: user.email,
    });

    if (!deleted)
      return res.status(404).json({ message: "Message not found" });

    res.json({ message: "Deleted successfully" });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});





// signOut user
app.post(`${BASE_ROUTE}/user/signout`, async (req, res) => {
  try {
    const currentUser = req.session?.userID
      ? await User.findById(req.session.userID)
      : null;

    if (currentUser) {
      await createAuditLog({
        req,
        category: "authentication",
        action: "auth.signout",
        description: "User signed out",
        actor: currentUser,
      });
    }

    // destroy the session
    req.session.destroy();
    // clear cookie if any
    res.clearCookie(process.env.SESSION_NAME);
    res.status(200).send("logged out successfully");
  } catch (error) {
    res.status(400).send(error.message);
  }
});


/**
 * Generates an appropriate response message for the user based on the admin's decision.
 */
function generateAdminResponse(userTo, responder, action) {
  const adminSignature = `${responder?.name} | ${responder?.rank}`;

  if (action === "granted" || action === "success") {
    return `Dear ${userTo?.name},

Your request regarding the lost device has been successfully processed and the device has been deregistered from the system for security purposes.

If you find the device, please contact the IT department immediately.

Best regards, 
${adminSignature} 
Administration Department`;
  }

  if (action === "rejected") {
    return `Dear ${userTo?.name},

We have reviewed your request regarding the lost device. Unfortunately, we are unable to approve your request at this time. 

Please visit the lost device section for details or contact support for further assistance.

Best regards, 
${adminSignature} 
Administration Department`;
  }

  return `Dear ${userTo?.name},

Your request regarding the lost device has been successfully processed.
Best regards,
${adminSignature} 
Administration Department`;;
}



//  USER MANAGEMENT ROUTE
// deactivate user
app.put(`${BASE_ROUTE}/admin/user/:id/toggle-active`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    // Only HR can manage users or superadmin
    if (!["hr", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Prevent admin from deactivating themselves
    if (targetUser._id.toString() === currentUser._id.toString())
      return res.status(400).json({ message: "You cannot deactivate yourself" });

    targetUser.isAccountActive = !targetUser.isAccountActive;
    await targetUser.save();

    res.json({
      message: `User account is now ${targetUser.isAccountActive ? "Active" : "Deactivated"
        }`,
      user: targetUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// change user rank 
app.put(`${BASE_ROUTE}/admin/user/:id/update-rank`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { rank } = req.body;

    const allowedRanks = ["admin", "user", "hr", "supervisor", "ceo", "auditor", "superadmin"];
    if (!allowedRanks.includes(rank))
      return res.status(400).json({ message: "Invalid rank value" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "unauthorised operation!" });

    if (!["employee"].includes(currentUser.role))
      return res.status(403).json({ message: "You are not yet permanent employee!" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // suppose user is being updated to supervisor, then populate them in supervisor db
    const alreadySupervisor = await Supervisor.findOne({ email: targetUser.email })

    if (rank?.trim()?.toLowerCase() === 'supervisor') {
      if (!alreadySupervisor) {
        await Supervisor.create({
          name: targetUser.name,
          email: targetUser.email,
          station: targetUser.station,
          department: targetUser.department
        })
      }
    }

    // remove them from supervisor db if they are just user and initially was supervisor
    if (rank?.trim()?.toLowerCase() === 'user') {
      if (alreadySupervisor) {
        await Supervisor.findByIdAndDelete(alreadySupervisor._id)
      }
    }

    targetUser.rank = rank;
    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_rank_updated",
      description: "User rank updated",
      actor: currentUser,
      target: targetUser,
      metadata: { newRank: rank },
    });

    res.json({
      message: `User rank updated to ${rank}`,
      user: targetUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// change user role
app.put(`${BASE_ROUTE}/admin/user/:id/update-role`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { role } = req.body;

    const allowedRoles = [
      "employee",
      "intern",
      "attachee",
    ];

    if (!allowedRoles.includes(role))
      return res.status(400).json({ message: "Invalid role value" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "ceo", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.role = role;
    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_role_updated",
      description: "User role updated",
      actor: currentUser,
      target: targetUser,
      metadata: { newRole: role },
    });

    res.json({
      message: `User role updated to ${role}`,
      user: targetUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// get all users
app.get(`${BASE_ROUTE}/admin/users`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "ceo", "supervisor", "auditor", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const users = await User.find().sort({ createdAt: -1 });

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// get all users per department
app.get(`${BASE_ROUTE}/supervisor/users`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["supervisor", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const users = await User.find({ department: currentUser.department }).sort({ createdAt: -1 });

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// change or add department
app.put(`${BASE_ROUTE}/admin/user/:id/update-department`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { department } = req.body;

    if (!department || department.trim() === "")
      return res.status(400).json({ message: "Department is required" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.department = department.trim();
    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_department_updated",
      description: "User department updated",
      actor: currentUser,
      target: targetUser,
      metadata: { newDepartment: targetUser.department },
    });

    res.json({
      message: `Department updated successfully`,
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// change or update station
app.put(`${BASE_ROUTE}/admin/user/:id/update-station`, async (req, res) => {
  try {

    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { station } = req.body;

    if (!station || station === undefined || station === null)
      return res.status(400).json({ message: "Station is required" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.station = station;
    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_station_updated",
      description: "User station updated",
      actor: currentUser,
      target: targetUser,
      metadata: { newStation: station },
    });

    res.json({
      message: `station updated successfully`,
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// admin reset biometrics of user
app.put(`${BASE_ROUTE}/admin/user/:id/reset-biometrics`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.authenticators = [];
    targetUser.authenticator = undefined;
    targetUser.doneBiometric = false;
    targetUser.hasDevices = false;
    await targetUser.save();

    // delete any devices that have been saved in the model of the target user email
    // this makes the user by default to be like they have not added any devices

    await Devices.deleteMany({ user_email: targetUser.email })

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_biometrics_reset",
      description: "User biometrics reset",
      actor: currentUser,
      target: targetUser,
    });

    res.json({
      message: `User biometrics reset successfully`,
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


// admin reset password of user
app.put(`${BASE_ROUTE}/admin/user/:id/reset-password`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // generate and hash a new password for the user, then save it to the database and send sms after
    const resetpassword = generateResetCode();
    const hashedPassword = await bcrypt.hash(resetpassword, 10);
    targetUser.password = hashedPassword;

    // reset the password reset flag to false since the admin has reset it  
    targetUser.isPasswordReset = false;

    // save user
    await targetUser.save();

    // create audit log for the password reset action
    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user_password_reset",
      description: "User password reset",
      actor: currentUser,
      target: targetUser,
    });

    // send sms to the user with the new password
    await SendMessageNow(targetUser, `Hello ${targetUser.name}, your password has been reset by the admin. Your new password is: ${resetpassword}. Please change it after logging in.`);

    res.json({
      message: `User password reset successfully to ${resetpassword} Ask them to check their sms for the new password.`,
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




// get all supervisors
app.get(`${BASE_ROUTE}/all/supervisors`, async (req, res) => {
  try {
    const supervisors = await Supervisor.find({})
    res.status(200).json(supervisors)
  } catch (error) {
    res.status(400).send(error.message)
  }
})


// assign supervisor to the user

app.put(`${BASE_ROUTE}/admin/user/:id/update-supervisor`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { supervisor } = req.body;


    if (!supervisor)
      return res.status(400).json({ message: "Supervisor is required" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "ceo", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const supervisorInUserDB = await User.findOne({
      email: supervisor.email,
    });

    const targetUser = await User.findById(req.params.id);
    if (!supervisorInUserDB) {
      return res.status(404).json({ message: "Supervisor not found" });
    }
    // fetch the potential supervisor data in supervisor data
    const userInSupervisorDb = await Supervisor.findOne({ email: supervisor.email });
    if (!userInSupervisorDb)
      return res.status(404).json({ message: "Supervisor not found" });

    // Ensure supervisor has proper rank
    if (!["supervisor", "admin", "hr", "ceo", "superadmin"].includes(supervisorInUserDB.rank))
      return res.status(400).json({ message: "Selected user is not eligible to be a supervisor" });

    // Prevent assigning user as their own supervisor
    if (targetUser._id.toString() === userInSupervisorDb._id.toString())
      return res.status(400).json({ message: "User cannot supervise themselves" });

    // Store supervisor as name or email (since schema uses string)
    targetUser.supervisor = userInSupervisorDb.name;
    await targetUser.save();

    res.json({
      message: "Supervisor updated successfully",
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




// LEAVE MANAGEMENT

// post
app.post(`${BASE_ROUTE}/leave`, async (req, res) => {
  try {
    if (!req.session.isOnline) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) {
      return res.status(404).json({ message: "Current user not found" });
    }

    let startDateValue;
    let endDateValue;

    try {
      startDateValue = parseSafeDate(req.body.startDate, "startDate");
      endDateValue = parseSafeDate(req.body.endDate, "endDate");
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    if (endDateValue < startDateValue) {
      return res.status(400).json("end date should be higher than start date");
    }

    const leave = await Leave.create({
      ...req.body,
      email: currentUser.email,
      status: "pending",
    });

    await sendLeaveSms(
      currentUser,
      buildLeaveSmsMessage(currentUser, leave, "submitted")
    );

    await createAuditLog({
      req,
      category: "leave",
      action: "leave.request_submitted",
      description: "Leave request submitted",
      actor: currentUser,
      metadata: {
        leaveId: leave._id.toString(),
        leaveType: leave.type,
        startDate: leave.startDate,
        endDate: leave.endDate,
        status: leave.status,
      },
    });

    res.status(201).json(leave);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Get all leaves user
app.get(`${BASE_ROUTE}/user/all/leaves`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });
    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    const leaves = await Leave.find({ email: currentUser.email });
    res.status(200).json(leaves);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.get(`${BASE_ROUTE}/admin/all/leaves`, async (req, res) => {
  try {
    const leaves = await Leave.find({});

    // Fetch corresponding user info for each leave
    const enrichedLeaves = await Promise.all(
      leaves.map(async (leave) => {
        const user = await User.findOne({ email: leave.email }).select(
          "name department station email"
        );
        return {
          ...leave.toObject(),
          name: user?.name || "Unknown",
          department: user?.department || "N/A",
          station: user?.station || "N/A",
        };
      })
    );

    res.status(200).json(enrichedLeaves);
  } catch (error) {
    res.status(400).send(error.message);
  }
});


// supervisor get leaves of their department
app.get(`${BASE_ROUTE}/supervisor/leaves`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentSupervisor = await User.findById(req.session.userID);
    if (!currentSupervisor)
      return res.status(404).json({ message: "User not found" });

    if (!["supervisor", "superadmin"].includes(currentSupervisor.rank)) {
      return res.status(403).json({
        message: "Unauthorised user",
      });

    }

    const department = currentSupervisor.department;

    // Get all users in the supervisor's department
    const departmentUsers = await User.find({ department }).select("email");

    const departmentEmails = departmentUsers.map((u) => u.email);

    // Fetch leaves for users in the supervisor's department
    const leaves = await Leave.find({ email: { $in: departmentEmails } });

    res.status(200).json(leaves);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// update the leave
app.put(`${BASE_ROUTE}/admin/leave/:id`, async (req, res) => {

  try {

    if (!req.session?.isOnline) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Unauthorised user" });
    }

    const existingLeave = await Leave.findById(req.params.id);
    if (!existingLeave) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    const allowedUpdates = {};
    if (typeof req.body.status !== "undefined") {
      allowedUpdates.status = req.body.status;
    }

    const updatedLeave = await Leave.findByIdAndUpdate(
      req.params.id,
      allowedUpdates,
      { new: true, runValidators: true }
    );

    const targetUser = await User.findOne({ email: updatedLeave.email });
    if (!targetUser) {
      return res.status(404).json({ message: "Leave owner not found" });
    }

    if (updatedLeave.status === "approved") {
      targetUser.isOnLeave = true;
      await targetUser.save();
    }

    if (updatedLeave.status === "rejected" && existingLeave.status === "approved") {
      const otherApprovedLeave = await Leave.exists({
        _id: { $ne: updatedLeave._id },
        email: updatedLeave.email,
        status: "approved",
        endDate: { $gte: new Date() },
      });

      if (!otherApprovedLeave) {
        targetUser.isOnLeave = false;
        await targetUser.save();
      }
    }

    if (
      ["approved", "rejected"].includes(updatedLeave.status) &&
      existingLeave.status !== updatedLeave.status
    ) {
      await sendLeaveSms(
        targetUser,
        buildLeaveSmsMessage(targetUser, updatedLeave, updatedLeave.status)
      );
    }

    await createAuditLog({
      req,
      category: "leave",
      action: `leave.request_${updatedLeave.status}`,
      description: `Leave request ${updatedLeave.status}`,
      actor: currentUser,
      target: targetUser,
      metadata: {
        leaveId: updatedLeave._id.toString(),
        previousStatus: existingLeave.status,
        status: updatedLeave.status,
      },
    });

    res.status(200).json(updatedLeave);
  } catch (error) {
    res.status(400).send(error.message);
  }
});


// delete leave
app.delete(`${BASE_ROUTE}/leave/:id`, async (req, res) => {
  try {
    if (!req.session?.isOnline) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) {
      return res.status(404).json({ message: "Current user not found" });
    }

    const leave = await Leave.findById(req.params.id);
    if (!leave) {
      return res.status(404).json({ message: "Leave request not found" });
    }

    const canDelete =
      leave.email === currentUser.email ||
      ["admin", "hr", "superadmin"].includes(currentUser.rank);

    if (!canDelete) {
      return res.status(403).json({ message: "You cannot delete this leave request" });
    }

    const targetUser =
      leave.email === currentUser.email
        ? currentUser
        : await User.findOne({ email: leave.email });

    await Leave.findByIdAndDelete(req.params.id);

    if (targetUser) {
      if (leave.status === "approved") {
        const otherApprovedLeave = await Leave.exists({
          email: leave.email,
          status: "approved",
          endDate: { $gte: new Date() },
        });

        if (!otherApprovedLeave) {
          targetUser.isOnLeave = false;
          await targetUser.save();
        }
      }

      await sendLeaveSms(
        targetUser,
        buildLeaveSmsMessage(targetUser, leave, "cancelled")
      );
    }

    await createAuditLog({
      req,
      category: "leave",
      action: "leave.request_cancelled",
      description: "Leave request cancelled",
      actor: currentUser,
      target: targetUser || null,
      metadata: {
        leaveId: leave._id.toString(),
        status: leave.status,
      },
    });

    res.status(200).json({ message: "Leave deleted successfully" });
  } catch (error) {
    res.status(400).send(error.message);
  }
});



// feedback

app.post(`${BASE_ROUTE}/feedback`, async (req, res) => {
  try {
    const feedback = new Feedback(req.body);
    await feedback.save();
    res.status(201).json({ message: "Feedback saved successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error saving feedback", error });
  }
});


// create the get rated feedback and analysed stats 
// GET FEEDBACK ANALYTICS
app.get(`${BASE_ROUTE}/admin/feedback/analytics`, async (req, res) => {
  try {
    const stats = await Feedback.aggregate([
      {
        $group: {
          _id: null,
          totalResponses: { $sum: 1 },
          avgOverall: { $avg: "$overall" },
          avgEaseOfUse: { $avg: "$easeOfUse" },
          avgResponsiveness: { $avg: "$responsiveness" },
          avgSpeed: { $avg: "$speed" },
          avgClocking: { $avg: "$clocking" },
          avgUiDesign: { $avg: "$uiDesign" },
          avgReliability: { $avg: "$reliability" },
        }
      }
    ]);

    const distribution = await Feedback.aggregate([
      {
        $bucket: {
          groupBy: "$overall",
          boundaries: [0, 4, 7, 9, 11],
          default: "Other",
          output: {
            count: { $sum: 1 }
          }
        }
      }
    ]);

    res.json({
      summary: stats[0],
      distribution
    });

  } catch (error) {
    res.status(500).json({ message: "Error generating analytics", error });
  }
});


// supervisor/admin/hr allowing user to clock outside
app.put(`${BASE_ROUTE}/admin/user/:id/update-clock-outside`, async (req, res) => {
  try {
    // 1. Session Check
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const { startDate, endDate, reason } = req.body;

    // 2. Validation
    if (!startDate || !endDate || !reason) {
      return res.status(400).json({ message: "Start date, end date, and reason are required" });
    }

    // 3. Authorization Check
    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    let startDateValue;
    let endDateValue;

    try {
      startDateValue = parseSafeDate(startDate, "startDate");
      endDateValue = parseSafeDate(endDate, "endDate");
    } catch (dateError) {
      return res.status(400).json({ message: dateError.message });
    }

    if (endDateValue < startDateValue) {
      return res.status(400).json({ message: "End date cannot be before start date." });
    }

    // 4. Update Target User
    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Update the permission and the details
    targetUser.canClockOutside = true;
    targetUser.outsideClockingDetails = {
      startDate: startDateValue,
      endDate: endDateValue,
      reason: reason,
      // Tracking who gave permission
      authorizedBy: currentUser.name,
      authorizedByRole: currentUser.rank
    };

    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.clock_outside_updated",
      description: "Clock outside access granted",
      actor: currentUser,
      target: targetUser,
      metadata: {
        startDate,
        endDate,
        reason,
        canClockOutside: true,
      },
    });

    // send SMS notification to the user about the granted permission
    await SendMessageNow(targetUser, `Dear ${targetUser.name}, you have been granted permission to clock outside of your assigned station  "${targetUser.station}"  from ${startDate} to ${endDate} for the reason "${reason}". Please ensure to adhere to the guidelines provided.`);

    res.json({
      message: `Clock outside authorization updated for ${targetUser.name}`,
      user: targetUser,
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put(`${BASE_ROUTE}/admin/user/:id/revoke-clock-outside`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser?.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Reset fields to default values
    targetUser.canClockOutside = false;
    targetUser.outsideClockingDetails = {
      startDate: null,
      endDate: null,
      reason: "",
      authorizedBy: "",
      authorizedByRole: ""
    };

    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.clock_outside_revoked",
      description: "Clock outside access revoked",
      actor: currentUser,
      target: targetUser,
      metadata: { canClockOutside: false },
    });


    // send message notification to the user about the revoked permission
    await SendMessageNow(targetUser, `Dear ${targetUser.name}, your permission to clock outside of you station "${targetUser.station}" has been revoked. Please ensure to adhere to the standard clocking procedures.`);

    res.json({
      message: `Clock outside authorization revoked for ${targetUser.name}`,
      user: targetUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// leave update by supervisor and hr and superadmin
app.put(`${BASE_ROUTE}/admin/user/:id/revoke-on-leave`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!["admin", "hr", "supervisor", "superadmin"].includes(currentUser?.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Reset fields to default values
    targetUser.isOnLeave = false;
    // save changes
    await targetUser.save();

    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.on_leave_revoked",
      description: "On-leave status revoked",
      actor: currentUser,
      target: targetUser,
      metadata: { isOnLeave: false },
    });


    // send message notification to the user about the revoked permission
    await SendMessageNow(targetUser, `Dear ${targetUser.name}, your permission to clock outside of you station "${targetUser.station}" has been revoked. Please ensure to adhere to the standard clocking procedures.`);

    res.json({
      message: `Clock outside authorization revoked for ${targetUser.name}`,
      user: targetUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




// ─── Delete User (HR/SUPERADMIN Only) ──────────────────────────────────────────────────
app.delete(`${BASE_ROUTE}/admin/user/:id`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser || !["hr", "superadmin", "admin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Unauthorised Operation" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Prevent HR from deleting themselves
    if (targetUser._id.toString() === currentUser._id.toString())
      return res.status(400).json({ message: "You cannot delete your account" });

    // Capture user details for audit log before deletion
    const deletedUserSnapshot = snapshotUser(targetUser);
    const deletedUserDetails = {
      id: targetUser._id?.toString?.() || null,
      name: targetUser.name || "",
      email: targetUser.email || "",
      rank: targetUser.rank || "",
      role: targetUser.role || "",
      department: targetUser.department || "",
      station: targetUser.station || "",
      employeeId: targetUser.employeeId || "",
      phone: targetUser.phone || "",
      dateCreated: targetUser.createdAt || null,
    };

    // Delete user from all related collections
    try {
      // Delete from related models
      await Clocking.deleteMany({ user_id: req.params.id });
      await Leave.deleteMany({ requestedBy: req.params.id });
      await Feedback.deleteMany({ $or: [{ submittedBy: req.params.id }, { ratedUser: req.params.id }] });
      await Devices.deleteMany({ user: req.params.id });
      await deviceLost.deleteMany({ user_id: req.params.id });
      await MessageUser.deleteMany({ $or: [{ userId: req.params.id }, { sender: req.params.id }] });
      await MessageAdmin.deleteMany({ $or: [{ userId: req.params.id }, { sender: req.params.id }] });
      await PasswordReset.deleteMany({ userId: req.params.id });
      await VerifyReport.deleteMany({ $or: [{ userId: req.params.id }, { verifier: req.params.id }] });
    } catch (err) {
      console.error("Error deleting related records:", err);
    }

    // Delete user from User collection
    await User.findByIdAndDelete(req.params.id);

    // Create audit log for user deletion
    await createAuditLog({
      req,
      category: "admin_action",
      action: "admin.user.delete",
      description: `HR deleted user account: ${targetUser.name} (${targetUser.email})`,
      actor: currentUser,
      target: null, // User no longer exists
      metadata: {
        deletedUser: deletedUserDetails,
        deletedAt: new Date(),
      },
      status: "success",
    });

    res.json({
      message: `User ${targetUser.name} and all associated data have been permanently deleted`,
      deletedUser: deletedUserSnapshot,
    });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ message: error.message || "Failed to delete user" });
  }
});



app.get(`${BASE_ROUTE}/audit/logs`, async (req, res) => {
  try {
    // ---------------------------------------------------------
    // AUTHORIZATION
    // ---------------------------------------------------------
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const currentUser = await User.findById(req.session.userID);

    if (
      !currentUser ||
      !["auditor", "admin", "superadmin"].includes(currentUser.rank)
    ) {
      return res.status(403).json({
        message: "Access denied",
      });
    }

    // ---------------------------------------------------------
    // QUERY PARAMETERS
    // ---------------------------------------------------------
    const category = normalizeQueryValue(req.query.category, "all");
    const action = normalizeQueryValue(req.query.action, "all");
    const actorRank = normalizeQueryValue(req.query.actorRank, "all");
    const search = normalizeQueryValue(req.query.search, "");
    const dateFrom = normalizeQueryValue(req.query.dateFrom, "", false);
    const dateTo = normalizeQueryValue(req.query.dateTo, "", true);
    const limit = normalizeQueryValue(req.query.limit, "250", true);

    const parsedLimit = Math.min(
      Math.max(Number(limit) || 250, 1),
      500
    );

    const query = {};

    // ---------------------------------------------------------
    // BASIC FILTERS
    // ---------------------------------------------------------
    if (category !== "all") {
      query.category = category;
    }

    if (action !== "all") {
      query.action = action;
    }

    if (actorRank !== "all") {
      query["actor.rank"] = actorRank;
    }

    // ---------------------------------------------------------
    // SAFE DATE FILTER
    // ---------------------------------------------------------
    if (dateFrom || dateTo) {
      query.occurredAt = {};

      try {
        if (dateFrom) {
          query.occurredAt.$gte = parseDateRangeBoundary(dateFrom, "dateFrom", "start");
        }

        if (dateTo) {
          query.occurredAt.$lte = parseDateRangeBoundary(dateTo, "dateTo", "end");
        }

        // -------------------------------------------------------
        // VALIDATE DATE RANGE
        // -------------------------------------------------------
        if (
          query.occurredAt.$gte &&
          query.occurredAt.$lte &&
          query.occurredAt.$gte > query.occurredAt.$lte
        ) {
          return res.status(400).json({
            message: "dateFrom cannot be after dateTo.",
          });
        }
      } catch (dateError) {
        console.error(
          "Audit log date parsing error:",
          dateError
        );

        return res.status(400).json({
          message: "Invalid audit log date range.",
        });
      }
    }

    // ---------------------------------------------------------
    // SEARCH
    // ---------------------------------------------------------
    if (search) {
      const regex = new RegExp(
        search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        "i"
      );

      query.$or = [
        { action: regex },
        { description: regex },
        { "actor.name": regex },
        { "actor.email": regex },
        { "target.name": regex },
        { "target.email": regex },
      ];
    }

    // ---------------------------------------------------------
    // FETCH LOGS
    // ---------------------------------------------------------
    const logs = await AuditLog.find(query)
      .sort({
        occurredAt: -1,
      })
      .limit(parsedLimit)
      .lean();

    // ---------------------------------------------------------
    // CATEGORY COUNTS
    // ---------------------------------------------------------
    const categoryCounts = logs.reduce((acc, log) => {
      acc[log.category] =
        (acc[log.category] || 0) + 1;

      return acc;
    }, {});

    // ---------------------------------------------------------
    // ACTION COUNTS
    // ---------------------------------------------------------
    const actionCounts = logs.reduce((acc, log) => {
      acc[log.action] =
        (acc[log.action] || 0) + 1;

      return acc;
    }, {});

    // ---------------------------------------------------------
    // UNIQUE ACTORS
    // ---------------------------------------------------------
    const uniqueActors = new Set(
      logs
        .map(
          (log) =>
            log.actor?.email ||
            log.actor?.userId ||
            ""
        )
        .filter(Boolean)
    ).size;

    // ---------------------------------------------------------
    // PRIVILEGED ACTIONS
    // ---------------------------------------------------------
    const privilegedActions = logs.filter((log) =>
      PRIVILEGED_AUDIT_RANKS.includes(
        log.actor?.rank
      )
    ).length;

    // ---------------------------------------------------------
    // TODAY
    // ---------------------------------------------------------
    const now = new Date();

    const todayRange = getSafeDateRange(getNairobiDateKey(now), getNairobiDateKey(now));
    const todayStart = todayRange.start;
    const tomorrowStart = new Date(todayRange.end.getTime() + 1);

    const today = logs.filter((log) => {
      if (!log.occurredAt) {
        return false;
      }

      const occurredAt =
        log.occurredAt instanceof Date
          ? log.occurredAt
          : new Date(log.occurredAt);

      if (Number.isNaN(occurredAt.getTime())) {
        return false;
      }

      return (
        occurredAt >= todayStart &&
        occurredAt < tomorrowStart
      );
    }).length;

    // ---------------------------------------------------------
    // RESPONSE
    // ---------------------------------------------------------
    return res.json({
      logs,

      metrics: {
        total: logs.length,
        uniqueActors,
        privilegedActions,
        today,
      },

      categoryCounts,
      actionCounts,
    });

  } catch (error) {
    console.error(
      "Fetch audit logs error:",
      error
    );

    return res.status(500).json({
      message: "Failed to fetch audit logs",
    });
  }
});




app.post(`${BASE_ROUTE}/audit/logs/client-event`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) {
      return res.status(404).json({ message: "Current user not found" });
    }

    const { action, metadata = {} } = req.body;
    const eventConfig = CLIENT_AUDIT_ACTIONS[action];

    if (!eventConfig) {
      return res.status(400).json({ message: "Unsupported audit event" });
    }

    await createAuditLog({
      req,
      category: eventConfig.category,
      action,
      description: eventConfig.description,
      actor: currentUser,
      metadata,
    });

    res.status(201).json({ message: "Audit event recorded" });
  } catch (error) {
    console.error("Create client audit log error:", error);
    res.status(500).json({ message: "Failed to record audit event" });
  }
});




// get colleagues of the same station and department
app.get(`${BASE_ROUTE}/user/colleagues`, async (req, res) => {
  try {
    // 1. Check authentication
    if (!req.session.isOnline || !req.session.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // 2. Fetch the current user's profile to get their context
    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) {
      return res.status(404).json({ message: "Current user not found" });
    }

    // 3. Find users in the same station AND department, excluding the current user
    const colleagues = await User.find({
      station: currentUser.station,
      department: currentUser.department,
      _id: { $ne: currentUser._id } // Custom Semantics: "Not Equal" to current ID
    }).select("-password"); // Security: Ensure passwords aren't sent

    res.status(200).json(colleagues);
  } catch {
    res.status(500).json({ message: "Server error while fetching colleagues" });
  }
});


// Report Document Verification
app.post(`${BASE_ROUTE}/verify/create`, async (req, res) => {
  try {
    const { data } = req.body;

    //  Generate secure token
    const token = crypto.randomBytes(32).toString('hex');

    //  Hash the data
    const dataHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');

    await Verification.create({
      token,
      dataHash,
      userId: req.user?._id || null, // optional
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    });

    res.json({ token, dataHash });

  } catch {
    res.status(500).json({ message: 'Failed to create verification' });
  }
});


// verify
app.get(`${BASE_ROUTE}/verify/:token`, async (req, res) => {
  try {
    const { token } = req.params;

    const record = await Verification.findOne({ token });

    if (!record) {
      return res.json({ valid: false });
    }

    // check expiry
    if (record.expiresAt && record.expiresAt < new Date()) {
      return res.json({ valid: false, expired: true });
    }

    const providedHash = req.query.hash;
    let contentMatch = null;

    if (providedHash) {
      contentMatch = providedHash === record.dataHash;
    }

    res.json({
      valid: true,
      createdAt: record.createdAt,
      type: record.type,
      message: "This is an official KMFRI attendance report",
      dataHash: record.dataHash,
      contentMatch // true/false/null
    });

  } catch {
    res.status(500).json({ message: 'Verification failed' });
  }
});



// -----------------------------
// Superadmin endpoints (endpoints protected to superadmin)
// -----------------------------

const ensureSuperadmin = async (req, res, allowBootstrap = false) => {
  if (!req.session?.isOnline || !req.session?.userID) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const currentUser = await User.findById(req.session.userID);
  if (!currentUser) return res.status(401).json({ message: 'Unauthorized' });

  const anySuperadmin = await User.findOne({ rank: 'superadmin' });
  if (!anySuperadmin && allowBootstrap) {
    return { allowed: true, currentUser };
  }

  if (currentUser.rank !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied. Superadmin only.' });
  }

  return { allowed: true, currentUser };
};

app.get(`${BASE_ROUTE}/superadmin/config`, async (req, res) => {
  try {
    const cfg = await PlatformConfig.getSingleton();
    return res.status(200).json(cfg);
  } catch (err) {
    console.error('Get config error:', err);
    return res.status(500).json({ message: 'Failed to load configuration' });
  }
});


app.post(`${BASE_ROUTE}/superadmin/config`, async (req, res) => {

  try {

    const auth = await ensureSuperadmin(req, res, true);

    if (!auth || auth.allowed !== true) return;

    const updates = req.body || {};

    const cfg = await PlatformConfig.getSingleton();

    // =====================================================
    // LOGO
    // =====================================================

    if (typeof updates.logoUrl !== "undefined") {

      cfg.logoUrl = updates.logoUrl;

      cfg.markModified("logoUrl");

    }

    // =====================================================
    // BRANDING
    // =====================================================

    if (updates.branding) {

      cfg.branding = {

        ...(cfg.branding?.toObject?.() || cfg.branding),

        ...updates.branding,

      };

      cfg.markModified("branding");

    }

    // =====================================================
    // ACTIVE THEME
    // =====================================================

    if (typeof updates.activeThemeName !== "undefined") {

      cfg.activeThemeName = updates.activeThemeName;

      cfg.markModified("activeThemeName");

    }

    // =====================================================
    // THEMES
    // =====================================================

    if (updates.themes) {

      cfg.themes = updates.themes;

      cfg.markModified("themes");

    }

    // =====================================================
    // GEOFENCE
    // =====================================================

    if (updates.geofence) {

      cfg.geofence = {

        ...(cfg.geofence?.toObject?.() || cfg.geofence),

        ...updates.geofence,

      };

      cfg.markModified("geofence");

    }

    // =====================================================
    // ATTENDANCE POLICY
    // =====================================================

    if (updates.attendancePolicy) {

      cfg.attendancePolicy = {

        ...(cfg.attendancePolicy?.toObject?.() || cfg.attendancePolicy),

        ...updates.attendancePolicy,

      };

      cfg.markModified("attendancePolicy");

    }

    if (updates.attendancePolicy) {

      getAttendanceScheduleTimes(cfg.attendancePolicy);

    }

    // =====================================================
    // MASTER SETTINGS
    // =====================================================

    if (updates.masterSettings) {

      cfg.masterSettings = {

        ...(cfg.masterSettings?.toObject?.() || cfg.masterSettings),

        ...updates.masterSettings,

      };

      cfg.markModified("masterSettings");

    }

    // =====================================================
    // NOTIFICATION SETTINGS
    // =====================================================

    if (updates.notificationReminders) {

      cfg.notificationReminders = {

        ...(cfg.notificationReminders?.toObject?.() || cfg.notificationReminders),

        ...updates.notificationReminders,

      };

      cfg.markModified("notificationReminders");

    }

    // =====================================================
    // DROPDOWNS
    // =====================================================

    if (updates.dropdowns) {

      cfg.dropdowns = updates.dropdowns;

      cfg.markModified("dropdowns");

    }

    // =====================================================
    // DEPARTMENTS
    // =====================================================

    if (updates.departments) {

      cfg.departments = updates.departments;

      cfg.markModified("departments");

    }

    // =====================================================
    // STATIONS
    // =====================================================

    if (updates.stations) {

      cfg.stations = updates.stations;

      cfg.markModified("stations");

    }

    await cfg.save();


    // refresh scheduler
    await refreshAttendanceScheduler();


    await createAuditLog({

      req,

      category: "superadmin",

      action: "superadmin.config.update",

      description: "Platform configuration updated",

      actor: auth.currentUser,

      metadata: {

        updatedSections: Object.keys(updates),

      },

    });

    return res.status(200).json(cfg);


  }

  catch (err) {

    console.error("Update config error:", err);

    return res.status(400).json({

      message: err.message || "Configuration update failed."

    });

  }

});



app.post(`${BASE_ROUTE}/superadmin/config/reset`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;

    const { section = 'all' } = req.body || {};
    const defaults = getDefaultPlatformConfig();
    const cfg = await PlatformConfig.getSingleton();
    const resettableSections = ['branding', 'themes', 'notificationReminders', 'geofence', 'attendancePolicy', 'masterSettings', 'dropdowns', 'departments', 'stations', 'logoUrl'];

    if (section === 'all') {
      Object.entries(defaults).forEach(([key, value]) => {
        cfg[key] = value;
        cfg.markModified(key);
      });
    } else {
      if (!resettableSections.includes(section)) throw new Error('Unsupported reset section');
      if (section === 'themes') {
        const currentBranding = cfg.branding?.toObject?.() || cfg.branding || {};
        cfg.themes = defaults.themes;
        cfg.activeThemeName = defaults.activeThemeName;
        cfg.branding = {
          ...currentBranding,
          primaryColor: defaults.branding.primaryColor,
          secondaryColor: defaults.branding.secondaryColor,
          accentColor: defaults.branding.accentColor,
        };
        cfg.markModified('themes');
        cfg.markModified('activeThemeName');
        cfg.markModified('branding');
      } else {
        cfg[section] = defaults[section];
        cfg.markModified(section);
      }
    }

    await cfg.save();

    if (section === 'all' || section === 'attendancePolicy') {
      await refreshAttendanceScheduler();
    }

    await createAuditLog({
      req,
      category: 'superadmin',
      action: 'superadmin.config.reset',
      description: section === 'all' ? 'Reset platform configuration to defaults' : `Reset ${section} configuration to defaults`,
      actor: auth.currentUser,
      metadata: { section },
    });

    return res.status(200).json(cfg);
  } catch (err) {
    console.error('Reset config error:', err);
    return res.status(400).json({ message: err.message || 'Reset failed' });
  }
});

app.post(`${BASE_ROUTE}/superadmin/departments/add`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;
    const { name } = req.body;
    if (!name || !name.trim()) throw new Error('Department name required');
    const cfg = await PlatformConfig.getSingleton();
    if (!cfg.departments.includes(name)) cfg.departments.push(name);
    await cfg.save();
    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.department.add', description: `Added department ${name}`, actor: auth.currentUser, metadata: { name } });
    return res.status(200).json(cfg.departments);
  } catch (err) {
    console.error('Add department error:', err);
    return res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/superadmin/departments/remove`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;
    const { name } = req.body;
    if (!name) throw new Error('Department name required');
    const cfg = await PlatformConfig.getSingleton();
    cfg.departments = cfg.departments.filter((d) => d !== name);
    await cfg.save();
    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.department.remove', description: `Removed department ${name}`, actor: auth.currentUser, metadata: { name } });
    return res.status(200).json(cfg.departments);
  } catch (err) {
    console.error('Remove department error:', err);
    return res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/superadmin/stations/add`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;
    const { name, lat = 0, lng = 0, radiusMeters, active = true } = req.body;
    if (!name || !name.trim()) throw new Error('Station name required');
    const cfg = await PlatformConfig.getSingleton();
    const station = {
      name: name.trim(),
      lat: Number(lat || 0),
      lng: Number(lng || 0),
      radiusMeters: Number(radiusMeters || cfg.geofence?.radiusMeters || 100),
      active: active !== false,
    };
    const existingIndex = cfg.stations.findIndex((s) => (typeof s === 'string' ? s : s.name) === station.name);
    if (existingIndex >= 0) {
      cfg.stations[existingIndex] = station;
    } else {
      cfg.stations.push(station);
    }
    await cfg.save();
    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.station.add', description: `Saved station ${station.name}`, actor: auth.currentUser, metadata: station });
    return res.status(200).json(cfg.stations);
  } catch (err) {
    console.error('Add station error:', err);
    return res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/superadmin/stations/remove`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;
    const { name } = req.body;
    if (!name) throw new Error('Station name required');
    const cfg = await PlatformConfig.getSingleton();
    cfg.stations = cfg.stations.filter((s) => (typeof s === 'string' ? s : s.name) !== name);
    await cfg.save();
    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.station.remove', description: `Removed station ${name}`, actor: auth.currentUser, metadata: { name } });
    return res.status(200).json(cfg.stations);
  } catch (err) {
    console.error('Remove station error:', err);
    return res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/superadmin/dropdowns/update`, async (req, res) => {
  try {
    const auth = await ensureSuperadmin(req, res, true);
    if (!auth || auth.allowed !== true) return;
    const { key, values } = req.body;
    if (!key) throw new Error('Dropdown key required');
    if (!Array.isArray(values)) throw new Error('Values must be an array');
    const cfg = await PlatformConfig.getSingleton();
    cfg.dropdowns.set(key, values);
    await cfg.save();
    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.dropdown.update', description: `Updated dropdown ${key}`, actor: auth.currentUser, metadata: { key, values } });
    return res.status(200).json({ key, values });
  } catch (err) {
    console.error('Update dropdown error:', err);
    return res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/superadmin/create-superadmin`, async (req, res) => {
  try {
    const anySuperadmin = await User.findOne({ rank: 'superadmin' });
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) throw new Error('Missing required fields');

    if (!validator.isEmail(email)) throw new Error('Invalid email');

    if (anySuperadmin) {
      const auth = await ensureSuperadmin(req, res, false);
      if (!auth || auth.allowed !== true) return;
    }

    const existing = await User.findOne({ email });
    if (existing) throw new Error('Email already registered');

    const hashed = await bcrypt.hash(password, 10);
    const created = await User.create({ name, email: email.toLowerCase(), password: hashed, phone: phone || '', rank: 'superadmin', role: 'employee' });

    await createAuditLog({ req, category: 'superadmin', action: 'superadmin.user.create', description: `Superadmin account created for ${created.email}`, actor: { name: created.name, email: created.email, rank: 'superadmin' }, target: created });

    return res.status(200).json({ message: 'Superadmin created', user: sanitizeUserResponse(created) });
  } catch (err) {
    console.error('Create superadmin error:', err);
    return res.status(400).json({ message: err.message });
  }
});




// =====================================================
// SUPERADMIN DASHBOARD (FULL)
// =====================================================


app.get(`${BASE_ROUTE}/superadmin/dashboard/full`, async (req, res) => {

  try {

    const auth = await ensureSuperadmin(req, res, true);

    if (!auth || auth.allowed !== true) return;

    const cfg = await PlatformConfig.getSingleton();

    /* =====================================================
       USER COUNTS
    ===================================================== */

    const [
      totalUsers,
      totalEmployees,
      totalSupervisors,
      totalHR,
      totalAdmins,
      totalSuperadmins
    ] = await Promise.all([

      User.countDocuments(),

      User.countDocuments({
        role: "employee"
      }),

      User.countDocuments({
        rank: "supervisor"
      }),

      User.countDocuments({
        rank: "hr"
      }),

      User.countDocuments({
        rank: "admin"
      }),

      User.countDocuments({
        rank: "superadmin"
      })

    ]);

    /* =====================================================
       SYSTEM HEALTH
    ===================================================== */

    const memory = process.memoryUsage();

    const health = {

      database:
        mongoose.connection.readyState === 1
          ? "Healthy"
          : "Disconnected",

      nodeVersion:
        process.version,

      environment:
        process.env.NODE_ENV || "development",

      uptime:
        Math.floor(process.uptime()),

      hostname:
        os.hostname(),

      platform:
        os.platform(),

      architecture:
        os.arch(),

      cpuCount:
        os.cpus().length,

      memory: {

        rss:
          memory.rss,

        heapUsed:
          memory.heapUsed,

        heapTotal:
          memory.heapTotal,

        freeMemory:
          os.freemem(),

        totalMemory:
          os.totalmem()

      }

    };

    /* =====================================================
       RESPONSE
    ===================================================== */

    return res.status(200).json({

      message: "Dashboard loaded successfully.",

      dashboard: {

        organization: {

          organizationName:
            cfg.branding.organizationName,

          shortName:
            cfg.branding.shortName,

          activeTheme:
            cfg.activeThemeName,

          departments:
            cfg.departments.length,

          stations:
            cfg.stations.length

        },

        users: {

          total:
            totalUsers,

          employees:
            totalEmployees,

          supervisors:
            totalSupervisors,

          hr:
            totalHR,

          admins:
            totalAdmins,

          superadmins:
            totalSuperadmins

        },

        configuration: {

          themes:
            cfg.themes.length,

          dropdowns:
            cfg.dropdowns.size,

          geofenceEnabled:
            cfg.geofence.enabled,

          geofenceRadius:
            cfg.geofence.radiusMeters,

          maintenanceMode:
            cfg.masterSettings.maintenanceMode,

          selfRegistration:
            cfg.masterSettings.allowEmployeeSelfRegistration

        },

        attendance: {

          standardClockIn:
            cfg.attendancePolicy.standardClockIn,

          standardClockOut:
            cfg.attendancePolicy.standardClockOut,

          gracePeriod:
            cfg.attendancePolicy.gracePeriodMinutes,

          biometric:
            cfg.attendancePolicy.requireBiometricVerification,

          allowClockOutside:
            cfg.attendancePolicy.allowClockOutsideStation

        },

        notifications: {

          channels:
            cfg.notificationReminders.channels,

          clockInReminder:
            cfg.notificationReminders.clockInReminderMinutes,

          clockOutReminder:
            cfg.notificationReminders.clockOutReminderMinutes

        },

        health

      }

    });

  }

  catch (err) {

    console.error("Dashboard Full Error:", err);

    return res.status(500).json({

      message:
        err.message || "Failed to load dashboard."

    });

  }

});

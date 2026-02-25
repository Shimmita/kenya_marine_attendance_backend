import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import { default as connectMongoStore } from "connect-mongodb-session";
import cors from "cors";
import "dotenv/config";
import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import validator from "validator";
import Clocking from "./model/Clocking.js";
import DeviceLost from "./model/deviceLost.js";
import Devices from "./model/Devices.js";
import Leave from "./model/Leave.js";
import MessageAdmin from "./model/MessageAdmin.js";
import MessageUser from "./model/MessageUser.js";
import Supervisor from "./model/Supervisor.js";
import User from "./model/User.js";
import Feedback from "./model/Feedback.js";
const allowedOrigins = [
  process.env.CROSS_ORIGIN_ALLOWED,
  process.env.CROSS_ORIGIN_ALLOWED_PRODUCTION
];
const mongoDBSession = connectMongoStore(session);
const app = express();
app.use(bodyParser.json());
app.use(express.json());
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
  })
);

const PORT = process.env.PORT || 5000;
const BASE_ROUTE = process.env.BASE_ROUTE;
const environment = process.env.ENVIRONMENT_MODE;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const getRpID = () =>
  environment === "SANDBOX"
    ? process.env.DOMAIN_NAME_LOCAL   // e.g. "localhost"
    : process.env.DOMAIN_NAME_PROD;

const getExpectedOrigin = () =>
  environment === "SANDBOX"
    ? process.env.ORIGIN_LOCAL || "http://localhost:5173"
    : process.env.ORIGIN_PROD;

// ─── Database ─────────────────────────────────────────────────────────────────

mongoose
  .connect(
    environment === "SANDBOX"
      ? process.env.MONGO_CONNECTION_URI
      : process.env.MONGO_CONNECTION_URI_CLOUD
  )
  .then(() =>
    console.log(`Connected to MongoDB (${environment === "SANDBOX" ? "LOCAL" : "CLOUD"})`)
  )
  .catch((err) => console.error("Database connection failed:", err));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

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
    saveUninitialized: false,
    name: process.env.SESSION_NAME,
    store,
    cookie: {
      maxAge: 60 * 60 * 24 * 1000,
      secure: environment !== "SANDBOX",
      sameSite: environment === "SANDBOX" ? "lax" : "none",
    },
  })
);

// ─── Auth check ───────────────────────────────────────────────────────────────

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
    const data = req.body.formData
    const { email, password } = data

    if (!validator.isEmail(email)) throw new Error("Provided email is malformed!");
    if (!password || password.length < 4) throw new Error("Password must be at least 4 characters!");

    const existingUser = await User.findOne({ email });
    if (existingUser) throw new Error("User already registered!");

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ ...data, password: hashedPassword });

    return res.status(200).json({ message: "Account created successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(400).json({ message: error.message });
  }
});

// ─── Sign In ──────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signin`, async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!validator.isEmail(email)) throw new Error("Provided email is malformed!");
    if (!password || password.length < 4) throw new Error("Password must be at least 4 characters!");

    const user = await User.findOne({ email });
    if (!user) throw new Error("Create a new account to continue!");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error("Invalid credentials!");

    if (!user.email_verified) throw new Error("Email not verified. Contact admin.");

    req.session.isOnline = true;
    req.session.userID = user._id.toString();

    return res.status(200).json(user);
  } catch (error) {
    console.error("Signin error:", error);
    return res.status(400).json({ message: error.message });
  }
});

// ─── Biometrics ───────────────────────────────────────────────────────────────

/**
 * 1. Generate Registration Challenge
 */
app.get(`${BASE_ROUTE}/biometric/register/challenge`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "session expired, logout and login again to proceed!" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    // temp fix so that it can register outside google emails
    // can make use of platform to force using device bound auth
    /* const options = await generateRegistrationOptions({
      rpName: "KMFRI Attendance",
      rpID: getRpID(),
      userID: Uint8Array.from(Buffer.from(user._id.toString())),
      userName: user.email,
      authenticatorSelection: { userVerification: "required" },
    }); */

    const options = await generateRegistrationOptions({
      rpName: "KMFRI Attendance",
      rpID: getRpID(),
      userID: Uint8Array.from(Buffer.from(user._id.toString())),
      userName: user.email,
      attestationType: "none",
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required",
      },
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

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
    });

    if (!verification.verified) return res.status(400).json({ registered: false });

    const { credential } = verification.registrationInfo;

    user.authenticator = {
      credentialID: credential.id,                                              // ✅ already base64url — store directly
      credentialPublicKey: Buffer.from(credential.publicKey).toString("base64url"), // ✅ raw bytes → base64url
      counter: credential.counter,
    };

    // update user to mark biometric registration complete
    user.doneBiometric = true;

    await user.save();
    delete req.session.registrationChallenge;

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
    if (!user || !user.authenticator) {
      return res.status(400).json({ message: "Biometric not registered for this account" });
    }

    const options = await generateAuthenticationOptions({
      rpID: getRpID(),
      userVerification: "required",
      allowCredentials: [
        {
          id: user.authenticator.credentialID, // base64url string — correct for v10+
          type: "public-key",
        },
      ],
    });

    req.session.authChallenge = options.challenge;
    req.session.biometricVerified = false;

    res.json(options);
  } catch (error) {
    console.error("Auth challenge error:", error);
    res.status(500).json({ message: "Failed to generate authentication options" });
  }
});

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
app.post(`${BASE_ROUTE}/biometric/auth/verify`, async (req, res) => {
  try {
    if (!req.session.isOnline) {
      return res.status(401).json({ verified: false, message: "Unauthorized" });
    }

    const user = await User.findById(req.session.userID);
    if (!user || !user.authenticator) {
      return res.status(400).json({ verified: false, message: "Fingerprint not registered" });
    }

    const expectedChallenge = req.session.authChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({
        verified: false,
        message: "No auth challenge found. Please restart.",
      });
    }

    // extract selected station and auth response from request body
    const { selectedStation, ...authResponse } = req.body;

    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
      // ✅ v10+ shape: `credential` not `authenticator`, `id` not `credentialID`,
      //    `publicKey` (Uint8Array) not `credentialPublicKey` (Buffer)
      credential: {
        id: user.authenticator.credentialID,                                         // base64url string
        publicKey: new Uint8Array(
          Buffer.from(user.authenticator.credentialPublicKey, "base64url")           // base64url → Uint8Array
        ),
        counter: user.authenticator.counter,
      },
      requireUserVerification: true,
    });

    if (!verification.verified) return res.status(401).json({ verified: false });

    // Update counter to prevent replay attacks
    user.authenticator.counter = verification.authenticationInfo.newCounter;

    // save in the db
    await user.save();

    // save clocking in data in East African Time (EAT) timezone
    if (!user?.hasClockedIn && !user?.isToClockOut) {

      const now = new Date();

      // Convert to Nairobi time
      const eatTime = new Date(
        now.toLocaleString("en-US", { timeZone: "Africa/Nairobi" })
      );

      const hours = eatTime.getHours();

      // Late if after 9:00 AM
      const isLate = hours > 9 || (hours === 9 && eatTime.getMinutes() > 0);
      const isEmployee = user.role === "employee"

      const clockingData = {
        name: user.name,
        email: user.email,
        department: user.department,
        supervisor: isEmployee ? "" : user.supervisor,
        station: selectedStation,
        phone: user.phone,
        // store UTC
        clock_in: now,
        // updated when is clocking out, store UTC
        clock_out: null,
        // value isLate is determined at clock-in time
        isLate: isLate,
        // will update later when clocking out
        isPresent: false,
      };

      await Clocking.create(clockingData);

      user.hasClockedIn = true;
      user.isToClockOut = true;

      await user.save();
    }
    else {

      const latestClocking = await Clocking
        .findOne({ email: user.email })
        .sort({ clock_in: -1 });

      if (!latestClocking) {
        return res.status(404).json({ message: "No clock-in record found" });
      }

      const now = new Date();
      latestClocking.clock_out = now;

      // Calculate difference in milliseconds
      const diffMs = now - latestClocking.clock_in;

      // Convert to hours
      const diffHours = diffMs / (1000 * 60 * 60);

      // Present if worked 5 hours or more
      latestClocking.isPresent = diffHours >= 5;

      await latestClocking.save();

      user.hasClockedIn = false;
      user.isToClockOut = false;

      await user.save();
    }


    req.session.biometricVerified = true;
    req.session.biometricVerifiedAt = Date.now();
    delete req.session.authChallenge;
    res.json({ verified: true });
  } catch (err) {
    console.error("Auth verify error:", err);
    res.status(401).json({ verified: false, message: err.message });
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
    // TODO: record attendance in database, e.g.:
    // await AttendanceRecord.create({
    //   userID: req.session.userID,
    //   clockInTime: new Date(),
    //   type: "clock-in",
    // });

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

    const user = await User.findById(req.session.userID).select("-password").select("-authenticator");
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

    const { name, department, supervisor, phone, startDate, endDate, gender } = req.body;

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    user.name = name || user.name;
    user.department = department || user.department;
    user.supervisor = supervisor || user.supervisor;
    user.phone = phone || user.phone;
    user.startDate = startDate || user.startDate;
    user.endDate = endDate || user.endDate;
    user.gender = gender || user.gender;

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

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

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

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const userEmail = user.email;
    const now = new Date();

    // Date Ranges
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

    const startOfWeek = new Date(now);
    const dayOfWeek = now.getDay();
    const diffToMonday = now.getDate() - dayOfWeek + (dayOfWeek === 0 ? -6 : 1);
    startOfWeek.setDate(diffToMonday);
    startOfWeek.setHours(0, 0, 0, 0);

    const records = await Clocking.find({
      email: userEmail,
      clock_in: { $gte: startOfMonth, $lte: endOfMonth }
    });

    // Helper: Calculate working days excluding weekends
    const getWorkingDays = (start, end) => {
      let count = 0;
      let cur = new Date(start);
      while (cur <= end && cur <= now) {
        if (cur.getDay() !== 0 && cur.getDay() !== 6) count++;
        cur.setDate(cur.getDate() + 1);
      }
      return count || 1;
    };

    const processStats = (filteredRecords, totalExpectedDays) => {
      const dailyMap = {};

      filteredRecords.forEach(rec => {
        const dateKey = new Date(rec.clock_in).toISOString().split('T')[0];
        if (!dailyMap[dateKey]) {
          dailyMap[dateKey] = { hours: 0, isLateAny: false, isEarlyAny: false, clockings: 0 };
        }

        if (rec.clock_out) {
          const duration = (new Date(rec.clock_out) - new Date(rec.clock_in)) / (1000 * 60 * 60);
          dailyMap[dateKey].hours += duration;
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
        if (day.hours >= 5) presentDays++;
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



// ADMIN, SUPERVISOR,CEO,HR LEVEL overall org stats

// Admin Overall Stats
app.get(`${BASE_ROUTE}/overall/attendance/stats`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const [records, allUsers] = await Promise.all([
      Clocking.find({ clock_in: { $gte: startOfMonth } }),
      User.find({}, 'email name department station')
    ]);

    const stats = {
      orgTotalHours: 0,
      orgTotalOvertime: 0,
      departmentData: {},
      stationData: {}, // Track which branches are most active
      employeeMetrics: {},
      lateToday: 0
    };

    records.forEach(rec => {
      const email = rec.email;
      const dept = rec.department || "Unassigned";
      const station = rec.station || "Main";

      if (!stats.employeeMetrics[email]) {
        stats.employeeMetrics[email] = { hours: 0, overtime: 0, lateCount: 0, earlyCount: 0, days: new Set() };
      }

      // 1. Calculate Hours
      if (rec.clock_out) {
        const diff = (rec.clock_out - rec.clock_in) / (1000 * 60 * 60);
        stats.employeeMetrics[email].hours += diff;
        if (diff > 9) stats.employeeMetrics[email].overtime += (diff - 9);
      }

      // 2. Punctuality
      if (rec.isLate) stats.employeeMetrics[email].lateCount++;
      else stats.employeeMetrics[email].earlyCount++;

      // 3. Dept & Station Aggregation
      if (!stats.departmentData[dept]) stats.departmentData[dept] = { hours: 0, staff: new Set() };
      stats.departmentData[dept].hours += (rec.clock_out ? (rec.clock_out - rec.clock_in) / (1000 * 60 * 60) : 0);
      stats.departmentData[dept].staff.add(email);

      if (!stats.stationData[station]) stats.stationData[station] = { checkins: 0 };
      stats.stationData[station].checkins++;
    });

    // Final Org-wide Calculations
    const totalStaff = allUsers.length;
    let burnoutAlerts = 0;
    let topPerformers = [];

    Object.entries(stats.employeeMetrics).forEach(([email, data]) => {
      stats.orgTotalHours += data.hours;
      stats.orgTotalOvertime += data.overtime;
      if (data.overtime > 20) burnoutAlerts++; // More than 20h overtime/month is high risk

      topPerformers.push({
        email,
        score: (data.hours * 0.6) + (data.earlyCount * 2) - (data.lateCount * 1)
      });
    });

    res.status(200).json({
      overview: {
        totalStaff,
        activeStaffThisMonth: Object.keys(stats.employeeMetrics).length,
        totalOrgHours: stats.orgTotalHours.toFixed(1),
        totalOrgOvertime: stats.orgTotalOvertime.toFixed(1),
        averageStaffEfficiency: (stats.orgTotalHours / (totalStaff * 160) * 100).toFixed(1) + "%", // Based on 160h standard month
      },
      healthSignals: {
        burnoutRiskCount: burnoutAlerts,
        chronicLatenessDept: Object.keys(stats.departmentData).sort((a, b) => b.hours - a.hours)[0],
        mostActiveStation: Object.keys(stats.stationData).sort((a, b) => b.checkins - a.checkins)[0]
      },
      departmentBreakdown: Object.keys(stats.departmentData).map(d => ({
        name: d,
        totalHours: stats.departmentData[d].hours.toFixed(1),
        headcount: stats.departmentData[d].staff.size
      })),
      topPerformers: topPerformers.sort((a, b) => b.score - a.score).slice(0, 5)
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
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
    const gender = user.gender
    const role = user.role
    // Check if station exists and extract the value
    const stationName = latestStation?.station;
    // 1. Determine Pronouns/Subject Reference based on Gender
    const genderKey = gender?.toLowerCase();
    const pronoun = genderKey === "male" ? "He" : genderKey === "female" ? "She" : "The user";

    // 2. Format Role (Capitalize first letter)
    const formattedRole = role.charAt(0).toUpperCase() + role.slice(1);

    // 3. Define the Station Text (only if available)
    const stationText = latestStation?.station
      ? `\n- **Latest Clocking Station:** ${latestStation.station}`
      : "";

    // 4. Construct the letter-style message (Now including stationText)
    const message = `**SUBJECT: Lost Device Report - ${name}**

Hello Admin Team,

**${formattedRole} ${name}** (Phone: ${phone}) from ${stationName} - **${department}** department has reported a lost device. ${pronoun} was last seen at a station.

**Details:**
- **Email:** ${email}${stationText}

**Next Steps:**
Please navigate to the **User Requests** section to review this case and resolve the issue. Most likely, this will involve deregistering the device from the system to ensure security.

Best regards,
System Automator`;



    const userDevices = await Devices.find({ user_email: user.email })

    const existingPending = await DeviceLost.findOne({
      user_email: user.email,
      status: "pending",
      device_fingerprint
    });

    if (existingPending)
      throw new Error("You already have a pending request");

    const lostRequest = await DeviceLost.create({
      description,
      user_email: user.email,
      startDate,
      endDate,
      device_fingerprint
    });


    // if user has no multiple devices, then flag them to do biometric false for forced 
    // fingerprint registration
    if (!user.hasDevices || !userDevices.length > 1) {
      user.doneBiometric = false
      user.authenticator = null

      // flag the device in question as lost
      const myLostDevice = await Devices.findOne({ device_fingerprint })
      myLostDevice.device_lost = true
      await myLostDevice.save()
    } else {
      // mark the other device(could be a browser check on that precisely) available as primary
      const primaryDevice = userDevices.find(d => d.device_fingerprint !== device_fingerprint)

      if (primaryDevice) {
        primaryDevice.device_primary = true
        await primaryDevice.save()
      }
    }


    // send message/notification to the admin+hr+supervisor
    await MessageAdmin.create({
      title,
      message,
      label: "urgent",
      status: 'pending',
      user_email: email,
      device_fingerprint
    })


    // mark user as device lost (temporary state)
    user.deviceLost = true;
    await user.save();


    res.json({
      message: "Lost device request submitted",
      data: lostRequest
    });

  } catch (err) {
    console.error("Lost device request error:", err);
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

    if (!["admin", "hr", "supervisor", "ceo"].includes(user.rank))
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

    if (!["admin", "hr", "supervisor"].includes(responder.rank))
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
      // mark all devices lost
      await Devices.updateMany(
        { user_email: affectedUser.email },
        { device_lost: true, device_primary: false }
      );

      // clear biometric (force re-registration)
      affectedUser.authenticator = undefined;
      affectedUser.doneBiometric = false;
      affectedUser.hasDevices = false;
      // affectedUser.deviceLost = false;
      affectedUser.deviceLost = true;

      await affectedUser.save();
    }

    // update the admin message
    const messageAdmin = await MessageAdmin.findOne({ device_fingerprint: request.device_fingerprint })
    messageAdmin.status = action
    messageAdmin.responded = responder.rank
    messageAdmin.respondedName = responder.name

    const message = generateAdminResponse(affectedUser, responder, action)

    // send message notification to the user (specific email)
    await MessageUser.create({
      label: 'none',
      message,
      title: "Lost Device Request",
      status: action,
      user_email: affectedUser.email
    })

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


// notifications

// HIGH RANK NOTIF
app.get(`${BASE_ROUTE}/admin/notification`, async (req, res) => {
  try {
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const acceptableRanks = ['admin', 'hr', 'supervisor']

    if (!acceptableRanks.includes(user.rank)) {
      throw new Error("unauthorized")
    }

    const messages = MessageAdmin.find({}).sort({ createdAt: -1 });
    res.json(messages)

  } catch (error) {
    res.status(400).send(err.message);
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
    res.status(400).send(err.message);
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
    // destroy the session
    req.session.destroy();
    // clear cookie if any
    res.clearCookie(process.env.SESSION_NAME);
    res.status(200).send("logged out successfully");
  } catch (error) {
    res.status(400).send(err.message);
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

    // Only admin/hr/ceo can manage users
    if (!["admin", "hr", "ceo"].includes(currentUser.rank))
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

    const allowedRanks = ["admin", "user", "hr", "supervisor", "ceo"];
    if (!allowedRanks.includes(rank))
      return res.status(400).json({ message: "Invalid rank value" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "ceo", "hr"].includes(currentUser.rank))
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
      "employee-contract",
    ];

    if (!allowedRoles.includes(role))
      return res.status(400).json({ message: "Invalid role value" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "ceo"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.role = role;
    await targetUser.save();

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

    if (!["admin", "hr", "ceo", "supervisor"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const users = await User.find().sort({ createdAt: -1 });

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

    if (!["admin", "hr", "ceo"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.department = department.trim();
    await targetUser.save();

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
    console.log(station)

    if (!station || station === undefined || station === null)
      return res.status(400).json({ message: "Station is required" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser)
      return res.status(404).json({ message: "Current user not found" });

    if (!["admin", "hr", "ceo", "supervisor"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    targetUser.station = station;
    await targetUser.save();

    res.json({
      message: `station updated successfully`,
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

    if (!["admin", "hr", "ceo"].includes(currentUser.rank))
      return res.status(403).json({ message: "Access denied" });

    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // fetch the gen user data for the potential supervisor be
    const supervisorInUserDB = await User.findOne({ email: supervisor.email })
    if (!supervisorInUserDB) {
      return res.status(404).json({ message: "Supervisor not found" });
    }
    // fetch the potential supervisor data in supervisor data
    const userInSupervisorDb = await Supervisor.findOne({ email: supervisor.email });
    if (!userInSupervisorDb)
      return res.status(404).json({ message: "Supervisor not found" });

    // Ensure supervisor has proper rank
    if (!["supervisor", "admin", "hr", "ceo"].includes(supervisorInUserDB.rank))
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

    if (new Date(req.body.endDate) < new Date(req.body.startDate)) {
      return res.status(400).json("end date should be higher than start date");
    }

    const leave = await Leave.create(req.body);
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

// update the leave
app.put(`${BASE_ROUTE}/admin/leave/:id`, async (req, res) => {
  try {
    const updatedLeave = await Leave.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.status(200).json(updatedLeave);
  } catch (error) {
    res.status(400).send(error.message);
  }
});


// delete leave
app.delete(`${BASE_ROUTE}/leave/:id`, async (req, res) => {
  try {
    await Leave.findByIdAndDelete(req.params.id);
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

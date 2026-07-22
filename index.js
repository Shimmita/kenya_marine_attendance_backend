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
import ldapjs from "ldapjs";
import mongoose from "mongoose";
import os from "os";
import sharp from "sharp";
import validator from "validator";
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
  formatDateKey,
  isPublicHoliday,
  isWeekend
} from "./util/Holiday.js";
import { SendMessageNow } from "./util/SendSMS.js";
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
const MAX_USER_DEVICES = 2;
const CLIENT_AUDIT_ACTIONS = {
  "attendance.history_exported": {
    category: "attendance",
    description: "Attendance history exported",
  },
};
const PASSWORD_RESET_CODE_TTL_MS = 1000 * 60 * 20;
const hashResetCode = (code) =>
  crypto.createHash("sha256").update(String(code)).digest("hex");
const generateResetCode = () =>
  String(Math.floor(100000 + Math.random() * 900000));

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
    rolling: true,
    saveUninitialized: false,
    name: process.env.SESSION_NAME,
    store,
    cookie: {
      maxAge: 60 * 20 * 1000,
      secure: environment !== "SANDBOX",
      sameSite: environment === "SANDBOX" ? "lax" : "none",
    },
  })
);

// ─── Auth check ───────────────────────────────────────────────────────────────

app.use(BASE_ROUTE, clearExpiredTemporaryAccountForSession);

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
    const { email, password, role } = data;

    if (!validator.isEmail(email)) throw new Error("Provided email is malformed!");
    if (!password || password.length < 4) throw new Error("Password must be at least 4 characters!");
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
      const startDate = new Date(data.startDate);
      const endDate = new Date(data.endDate);
      if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
        throw new Error("Start date and end date must be valid dates.");
      }
      if (startDate > endDate) {
        throw new Error("End date cannot be before start date.");
      }
    }


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
        { staffNo }
      ]
    });

    if (duplicate) {
      if (duplicate.email === email)
        throw new Error("User already registered!");

      if (duplicate.phone === normalizedPhone)
        throw new Error("Phone number already exists.");

      if (duplicate.employeeId === employeeId)
        throw new Error("Employee ID already exists.");

      if (duplicate.staffNo === staffNo)
        throw new Error("Staff Number already exists.");
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
    await SendMessageNow(createdUser)

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
      staffNo
    } = req.body.formData;

    if (!name?.trim())
      throw new Error("Full name is required.");

    if (!employeeId?.trim())
      throw new Error("Employee ID is required.");

    if (!staffNo?.trim())
      throw new Error("Staff number is required.");

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
        { staffNo }
      ]
    });

    if (duplicate) {
      if (duplicate.email === email)
        throw new Error("Email already exists.");

      if (duplicate.phone === normalizedPhone)
        throw new Error("Phone number already exists.");

      if (duplicate.employeeId === employeeId)
        throw new Error("Employee ID already exists.");

      if (duplicate.staffNo === staffNo)
        throw new Error("Staff Number already exists.");
    }

    const password = await bcrypt.hash(employeeId, 10);

    const createdUser = await User.create({
      name,
      email,
      phone: normalizedPhone,
      role: role || "employee",
      department,
      station,
      employeeId,
      staffNo,
      password
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
          staffNo: createdUser.staffNo
        }
      }
    });


    // send message to the reg staff
    await SendMessageNow(createdUser)

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
    const staffNoSet = new Set();
    const phoneSet = new Set();

    const emails = [];
    const employeeIds = [];
    const staffNos = [];
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
        const staffNo = user.staffNo?.toString().trim() || "";
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

        if (staffNo && staffNoSet.has(staffNo)) {
          errors.push(`Row ${row}: Duplicate Staff No in uploaded file.`);
          continue;
        }

        if (phoneSet.has(phone)) {
          errors.push(`Row ${row}: Duplicate phone number in uploaded file.`);
          continue;
        }

        emailSet.add(email);
        employeeIdSet.add(employeeId);
        phoneSet.add(phone);

        if (staffNo) {
          staffNoSet.add(staffNo);
          staffNos.push(staffNo);
        }

        emails.push(email);
        employeeIds.push(employeeId);
        phones.push(phone);

        validatedUsers.push({
          row,
          employeeId,
          staffNo,
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
        { staffNo: { $in: staffNos } },
        { phone: { $in: phones } }
      ]
    }).lean();

    const existingEmails = new Set(existingUsers.map(u => u.email));
    const existingEmployeeIds = new Set(existingUsers.map(u => u.employeeId));
    const existingStaffNos = new Set(existingUsers.map(u => u.staffNo).filter(Boolean));
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
        errors.push(`Row ${user.row}: Employee ID already exists.`);
        continue;
      }

      if (user.staffNo && existingStaffNos.has(user.staffNo)) {
        errors.push(`Row ${user.row}: Staff No already exists.`);
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
    await Promise.all(
      finalUsers.map(async user => {
        const defaultPassword =
          process.env.DEFAULT_PASSWORD_SUFFIX || user.employeeId;

        user.password = await bcrypt.hash(defaultPassword, 10);
        user.isPasswordReset = false;
      })
    );

    // 7. Batch insert all validated users
    const createdUsers = await User.insertMany(finalUsers, {
      ordered: false
    });


    // send message
    await Promise.allSettled(
      createdUsers.map(user => SendMessageNow(user))
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

    return res.status(200).json(sanitizeUserResponse(user));
  } catch (error) {
    console.error("Signin error:", error);
    return res.status(400).json({ message: error.message });
  }
});


// ─── LDAP Authentication Helper ───────────────────────────────────────────────

const LDAP_TIMEOUT_MS = 5000; // 5 second timeout for LDAP connection
const LDAP_REQUEST_TIMEOUT_MS = 10000; // 10 second timeout for entire LDAP auth process

const authenticateWithLDAP = async (userId, password) => {
  const url = process.env.LDAP_URL;
  const baseDN = process.env.LDAP_BASE_DN;

  // Create LDAP client with timeout settings
  const client = ldapjs.createClient({
    url,
    timeout: LDAP_TIMEOUT_MS,
    connectTimeout: LDAP_TIMEOUT_MS,
  });

  // Handle connection errors at the client level
  client.on('error', (err) => {
    console.error('LDAP client error:', err.code, err.message);
  });

  const tryBind = (dn) =>
    new Promise((resolve, reject) => {
      client.bind(dn, password, (err) => {
        if (err) return reject(err);
        resolve(true);
      });
    });

  // Wrap entire LDAP process in a timeout promise  
  return Promise.race([
    // Main LDAP authentication logic
    (async () => {
      try {
        //  1. UPN
        try {
          const upn = `${userId}${process.env.UPN_METHOD_URL}`;
          await tryBind(upn);
          return { success: true, method: "UPN" };
        } catch (err) {
          console.log("UPN failed:", err.message);
        }

        //  2. DOMAIN
        try {
          const domainUser = `${process.env.LDAP_DOMAIN}\\${userId}`;
          await tryBind(domainUser);
          return { success: true, method: "DOMAIN" };
        } catch (err) {
          console.log("DOMAIN failed:", err.message);
        }

        //  3. SEARCH + BIND
        return new Promise((resolve, reject) => {
          client.bind(
            process.env.LDAP_BIND_DN,
            process.env.LDAP_BIND_PASSWORD,
            (err) => {
              if (err) {
                console.log("Service bind failed:", err.message);
                return reject(new Error("Invalid credentials!"));
              }

              const opts = {
                scope: "sub",
                filter: `(|(sAMAccountName=${userId})(employeeID=${userId})(cn=${userId}))`,
                attributes: ["dn"],
              };

              client.search(baseDN, opts, (err, res) => {
                if (err) return reject(err);

                let userDN = null;

                res.on("searchEntry", (entry) => {
                  userDN = entry.objectName;
                  console.log("Found user DN:", userDN);
                });

                res.on("end", async () => {
                  if (!userDN) {
                    return reject(new Error("User not found!"));
                  }

                  try {
                    await tryBind(userDN);
                    resolve({ success: true, method: "SEARCH" });
                  } catch (err) {
                    console.log("Final bind failed:", err.message);
                    reject(new Error("Invalid credentials!"));
                  }
                });
              });
            }
          );
        });
      } catch (err) {
        throw err;
      } finally {
        client.unbind();
      }
    })(),
    // Timeout promise - rejects after LDAP_REQUEST_TIMEOUT_MS
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("ETIMEDOUT")),
        LDAP_REQUEST_TIMEOUT_MS
      )
    ),
  ]).catch((err) => {
    // Ensure cleanup on any error
    try {
      client.unbind();
    } catch (e) {
      // ignore unbind errors
    }
    throw err;
  });
};



// ─── Sign In (Staff - LDAP) ──────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signin-staff`, async (req, res) => {
  const { userId, password } = req.body;

  try {
    if (!userId || !userId.trim()) {
      throw new Error("User ID is required");
    }
    if (!password || !password.trim()) {
      throw new Error("Password is required");
    }

    //  1. Authenticate with LDAP
    const isValidStaff = await authenticateWithLDAP(userId, password);

    if (!isValidStaff.success) {
      throw new Error("Invalid credentials!");
    }

    //  2. Find user in DB (employeeId match)
    const user = await User.findOne({ employeeId: userId });

    if (!user) {
      throw new Error("You don't have access contact HR !");
    }


    //  3. Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    //  4. Update password
    user.password = hashedPassword;
    user.isPasswordReset = true;

    await user.save();

    // create session for the currenly logged in user
    req.session.isOnline = true;
    req.session.userID = user._id.toString();

    await createAuditLog({
      req,
      category: "authentication",
      action: "auth.signin",
      description: "User signed in",
      actor: user,
      metadata: { signInMethod: "ldap" },
    });

    return res.status(200).json(sanitizeUserResponse(user));

  } catch (error) {
    console.error("Staff signin error:", error);

    let message = error.message;
    let statusCode = 400;

    // Handle various LDAP connection errors gracefully
    if (error.code === "ETIMEDOUT" || message?.includes("ETIMEDOUT") || message?.includes("timeout")) {
      message = "Active Directory server is currently unavailable. Please try again later or contact your administrator.";
      statusCode = 503; // Service Unavailable
    } else if (error.code === "ECONNREFUSED" || message?.includes("ECONNREFUSED")) {
      message = "Active Directory server is unreachable. Please try again later or contact your administrator.";
      statusCode = 503;
    } else if (error.code === "ENOTFOUND" || message?.includes("ENOTFOUND")) {
      message = "Active Directory server address not found. Please contact your administrator.";
      statusCode = 503;
    } else if (message?.includes("Invalid credentials") || message?.includes("User not found")) {
      message = "Invalid credentials. Please check your user ID and password.";
      statusCode = 401; // Unauthorized
    }

    return res.status(statusCode).json({ message });
  }
});



// ─── Password Reset ───────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/request-password-reset`, async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email");

    const user = await User.findOne({ email });
    if (!user) {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.request_rejected",
        description: "Password reset requested for unknown email",
        actor: { email, name: email },
        metadata: { reason: "user_not_found" },
        status: "failed",
      });
      throw new Error("No account was found for that email address");
    }

    // Only interns and attachees may use this password reset flow; staff/employees use AD
    if (user.role === "employee") {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.request_rejected",
        description: "Password reset requested for AD-managed account",
        actor: user,
        target: user,
        metadata: { reason: "ad_managed_account" },
        status: "failed",
      });
      return res.status(403).json({ message: "This account is managed by Active Directory. Contact ICT support to reset your password." });
    }

    const resetCode = generateResetCode();
    const expiresAt = new Date(Date.now() + PASSWORD_RESET_CODE_TTL_MS);
    const existing = await PasswordReset.findOne({ email });

    // If there's an active (non-expired) reset request, notify the requester
    if (existing && existing.expiresAt && existing.expiresAt.getTime() > Date.now()) {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.request_duplicate",
        description: "Duplicate password reset request while a pending request exists",
        actor: { email, name: email },
        target: user,
        metadata: { email, existingExpiresAt: existing.expiresAt.toISOString() },
        status: "failed",
      });

      return res.status(409).json({
        message:
          "You have a previous password reset request pending. Contact System administrator at ICT department.",
        email,
      });
    }

    // Either create a new reset entry or overwrite an expired/old one
    if (existing) {
      existing.codeHash = hashResetCode(resetCode);
      existing.expiresAt = expiresAt;
      existing.lastSentAt = new Date();
      existing.attempts = 0;
      await existing.save();
    } else {
      await PasswordReset.create({
        email,
        codeHash: hashResetCode(resetCode),
        expiresAt,
        lastSentAt: new Date(),
      });
    }

    /* await transporter.sendMail({
      from: `"KMFRI ICT Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "KMFRI Password Reset Code",
      html: `
        <div style="font-family:Arial,Helvetica,sans-serif;max-width:580px;margin:0 auto;padding:24px;background:#f8fbfd;border-radius:16px;border:1px solid #d8e6ef;">
          <div style="background:linear-gradient(135deg,#0a3560 0%,#0a5b8c 100%);padding:20px;border-radius:14px;color:#fff;">
            <h2 style="margin:0 0 8px;">Password Reset Request</h2>
            <p style="margin:0;opacity:0.9;">Use the code below to reset your KMFRI attendance account password.</p>
          </div>
          <div style="padding:24px 8px 8px;">
            <p style="font-size:15px;color:#12344d;">Hi ${user.name || "there"},</p>
            <p style="font-size:15px;color:#12344d;line-height:1.6;">Enter this verification code on the password reset page to continue:</p>
            <div style="margin:22px 0;padding:18px 20px;background:#ffffff;border:1px dashed #0a5b8c;border-radius:14px;text-align:center;">
              <span style="font-size:32px;letter-spacing:10px;font-weight:800;color:#0a3560;">${resetCode}</span>
            </div>
            <p style="font-size:14px;color:#486581;line-height:1.6;">This code expires in 15 minutes. If you did not request a password reset, you can ignore this email.</p>
            <p style="font-size:14px;color:#486581;line-height:1.6;">Reset page: <a href="${process.env.FRONTEND_URL || ""}/reset-password" style="color:#0a5b8c;font-weight:700;">Open password reset</a></p>
          </div>
        </div>
      `,
    }); */

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.code_sent",
      description: "Password reset code sent by email",
      actor: user,
      target: user,
      metadata: { email, expiresAt: expiresAt.toISOString() },
    });

    res.json({
      status: "code_sent",
      message: "A password reset request has been initiated. Contact System administrator at ICT department.",
      email,
    });
  } catch (err) {
    console.error("Request password reset error:", err);
    res.status(400).json({ message: err.message });
  }
});

app.post(`${BASE_ROUTE}/auth/reset-password`, async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");
    if (!code) throw new Error("Reset code is required");
    if (!newPassword || newPassword.length < 6) {
      throw new Error("Password must be at least 6 characters");
    }

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    const resetRequest = await PasswordReset.findOne({ email });
    if (!resetRequest) {
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.verification_failed",
        description: "Password reset attempted without active request",
        actor: { email, name: email },
        target: user,
        metadata: { reason: "missing_request" },
        status: "failed",
      });
      throw new Error("No active password reset request was found for this email");
    }

    if (resetRequest.expiresAt && resetRequest.expiresAt.getTime() < Date.now()) {
      await PasswordReset.deleteOne({ email });
      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.verification_failed",
        description: "Expired password reset code used",
        actor: { email, name: email },
        target: user,
        metadata: { reason: "expired_code" },
        status: "failed",
      });
      throw new Error("This reset code has expired. Please request a new one");
    }

    const matches = resetRequest.codeHash === hashResetCode(code);
    if (!matches) {
      resetRequest.attempts = (resetRequest.attempts || 0) + 1;
      await resetRequest.save();

      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.verification_failed",
        description: "Invalid password reset code submitted",
        actor: { email, name: email },
        target: user,
        metadata: { reason: "invalid_code", attempts: resetRequest.attempts },
        status: "failed",
      });
      throw new Error("The reset code you entered is invalid");
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.isPasswordReset = false;
    await user.save();
    await PasswordReset.deleteOne({ email });

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.completed",
      description: "Password reset completed using emailed code",
      actor: user,
      target: user,
      metadata: { email },
    });

    res.json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(400).json({ message: error.message });
  }
});

app.get(`${BASE_ROUTE}/admin/password-reset/requests`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) return res.status(401).json({ message: "Unauthorized" });
    // only admin or superadmin can view
    if (!["admin", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Access denied, only admin or superadmin can view password reset requests." });
    }

    const requests = await PasswordReset.find().sort({ createdAt: -1 }).lean();
    const enriched = await Promise.all(requests.map(async (request) => {
      const user = await User.findOne({ email: request.email }).lean();
      return {
        ...request,
        userName: user?.name || "Unknown User",
        role: user?.role || "Unknown",
        department: user?.department || "",
        station: user?.station || "",
        userIsPasswordReset: Boolean(user?.isPasswordReset),
      };
    }));

    res.json(enriched);
  } catch (error) {
    console.error("Fetch password reset requests error:", error);
    res.status(500).json({ message: "Failed to load password reset requests" });
  }
});

app.put(`${BASE_ROUTE}/admin/password-reset/approve`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "Unauthorized" });

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser) return res.status(401).json({ message: "Unauthorized" });
    if (!["admin", "superadmin"].includes(currentUser.rank))
      return res.status(403).json({ message: "Only admin can approve password reset requests" });

    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email });
    const resetRequest = await PasswordReset.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!resetRequest) return res.status(404).json({ message: "Password reset request not found" });

    const newPassword = String(req.body?.newPassword || "");

    // If admin provided a new password, perform the reset immediately
    if (newPassword) {
      if (newPassword.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });

      user.password = await bcrypt.hash(newPassword, 10);
      user.isPasswordReset = false;
      await user.save();

      // Remove the reset request after successful admin reset
      await PasswordReset.deleteOne({ email });

      // Send email notification to user
      /* await transporter.sendMail({
        from: `"KMFRI ICT Support" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Your Password Has Been Reset",
        html: `
          <div style="font-family:Arial,Helvetica,sans-serif;max-width:580px;margin:0 auto;padding:24px;background:#f8fbfd;border-radius:16px;border:1px solid #d8e6ef;">
            <div style="background:linear-gradient(135deg,#0a3560 0%,#0a5b8c 100%);padding:20px;border-radius:14px;color:#fff;">
              <h2 style="margin:0 0 8px;">Password Reset Complete</h2>
              <p style="margin:0;opacity:0.9;">Your KMFRI attendance account password has been reset by the administrator.</p>
            </div>
            <div style="padding:24px 8px 8px;">
              <p style="font-size:15px;color:#12344d;">Hi ${user.name || "there"},</p>
              <p style="font-size:15px;color:#12344d;line-height:1.6;">Your password has been reset by the ICT administrator. You can now sign in with your new password.</p>
              <p style="font-size:15px;color:#12344d;line-height:1.6;"><strong>New password:</strong> ${newPassword}</p>
              <p style="font-size:14px;color:#d97706;line-height:1.6;"><strong>⚠️ Important:</strong> Please change this password immediately after logging in for security reasons.</p>
              <p style="font-size:14px;color:#486581;line-height:1.6;">If you did not request a password reset, please contact ICT support immediately.</p>
            </div>
          </div>
        `,
      }); */

      await createAuditLog({
        req,
        category: "password_reset",
        action: "password_reset.admin_reset",
        description: "Admin performed password reset and set a new password",
        actor: currentUser,
        target: user,
        metadata: { email, approvedBy: currentUser.email, method: "admin_set_password" },
      });

      return res.json({ message: `Password for ${email} has been reset by admin`, email, reset: true });
    }

    // Backwards compatible behavior: mark user as awaiting reset (legacy flow)
    user.isPasswordReset = true;
    await user.save();

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.admin_approved",
      description: "Admin approved password reset request (awaiting admin-provided password)",
      actor: currentUser,
      target: user,
      metadata: { email, approvedBy: currentUser.email },
    });

    res.json({ message: `Password reset request for ${email} has been approved`, email, approved: true });
  } catch (error) {
    console.error("Approve password reset request error:", error);
    res.status(500).json({ message: error.message || "Failed to approve password reset request" });
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

    } catch (error) {
      res.status(500).json({ message: "Failed to update profile" });
    }
  }
);



// ─── Biometrics ───────────────────────────────────────────────────────────────

/**
 * 1. Generate Registration Challenge
 */
app.get(`${BASE_ROUTE}/biometric/register/challenge`, async (req, res) => {
  try {
    if (!req.session.isOnline) return res.status(401).json({ message: "session expired, logout and login again to proceed!" });

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const activeDevices = await getActiveUserDevices(user.email);
    if (activeDevices.length >= MAX_USER_DEVICES) {
      throw new Error(`You can only enroll up to ${MAX_USER_DEVICES} devices. Report a lost device or contact admin to clear one.`);
    }

    // temp fix so that it can register outside google emails
    // can make use of platform to force using device bound auth
    /* const options = await generateRegistrationOptions({
      rpName: "KMFRI Attendance",
      rpID: getRpID(),
      userID: Uint8Array.from(Buffer.from(user._id.toString())),
      userName: user.email,
      authenticatorSelection: { userVerification: "required" },
    }); */

    const existingAuthenticators = getUserAuthenticators(user);

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
      timeout: 60000,

      // prevents duplicate registrations
      excludeCredentials: existingAuthenticators.map((authenticator) => ({
        id: authenticator.credentialID,
        type: "public-key",
        transports: ["internal"],
      })),
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
    const activeDevices = await getActiveUserDevices(user.email);
    const activeDeviceFingerprints = activeDevices.map((device) => device.device_fingerprint);
    const authenticators = getUserAuthenticators(user).filter(
      (authenticator) =>
        !authenticator.deviceFingerprint ||
        activeDeviceFingerprints.includes(authenticator.deviceFingerprint)
    );
    if (!user || authenticators.length === 0) {
      return res.status(400).json({ message: "Biometric not registered for this account" });
    }

    const options = await generateAuthenticationOptions({
      rpID: getRpID(),

      userVerification: "required",

      // improves auth reliability across devices
      timeout: 30000,

      allowCredentials: [...new Map(
        authenticators.map((authenticator) => [
          authenticator.credentialID,
          {
            id: authenticator.credentialID,
            type: "public-key",

            // force device/platform auth only
            transports: ["internal"],
          },
        ])
      ).values()],
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
  if (!user || !user.isToClockOut) return user;

  const latestOpen = await Clocking.findOne({ email: user.email, clock_out: null }).sort({ clock_in: -1 });
  if (!latestOpen) return user;

  if (!isBeforeNairobiDate(latestOpen.clock_in, now)) return user;

  latestOpen.missedClockOut = true;
  latestOpen.isPresent = true;
  await latestOpen.save();

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
app.post(`${BASE_ROUTE}/biometric/auth/verify`, async (req, res) => {
  try {
    // metadata returned to client for debugging/confirmation
    let verifyResultMeta = { clockedOutside: false, outsideLocation: null };
    if (!req.session.isOnline) {
      return res.status(401).json({ verified: false, message: "Unauthorized" });
    }

    let user = await clearExpiredOutsideClocking(await User.findById(req.session.userID));
    user = await finalizeStaleClocking(user);
    const authenticators = getUserAuthenticators(user);
    if (!user || authenticators.length === 0) {
      return res.status(400).json({ verified: false, message: "Fingerprint not registered" });
    }

    const expectedChallenge = req.session.authChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({
        verified: false,
        message: "No auth challenge found. Please restart.",
      });
    }

    // extract selected station, optional outsideLocation and auth response from request body
    const { selectedStation, userCoords, device_fingerprint, outsideLocation, ...authResponse } = req.body;
    const matchedAuthenticator =
      authenticators.find(
        (authenticator) =>
          authenticator.credentialID === authResponse.id &&
          authenticator.deviceFingerprint === device_fingerprint
      ) ||
      authenticators.find(
        (authenticator) =>
          authenticator.credentialID === authResponse.id &&
          !authenticator.deviceFingerprint
      ) ||
      authenticators.find(
        (authenticator) => authenticator.credentialID === authResponse.id
      );

    if (!matchedAuthenticator) {
      return res.status(401).json({ verified: false, message: "This device is not enrolled for clocking." });
    }

    const matchedDevice = await Devices.findOne({
      user_email: user.email,
      device_fingerprint: matchedAuthenticator.deviceFingerprint || device_fingerprint,
      device_lost: { $ne: true },
    });

    if (!matchedDevice) {
      return res.status(403).json({ verified: false, message: "This device has not been approved for clocking." });
    }

    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
      // ✅ v10+ shape: `credential` not `authenticator`, `id` not `credentialID`,
      //    `publicKey` (Uint8Array) not `credentialPublicKey` (Buffer)
      credential: {
        id: matchedAuthenticator.credentialID,                                         // base64url string
        publicKey: new Uint8Array(
          Buffer.from(matchedAuthenticator.credentialPublicKey, "base64url")           // base64url → Uint8Array
        ),
        counter: matchedAuthenticator.counter,
      },
      requireUserVerification: true,
    });

    if (!verification.verified) return res.status(401).json({ verified: false });

    // Update counter to prevent replay attacks
    user.authenticators = authenticators.map((authenticator) =>
      authenticator.credentialID === matchedAuthenticator.credentialID &&
        (authenticator.deviceFingerprint || "") === (matchedAuthenticator.deviceFingerprint || "")
        ? {
          ...(authenticator.toObject?.() || authenticator),
          counter: verification.authenticationInfo.newCounter,
          lastUsedAt: new Date(),
        }
        : authenticator
    );
    user.authenticator = undefined;

    // save in the db
    await user.save();

    // save clocking in data in East African Time (EAT) timezone
    if (!user?.hasClockedIn && !user?.isToClockOut) {

      const now = new Date();

      // Convert to Nairobi time
      const eatTime = new Date(
        now.toLocaleString("en-US", { timeZone: "Africa/Nairobi" })
      );

      const attendancePolicy = await getAttendancePolicy();
      const targetClockIn = parseAttendanceTime(attendancePolicy.standardClockIn || '08:00', eatTime) || eatTime;
      const graceMinutes = Number(attendancePolicy.gracePeriodMinutes ?? 15);
      const graceDeadline = new Date(targetClockIn.getTime() + graceMinutes * 60 * 1000);
      const isLate = eatTime > graceDeadline;
      const isEmployee = user.role === "employee";

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
        userLocation: {
          latitude: userCoords?.latitude || null,
          longitude: userCoords?.longitude || null,
        }
      };

      const canClockOutsideNow = isOutsideClockingAuthorizedNow(user, now);

      // Only persist outside-clock metadata while the user's dated authorization is active.
      if (canClockOutsideNow) {
        clockingData.outsideLocation = outsideLocation || "";
        clockingData.clockInLocationName = outsideLocation || "";
        clockingData.clockedOutSide = true;
        clockingData.outSideReason = user.outsideClockingDetails?.reason || "";
        verifyResultMeta.clockedOutside = true;
        verifyResultMeta.outsideLocation = outsideLocation || null;
      } else {
        if (outsideLocation) {
          console.debug('outsideLocation provided but user not authorized', { email: user.email, canClockOutside: user.canClockOutside, outsideClockingDetails: user.outsideClockingDetails });
        }
      }

      await Clocking.create(clockingData);

      user.hasClockedIn = true;
      user.isToClockOut = true;

      await user.save();

      await createAuditLog({
        req,
        category: "attendance",
        action: "attendance.clock_in",
        description: "User clocked in",
        actor: user,
        metadata: {
          station: selectedStation,
          clockedOutside: verifyResultMeta.clockedOutside,
          outsideLocation: verifyResultMeta.outsideLocation,
          userLocation: clockingData.userLocation,
        },
      });
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

      const canClockOutsideNow = isOutsideClockingAuthorizedNow(user, now);

      if (canClockOutsideNow) {
        latestClocking.clockOutLocationName = outsideLocation || "";
        latestClocking.outsideLocation = latestClocking.outsideLocation || outsideLocation || "";
        latestClocking.clockedOutSide = true;
        latestClocking.outSideReason = user.outsideClockingDetails?.reason || latestClocking.outSideReason || "";
        verifyResultMeta.clockedOutside = true;
        verifyResultMeta.outsideLocation = outsideLocation || null;
      } else if (outsideLocation) {
        console.debug('outsideLocation provided at clock-out but user not authorized', { email: user.email, canClockOutside: user.canClockOutside, outsideClockingDetails: user.outsideClockingDetails });
      }

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

      await createAuditLog({
        req,
        category: "attendance",
        action: "attendance.clock_out",
        description: "User clocked out",
        actor: user,
        metadata: {
          station: latestClocking.station,
          workedHours: Number(diffHours.toFixed(2)),
          isPresent: latestClocking.isPresent,
          clockedOutside: verifyResultMeta.clockedOutside,
          outsideLocation: verifyResultMeta.outsideLocation,
        },
      });
    }


    req.session.biometricVerified = true;
    req.session.biometricVerifiedAt = Date.now();
    delete req.session.authChallenge;
    // include metadata so frontend can show whether outsideLocation was saved
    res.json({ verified: true, meta: verifyResultMeta });
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
          dailyMap[dateKey] = { hours: 0, isLateAny: false, isEarlyAny: false, clockings: 0, missedClockOut: false };
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
        if (day.hours >= 5) presentDays++;
        else if (day.hours > 0) halfDays++;
        else if (day.missedClockOut) presentDays++;

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
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    // get the query
    const {
      station = "",
      department = "",
    } = req.query;

    // get config for stations and depart from platform config
    const config = await PlatformConfig.getSingleton();

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const workingDaysSoFar =
      Math.ceil((now - startOfMonth) / (1000 * 60 * 60 * 24));

    const userFilter = {};

    if (station) {
      userFilter.station = station;
    }

    if (department) {
      userFilter.department = department;
    }

    const allUsers = await User.find(
      userFilter,
      "email name department station isAccountActive role"
    );

    const emails = allUsers.map((u) => u.email);

    const records = await Clocking.find({
      email: { $in: emails },
      clock_in: { $gte: startOfMonth },
    });

    const totalStaff = allUsers.length;



    const stats = {
      orgTotalHours: 0,
      orgTotalOvertime: 0,
      stations: {},
      employeeMetrics: {},
      inactiveUsers: allUsers.filter(u => !u.isAccountActive).length
    };

    // -----------------------------------
    // PROCESS RECORDS
    // -----------------------------------

    records.forEach(rec => {
      const email = rec.email;
      const station = rec.station || "Unassigned";
      const department = rec.department || "Unassigned";

      if (!stats.employeeMetrics[email]) {
        stats.employeeMetrics[email] = {
          hours: 0,
          overtime: 0,
          lateCount: 0,
          earlyCount: 0,
          daysPresent: new Set()
        };
      }

      let hoursWorked = 0;

      if (rec.clock_out) {
        hoursWorked =
          (rec.clock_out - rec.clock_in) / (1000 * 60 * 60);

        stats.employeeMetrics[email].hours += hoursWorked;

        if (hoursWorked > 9) {
          stats.employeeMetrics[email].overtime += hoursWorked - 9;
        }

        stats.employeeMetrics[email].daysPresent.add(
          rec.clock_in.toDateString()
        );
      }

      if (rec.isLate) stats.employeeMetrics[email].lateCount++;
      else stats.employeeMetrics[email].earlyCount++;

      // -----------------------------------
      // STATION INIT
      // -----------------------------------

      if (!stats.stations[station]) {
        stats.stations[station] = {
          totalHours: 0,
          totalOvertime: 0,
          totalCheckins: 0,
          lateCount: 0,
          staffSet: new Set(),
          departments: {},
          employeeScores: []
        };
      }

      const stationObj = stats.stations[station];

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

      if (!stationObj.departments[department]) {
        stationObj.departments[department] = {
          totalHours: 0,
          totalOvertime: 0,
          lateCount: 0,
          staffSet: new Set(),
          employeeScores: []
        };
      }

      const deptObj = stationObj.departments[department];

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
      const user = allUsers.find(u => u.email === email);
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
        ((station.lateCount / station.totalCheckins) * 100).toFixed(1) + "%";

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
          ((dept.lateCount / dept.headcount) * 100).toFixed(1) + "%";

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
        activeStaffThisMonth: Object.keys(stats.employeeMetrics).length,
        inactiveAccounts: stats.inactiveUsers,
        totalOrgHours: stats.orgTotalHours.toFixed(1),
        totalOrgOvertime: stats.orgTotalOvertime.toFixed(1),
        averageStaffEfficiency:
          ((stats.orgTotalHours / (totalStaff * 160)) * 100).toFixed(1) + "%"
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


// ============================================================================
// ADMIN - ATTENDANCE RECORDS
// ============================================================================

app.get(`${BASE_ROUTE}/overall/attendance/records`, async (req, res) => {
  try {

    if (!req.session.isOnline) {
      return res.status(401).json({
        message: "Unauthorized Access"
      });
    }

    const {
      station,
      department,
      role,
      rank,
      startDate,
      endDate,
    } = req.query;

    //----------------------------------------------------
    // Attendance Query
    //----------------------------------------------------

    const attendanceQuery = {};

    const start = startDate
      ? new Date(startDate)
      : new Date(
        new Date().getFullYear(),
        new Date().getMonth(),
        1
      );

    const end = endDate
      ? new Date(endDate)
      : new Date();

    end.setHours(23, 59, 59, 999);

    attendanceQuery.clock_in = {
      $gte: start,
      $lte: end
    };

    //----------------------------------------------------
    // User Query
    //----------------------------------------------------

    const userQuery = {};

    if (role && role !== "all") {
      userQuery.role = role;
    }

    if (rank && rank !== "all") {
      userQuery.rank = rank;
    }

    if (station && station !== "all") {
      userQuery.station = station;
    }

    if (department && department !== "all") {
      userQuery.department = department;
    }

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
    if (!req.session.isOnline) {
      return res.status(401).json({
        message: "Unauthorized Access",
      });
    }

    const {
      startDate,
      endDate,
      station,
      department,
      role,
      rank,
    } = req.query;

    //---------------------------------------------------------
    // Date Range
    //---------------------------------------------------------

    const start = startDate
      ? new Date(startDate)
      : new Date(
        new Date().getFullYear(),
        new Date().getMonth(),
        1
      );

    const end = endDate
      ? new Date(endDate)
      : new Date();

    end.setHours(23, 59, 59, 999);

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
          formatDateKey(current)
        );
      }

      current.setDate(current.getDate() + 1);
    }

    const totalWorkingDays = workingDates.length;

    //---------------------------------------------------------
    // User Filters
    //---------------------------------------------------------

    const userQuery = {};

    if (station && station !== "all")
      userQuery.station = station;

    if (department && department !== "all")
      userQuery.department = department;

    if (role && role !== "all")
      userQuery.role = role;

    if (rank && rank !== "all")
      userQuery.rank = rank;

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

      const dateKey = formatDateKey(record.clock_in);

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

    const dateKey = (date) => new Date(date).toISOString().split("T")[0];
    const hourDecimal = (date) => {
      const d = new Date(date);
      return d.getHours() + d.getMinutes() / 60;
    };
    const hourLabel = (value) => {
      if (value == null || Number.isNaN(value)) return "—";
      const h = Math.floor(value);
      const m = Math.round((value - h) * 60);
      return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
    };
    const countWeekdays = (start, end) => {
      let count = 0;
      const cursor = new Date(start);
      cursor.setHours(0, 0, 0, 0);
      const last = new Date(end);
      last.setHours(0, 0, 0, 0);
      while (cursor <= last) {
        const day = cursor.getDay();
        if (day !== 0 && day !== 6) count++;
        cursor.setDate(cursor.getDate() + 1);
      }
      return Math.max(count, 1);
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
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
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

        metric.daysPresent.add(rec.clock_in.toDateString());

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

    if (new Date(req.body.endDate) < new Date(req.body.startDate)) {
      return res.status(400).json("end date should be higher than start date");
    }

    const leave = await Leave.create(req.body);

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

    if (currentSupervisor.rank !== "supervisor")
      return res.status(403).json({
        message: "Selected user is not eligible to be a supervisor",
      });

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

    // 4. Update Target User
    const targetUser = await User.findById(req.params.id);
    if (!targetUser)
      return res.status(404).json({ message: "User not found" });

    // Update the permission and the details
    targetUser.canClockOutside = true;
    targetUser.outsideClockingDetails = {
      startDate: new Date(startDate),
      endDate: new Date(endDate),
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
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser || !["auditor", "admin", "superadmin"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Access denied" });
    }

    const {
      category = "all",
      action = "all",
      actorRank = "all",
      search = "",
      dateFrom,
      dateTo,
      limit = 250,
    } = req.query;

    const parsedLimit = Math.min(Math.max(Number(limit) || 250, 1), 500);
    const query = {};

    if (category !== "all") query.category = category;
    if (action !== "all") query.action = action;
    if (actorRank !== "all") query["actor.rank"] = actorRank;

    if (dateFrom || dateTo) {
      query.occurredAt = {};
      if (dateFrom) {
        query.occurredAt.$gte = new Date(`${dateFrom}T00:00:00.000Z`);
      }
      if (dateTo) {
        query.occurredAt.$lte = new Date(`${dateTo}T23:59:59.999Z`);
      }
    }

    if (search?.trim()) {
      const regex = new RegExp(search.trim(), "i");
      query.$or = [
        { action: regex },
        { description: regex },
        { "actor.name": regex },
        { "actor.email": regex },
        { "target.name": regex },
        { "target.email": regex },
      ];
    }

    const logs = await AuditLog.find(query)
      .sort({ occurredAt: -1 })
      .limit(parsedLimit)
      .lean();

    const categoryCounts = logs.reduce((acc, log) => {
      acc[log.category] = (acc[log.category] || 0) + 1;
      return acc;
    }, {});

    const actionCounts = logs.reduce((acc, log) => {
      acc[log.action] = (acc[log.action] || 0) + 1;
      return acc;
    }, {});

    const uniqueActors = new Set(
      logs
        .map((log) => log.actor?.email || log.actor?.userId || "")
        .filter(Boolean)
    ).size;

    const privilegedActions = logs.filter((log) =>
      PRIVILEGED_AUDIT_RANKS.includes(log.actor?.rank)
    ).length;

    res.json({
      logs,
      metrics: {
        total: logs.length,
        uniqueActors,
        privilegedActions,
        today: logs.filter((log) => {
          const current = new Date(log.occurredAt);
          const now = new Date();
          return current.toDateString() === now.toDateString();
        }).length,
      },
      categoryCounts,
      actionCounts,
    });
  } catch (error) {
    console.error("Fetch audit logs error:", error);
    res.status(500).json({ message: "Failed to fetch audit logs" });
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
  } catch (error) {
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

  } catch (err) {
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

  } catch (err) {
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


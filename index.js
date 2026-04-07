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
import Supervisor from "./model/Supervisor.js";
import User from "./model/User.js";
import Verification from "./model/VerifyReport.js";
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
const PRIVILEGED_AUDIT_RANKS = ["admin", "hr"];
const CLIENT_AUDIT_ACTIONS = {
  "attendance.history_exported": {
    category: "attendance",
    description: "Attendance history exported",
  },
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
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const currentUser = await User.findById(req.session.userID);
    if (!["hr"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Access denied, only HR personnel can create accounts." });
    }

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

// ─── Batch User Registration (HR Only) ────────────────────────────────────────

app.post(`${BASE_ROUTE}/admin/batch-register`, async (req, res) => {
  try {
    //  1. Check if user is authenticated
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized. Please log in first." });
    }

    //  2. Verify user has HR rank
    const currentUser = await User.findById(req.session.userID);
    if (!currentUser || !["hr"].includes(currentUser.rank)) {
      return res.status(403).json({ message: "Only HR personnel can perform this operation." });
    }

    //  3. Validate request body
    const { users } = req.body;
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(400).json({ message: "Please provide at least one record of data" });
    }


    //  5. Validate and prepare user data
    const validatedUsers = [];
    const errors = [];

    for (let i = 0; i < users.length; i++) {
      const user = users[i];

      try {
        // Required fields validation
        if (!user.email || !validator.isEmail(user.email)) {
          errors.push(`Row ${i + 1}: Invalid or missing email.`);
          continue;
        }

        if (!user.name || user.name.trim().length === 0) {
          errors.push(`Row ${i + 1}: Name is required.`);
          continue;
        }

        if (!user.employeeId || user.employeeId.toString().trim().length === 0) {
          errors.push(`Row ${i + 1}: Employee ID is required.`);
          continue;
        }

        // Check for duplicate email in batch
        if (validatedUsers.some(u => u.email === user.email)) {
          errors.push(`Row ${i + 1}: Duplicate email in batch.`);
          continue;
        }

        // Check if email already exists in database
        const existingUser = await User.findOne({ email: user.email });
        if (existingUser) {
          errors.push(`\nRow ${i + 1}: ${existingUser.email} Email already registered.`);
          continue;
        }

        // Check if employeeId already exists
        const existingEmployee = await User.findOne({ employeeId: user.employeeId });
        if (existingEmployee) {
          errors.push(`\nRow ${i + 1}: ${existingEmployee.employeeId} Employee ID already exists.`);
          continue;
        }

        // Generate default password, interns and attachee default password
        const defaultPassword = process.env.DEFAULT_PASSWORD_SUFFIX || existingEmployee.employeeId;
        const hashedPassword = await bcrypt.hash(defaultPassword, 10);

        // Prepare user object
        validatedUsers.push({
          employeeId: user.employeeId.toString().trim(),
          staffNo: user.staffNo || '',
          name: user.name.trim(),
          email: user.email.toLowerCase().trim(),
          phone: user.phone || '',
          role: user.role || 'employee', // employee, attachee, etc.
          station: user.station || '',
          department: user.department || '',
          gender: user.gender || '',
          password: hashedPassword,
          email_verified: false,
          isPasswordReset: false,
        });
      } catch (error) {
        errors.push(`Row ${i + 1}: ${error.message}`);
      }
    }

    // 6. If there are validation errors, return them
    if (errors.length > 0) {
      return res.status(400).json({
        message: `Validation failed. ${errors.length} error(s) found.\n ${errors.slice(0, 20).join("\n")}`,
        errors: errors.slice(0, 20), // Return first 20 errors
        totalErrors: errors.length
      });
    }

    // 7. Batch insert all validated users
    const createdUsers = await User.insertMany(validatedUsers, { ordered: false });

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
    console.error("Batch registration error:", error);

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
    if (!user) throw new Error("Create a new account to continue!");

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

    return res.status(200).json(user);
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

    return res.status(200).json(user);

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

// Request password reset - user initiates the reset request
app.post(`${BASE_ROUTE}/auth/request-password-reset`, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    // Already approved by admin, allow password change step
    if (user.isPasswordReset) {
      return res.status(200).json({
        status: "approved",
        message: "Your reset request has been approved. Please set a new password.",
      });
    }

    // Already requested, waiting on admin
    const existingRequest = await PasswordReset.findOne({ email: user.email });
    if (existingRequest) {
      return res.status(200).json({
        status: "pending",
        message: "Password reset request already submitted. Please contact your admin for approval.",
      });
    }

    // Create a request record
    await PasswordReset.create({ email: user.email });

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.requested",
      description: "Password reset requested",
      actor: user,
      metadata: { requestedFor: user.email },
    });

    res.status(200).json({
      status: "requested",
      message: "Password reset request submitted. Please contact your admin for approval.",
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    res.status(400).json({ message: error.message });
  }
});


// Get all password reset requests (admin only)
app.get(`${BASE_ROUTE}/auth/password-reset-requests`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const admin = await User.findById(req.session.userID);
    if (!admin || !["admin", "hr"].includes(admin.rank)) {
      return res.status(403).json({ message: "Access denied" });
    }

    const requests = await PasswordReset.find().sort({ createdAt: -1 }).lean();

    // enrich with user details when available
    const enriched = await Promise.all(requests.map(async (r) => {
      const user = await User.findOne({ email: r.email }).lean();
      return {
        ...r,
        userName: user?.name || 'N/A',
        department: user?.department || 'N/A',
        station: user?.station || 'N/A',
        role: user?.role || 'N/A',
        userIsPasswordReset: user?.isPasswordReset || false,
      };
    }));

    res.json(enriched);
  } catch (error) {
    console.error("Fetch password reset requests error:", error);
    res.status(400).json({ message: error.message });
  }
});

// Allow password reset - Admin approves a request
app.post(`${BASE_ROUTE}/auth/allow-password-reset`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const admin = await User.findById(req.session.userID);
    if (!admin || !["admin", "hr"].includes(admin.rank)) {
      return res.status(403).json({ message: "Access denied" });
    }

    const { email } = req.body;
    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    const request = await PasswordReset.findOne({ email });
    if (!request) throw new Error("Password reset request not found");

    user.isPasswordReset = true;
    await user.save();

    // Keep request until user changes password (as a record of workflow), or optional remove to avoid duplicates
    await PasswordReset.deleteOne({ email });

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.approved",
      description: "Password reset approved",
      actor: admin,
      target: user,
      metadata: { approvedFor: user.email },
    });

    res.json({ message: "Password reset approved", status: "approved" });
  } catch (error) {
    console.error("Allow password reset error:", error);
    res.status(400).json({ message: error.message });
  }
});

// Reset password - User sets new password after admin approval
app.post(`${BASE_ROUTE}/auth/reset-password`, async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");
    if (!newPassword || newPassword.length < 4) throw new Error("Password must be at least 4 characters");

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    if (!user.isPasswordReset) {
      throw new Error("Password reset not approved yet. Contact your admin.");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.isPasswordReset = false;
    await user.save();

    await PasswordReset.deleteOne({ email });

    await createAuditLog({
      req,
      category: "password_reset",
      action: "password_reset.completed",
      description: "Password reset completed",
      actor: user,
      metadata: { resetFor: user.email },
    });

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(400).json({ message: error.message });
  }
});

// Allow password reset - Admin approves the reset request
app.post(`${BASE_ROUTE}/auth/allow-password-reset`, async (req, res) => {
  try {
    // Check if user has admin privileges
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const admin = await User.findById(req.session.userID);
    if (!admin || !['admin', 'hr'].includes(admin.rank)) {
      return res.status(403).json({ message: "Only admin or HR can approve password resets" });
    }

    const { email } = req.body;

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    // isPasswordReset flag is already true, it just needs to stay true until user resets
    // Admin approval is confirmed by this endpoint being called
    res.status(200).json({ message: "Password reset approved for user" });
  } catch (error) {
    console.error("Allow password reset error:", error);
    res.status(400).json({ message: error.message });
  }
});

// Reset password - User sets new password after admin approval
app.post(`${BASE_ROUTE}/auth/reset-password`, async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email) throw new Error("Email is required");
    if (!validator.isEmail(email)) throw new Error("Invalid email format");
    if (!newPassword || newPassword.length < 4) throw new Error("Password must be at least 4 characters");

    const user = await User.findOne({ email });
    if (!user) throw new Error("User not found");

    if (!user.isPasswordReset) {
      throw new Error("Password reset not approved. Contact your admin.");
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and reset the flag
    user.password = hashedPassword;
    user.isPasswordReset = false;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(400).json({ message: error.message });
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
      console.error(error);
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
    const { selectedStation, userCoords, ...authResponse } = req.body;

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
        userLocation: {
          latitude: userCoords?.latitude || null,
          longitude: userCoords?.longitude || null,
        }
      };

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
          clockedOutside: false,
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
        },
      });
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
    if (!req.session.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const workingDaysSoFar =
      Math.ceil((now - startOfMonth) / (1000 * 60 * 60 * 24));

    const [records, allUsers] = await Promise.all([
      Clocking.find({ clock_in: { $gte: startOfMonth } }),
      User.find({}, "email name department station isAccountActive role")
    ]);

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
      stations: stats.stations
    });

  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});



// departmental stats
app.get(`${BASE_ROUTE}/supervisor/department/stats`, async (req, res) => {
  try {
    if (!req.session?.isOnline)
      return res.status(401).json({ message: "Unauthorized" });

    const currentSupervisor = await User.findById(req.session.userID);
    if (!currentSupervisor)
      return res.status(404).json({ message: "User not found" });

    if (currentSupervisor.rank !== "supervisor")
      return res.status(403).json({
        message: "Selected user is not eligible to be a supervisor",
      });

    const department = currentSupervisor.department;

    // -----------------------------------
    // FETCH STAFF
    // -----------------------------------
    const staff = await User.find(
      { department },
      "email name department station isAccountActive role"
    ).lean();

    if (!staff.length)
      return res.status(404).json({
        message: "No staff found in this department",
      });

    const emails = staff.map((u) => u.email);

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const workingDaysSoFar =
      Math.ceil((now - startOfMonth) / (1000 * 60 * 60 * 24));

    // -----------------------------------
    // FETCH CLOCKING RECORDS
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

    staff.forEach((u) => {
      metricsMap[u.email] = {
        name: u.name,
        email: u.email,
        station: u.station,
        hours: 0,
        overtime: 0,
        lateCount: 0,
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

      if (rec.clock_out) {
        hoursWorked =
          (rec.clock_out - rec.clock_in) / (1000 * 60 * 60);

        metric.hours += hoursWorked;

        if (hoursWorked > 9)
          metric.overtime += hoursWorked - 9;

        metric.daysPresent.add(
          rec.clock_in.toDateString()
        );
      }

      if (rec.isLate) metric.lateCount++;
    });

    // -----------------------------------
    // BUILD EMPLOYEE METRICS
    // -----------------------------------
    Object.values(metricsMap).forEach((m) => {
      deptStats.totalHours += m.hours;
      deptStats.totalOvertime += m.overtime;
      deptStats.lateCount += m.lateCount;

      const attendanceRate =
        (m.daysPresent.size / workingDaysSoFar) * 100;

      const productivityScore =
        m.hours * 0.6 +
        m.overtime * 0.5 -
        m.lateCount * 1.5;

      let burnoutLevel = "Low";
      if (m.overtime > 20) burnoutLevel = "High";
      else if (m.overtime > 10) burnoutLevel = "Moderate";

      deptStats.employeeMetrics.push({
        name: m.name,
        email: m.email,
        station: m.station,
        hours: m.hours.toFixed(1),
        overtime: m.overtime.toFixed(1),
        lateCount: m.lateCount,
        daysPresent: m.daysPresent.size,
        attendanceRate: attendanceRate.toFixed(1) + "%",
        productivityScore,
        burnoutLevel,
      });
    });

    // -----------------------------------
    // SORT + TOP 3 PERFORMERS
    // -----------------------------------
    const sortedEmployees = [...deptStats.employeeMetrics].sort(
      (a, b) => b.productivityScore - a.productivityScore
    );

    const top3Performers = sortedEmployees.slice(0, 3);

    // -----------------------------------
    // RESPONSE
    // -----------------------------------
    res.json({
      department,
      totalStaff: staff.length,
      activeStaffThisMonth: Object.keys(metricsMap).length,
      totalHours: deptStats.totalHours.toFixed(1),
      totalOvertime: deptStats.totalOvertime.toFixed(1),
      totalLateCount: deptStats.lateCount,
      topPerformers: top3Performers,   // 🔥 NEW
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

    // Only HR can manage users
    if (currentUser.rank !== "hr")
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

    const allowedRanks = ["admin", "user", "hr", "supervisor", "ceo", "auditor"];
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

    if (!["admin", "hr", "ceo", "supervisor"].includes(currentUser.rank))
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

    if (!["supervisor"].includes(currentUser.rank))
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

    if (!["admin", "hr", "supervisor"].includes(currentUser.rank))
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

    if (!["admin", "hr", "supervisor"].includes(currentUser.rank))
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

    if (!["admin", "hr", "supervisor"].includes(currentUser.rank))
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
    if (!["admin", "hr", "supervisor", "user"].includes(currentUser?.rank))
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

app.get(`${BASE_ROUTE}/audit/logs`, async (req, res) => {
  try {
    if (!req.session?.isOnline || !req.session?.userID) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const currentUser = await User.findById(req.session.userID);
    if (!currentUser || !["auditor", "admin"].includes(currentUser.rank)) {
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
    console.error("Error fetching colleagues:", error);
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
    console.error(err);
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

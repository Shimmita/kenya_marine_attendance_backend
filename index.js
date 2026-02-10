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
import User from "./model/User.js";

const mongoDBSession = connectMongoStore(session);
const app = express();
app.use(bodyParser.json());
app.use(express.json());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    credentials: true,
  })
);

const PORT = process.env.PORT || 5000;
const BASE_ROUTE = process.env.BASE_ROUTE;
const environment = process.env.ENVIRONMENT_MODE;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Return the correct RP ID based on environment.
 */
const getRpID = () =>
  environment === "SANDBOX"
    ? process.env.DOMAIN_NAME_LOCAL
    : process.env.DOMAIN_NAME_PROD;

/**
 * Return the correct expected origin based on environment.
 */
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
    console.log(
      `Connected to MongoDB (${environment === "SANDBOX" ? "LOCAL" : "CLOUD"})`
    )
  )
  .catch((err) => console.error("Database connection failed:", err));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
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
    saveUninitialized: false,
    name: process.env.SESSION_NAME,
    store,
    cookie: {
      maxAge: 60 * 60 * 2 * 1000, // 2 hours
      secure: environment !== "SANDBOX",
      sameSite: environment === "SANDBOX" ? "lax" : "none",
    },
  })
);

// ─── Auth check ───────────────────────────────────────────────────────────────

app.use(`${BASE_ROUTE}/valid`, async (req, res) => {
  try {
    if (!req.session?.isOnline) throw new Error("Not authenticated");
    res.status(200).json({ valid: true });
  } catch {
    res.status(400).json({ valid: false });
  }
});

// ─── Register ─────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signup`, async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      department,
      supervisor,
      phone,
      startDate,
      endDate,
      gender,
    } = req.body.formData;

    if (!validator.isEmail(email)) {
      throw new Error("Provided email is malformed!");
    }

    if (!password || password.length < 4) {
      throw new Error("Password must be at least 4 characters!");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) throw new Error("User already registered!");

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword,
      department,
      supervisor,
      phone,
      startDate,
      endDate,
      gender,
    });

    return res.status(200).json({ message: "Account created successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(400).json({ message: error.message });
  }
});

// ─── Login ────────────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/auth/signin`, async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!validator.isEmail(email)) {
      throw new Error("Provided email is malformed!");
    }

    if (!password || password.length < 4) {
      throw new Error("Password must be at least 4 characters!");
    }

    const user = await User.findOne({ email });
    if (!user) throw new Error("Create a new account to continue!");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error("Invalid credentials!");

    if (!user.email_verified) {
      throw new Error("Email not verified. Contact admin.");
    }

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
    if (!req.session.isOnline) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const options = await generateRegistrationOptions({
      rpName: "KMFRI Attendance",
      rpID: getRpID(),
      userID: Uint8Array.from(Buffer.from(user._id.toString())),
      userName: user.email,
      authenticatorSelection: {
        userVerification: "required",
      },
    });

    // Persist challenge in session for verification step
    req.session.registrationChallenge = options.challenge;

    res.json(options);
  } catch (err) {
    console.error("Register challenge error:", err);
    res.status(400).json({ message: err.message });
  }
});

/**
 * 2. Verify Registration Response
 *
 * FIX: credentialID and credentialPublicKey are stored as Base64URL strings
 * to avoid Mongoose Buffer serialization issues that caused auth to fail.
 */
app.post(`${BASE_ROUTE}/biometric/register/verify`, async (req, res) => {
  try {
    const user = await User.findById(req.session.userID);
    if (!user) throw new Error("User not found");

    const expectedChallenge = req.session.registrationChallenge;
    if (!expectedChallenge) {
      throw new Error("No registration challenge found. Please restart.");
    }

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
    });

    if (!verification.verified) {
      return res.status(400).json({ registered: false });
    }

    const { credential } = verification.registrationInfo;

    // ✅ Store as Base64URL strings — avoids Buffer round-trip corruption
    user.authenticator = {
      credentialID: Buffer.from(credential.id).toString("base64url"),
      credentialPublicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
    };

    await user.save();

    // Clean up challenge from session
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
 * FIX: Pass allowCredentials so the browser targets the correct passkey.
 * credentialID is stored as Base64URL string, pass it directly.
 */
app.get(`${BASE_ROUTE}/biometric/auth/challenge`, async (req, res) => {
  try {
    if (!req.session.isOnline) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await User.findById(req.session.userID);
    if (!user || !user.authenticator) {
      return res
        .status(400)
        .json({ message: "Biometric not registered for this account" });
    }

    const options = await generateAuthenticationOptions({
      rpID: getRpID(),
      userVerification: "required",
      // ✅ Target only this user's registered credential
      allowCredentials: [
        {
          id: user.authenticator.credentialID, // Base64URL string
          type: "public-key",
        },
      ],
    });

    req.session.authChallenge = options.challenge;
    req.session.biometricVerified = false;

    res.json(options);
  } catch (error) {
    console.error("Auth challenge error:", error);
    res
      .status(500)
      .json({ message: "Failed to generate authentication options" });
  }
});

/**
 * 4. Verify Authentication Response
 *
 * FIX: Convert Base64URL strings back to Buffers for verifyAuthenticationResponse.
 * This is the reverse of what we do on save, and it must be exact.
 */
app.post(`${BASE_ROUTE}/biometric/auth/verify`, async (req, res) => {
  try {
    if (!req.session.isOnline) {
      return res.status(401).json({ verified: false, message: "Unauthorized" });
    }

    const user = await User.findById(req.session.userID);
    if (!user || !user.authenticator) {
      return res.status(400).json({
        verified: false,
        message: "Fingerprint not registered",
      });
    }

    const expectedChallenge = req.session.authChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({
        verified: false,
        message: "No auth challenge found. Please restart.",
      });
    }

    // ✅ Convert Base64URL strings back to Buffers for the library
    const authenticator = {
      credentialID: Buffer.from(user.authenticator.credentialID, "base64url"),
      credentialPublicKey: Buffer.from(
        user.authenticator.credentialPublicKey,
        "base64url"
      ),
      counter: user.authenticator.counter,
    };

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: getRpID(),
      authenticator,
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(401).json({ verified: false });
    }

    // ✅ Update counter to prevent replay attacks
    user.authenticator.counter = verification.authenticationInfo.newCounter;
    await user.save();

    // Mark session as biometrically verified with a timestamp
    req.session.biometricVerified = true;
    req.session.biometricVerifiedAt = Date.now();

    // Clean up challenge
    delete req.session.authChallenge;

    res.json({ verified: true });
  } catch (err) {
    console.error("Auth verify error:", err);
    res.status(401).json({ verified: false, message: err.message });
  }
});

// ─── Attendance ───────────────────────────────────────────────────────────────

app.post(`${BASE_ROUTE}/attendance/clockin`, async (req, res) => {
  // Biometric must be verified within the last 2 minutes
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

    // Invalidate biometric window after use (one-shot)
    req.session.biometricVerified = false;

    res.json({ message: "Clock-in successful", timestamp: new Date() });
  } catch (err) {
    console.error("Clock-in error:", err);
    res.status(500).json({ message: "Clock-in failed" });
  }
});
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

export const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // smtp.office365.com
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER, // xyz@kmfri.go.ke
    pass: process.env.EMAIL_PASSWORD, // your_email_password
  },
  
});
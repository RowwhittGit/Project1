import nodemailer, { TransportOptions } from "nodemailer";

type SendEmailOptions = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

const sendEmail = async ({ to, subject, text, html }: SendEmailOptions) => {
  const transporter = nodemailer.createTransport({
    host: process.env["SMTP_HOST"] as string,
    port: Number(process.env["SMTP_PORT"]),
    secure: false,
    family: 4,
    auth: {
      user: process.env["SMTP_USER"] as string,
      pass: process.env["SMTP_PASSWORD"] as string,
    }
  } as TransportOptions); // * Cast the object to TransportOptions

  const emailOptions = {
    from: `MERN <${process.env["EMAIL_FROM"] as string}>`,
    to,
    subject,
    text,
    html,
  };

  // * Sending email activation account
  transporter.sendMail(emailOptions, (error: any, info: any) => {
    if (error) {
      console.error('SMTP ERROR:', JSON.stringify(error));
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

export default sendEmail;

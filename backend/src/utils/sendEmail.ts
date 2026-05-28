import { BrevoClient } from '@getbrevo/brevo';

type SendEmailOptions = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

const sendEmail = async ({ to, subject, text, html }: SendEmailOptions) => {
  const client = new BrevoClient({ apiKey: process.env["EMAIL_API"] as string });

  try {
    await client.transactionalEmails.sendTransacEmail({
      to: [{ email: to }],
      subject,
      htmlContent: html,
      textContent: text,
      sender: { name: 'MERN', email: process.env["EMAIL_FROM"] as string },
    });
    console.log('Email sent successfully to:', to);
  } catch (error) {
    console.error('BREVO ERROR:', JSON.stringify(error));
  }
};

export default sendEmail;

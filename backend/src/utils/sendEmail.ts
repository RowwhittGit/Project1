import { Resend } from 'resend';

type SendEmailOptions = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

const sendEmail = async ({ to, subject, text, html }: SendEmailOptions) => {
  const resend = new Resend(process.env["RESEND_API_KEY"] as string);

  const { error } = await resend.emails.send({
    from: `MERN <onboarding@resend.dev>`,
    to,
    subject,
    html,
    text,
  });

  if (error) {
    console.error('RESEND ERROR:', JSON.stringify(error));
  } else {
    console.log('Email sent successfully to:', to);
  }
};

export default sendEmail;

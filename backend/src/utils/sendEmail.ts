const Brevo = require('sib-api-v3-sdk');

const apiInstance = new Brevo.TransactionalEmailsApi();
apiInstance.setApiKey(
    Brevo.TransactionalEmailsApiApiKeys.apiKey,
    process.env['BREVO_API_KEY'] as string
);

export default async function sendEmail({ to, subject, text, html }: {
    to: string;
    subject: string;
    text: string;
    html: string;
}) {
    const sendSmtpEmail = new Brevo.SendSmtpEmail();
    sendSmtpEmail.to = [{ email: to }];
    sendSmtpEmail.subject = subject;
    sendSmtpEmail.textContent = text;
    sendSmtpEmail.htmlContent = html;
    sendSmtpEmail.sender = {
        name: process.env['BREVO_SENDER_NAME'] as string,
        email: process.env['BREVO_SENDER_EMAIL'] as string,
    };

    try {
        await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('Email sent successfully to:', to);
    } catch (error) {
        console.error('BREVO ERROR:', JSON.stringify(error));
    }
}

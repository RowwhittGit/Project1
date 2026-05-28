import SibApiV3Sdk from 'sib-api-v3-sdk';

const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
apiInstance.setApiKey(
    SibApiV3Sdk.TransactionalEmailsApiApiKeys.apiKey,
    process.env['BREVO_API_KEY'] as string
);

export default async function sendEmail({ to, subject, text, html }: {
    to: string;
    subject: string;
    text: string;
    html: string;
}) {
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
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

import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class SendEmailMiddleware {
    constructor(private mailerService: MailerService) { }

    sendEmail(email: string, content, attachmentsArray) {
        let subjectObject = {
            subjectTitle: 'Email Confirmation',
            subjectBody: content,
        };
        try {
            let mailOptions = {
                to: email,
                subject: subjectObject.subjectTitle,
                html: subjectObject.subjectBody,
                attachments: attachmentsArray,
            };
            this.mailerService.sendMail(mailOptions)
                .then((info) => {
                    console.log('email sent', info)
                });
        } catch (error) {
            console.log('error', error);
        }
    }
}
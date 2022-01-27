import { Injectable } from '@nestjs/common';
import * as SendGrid from '@sendgrid/mail';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SendgridService {
  constructor(private readonly configService: ConfigService) {
    // send grid add api key
    SendGrid.setApiKey(this.configService.get<string>('SEND_GRID_KEY'));
  }

  async send(to: string, subject: string, html: string) {
    const mail: SendGrid.MailDataRequired = {
      to,
      subject,
      from: process.env.AUTHENTICATION_SENDER_EMAIL, // Fill it with your validated email on SendGrid account
      html,
    };
    return SendGrid.send(mail);
  }
}

import { Injectable } from '@nestjs/common';
import { InjectTwilio, TwilioClient } from 'nestjs-twilio';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class TwilioService {
  constructor(@InjectTwilio() private readonly twilioClient: TwilioClient) {}

  async sendSMS(targetPhoneNumber: string) {

    // @TODO: add phone regex
    try {
      return await this.twilioClient.messages.create({
        body: 'SMS Body, sent to the phone!',
        from: process.env.TWILIO_PHONE_NUMBER,
        to: targetPhoneNumber,
      });
    } catch (e) {
      return e;
    }
  }

  async sendSMSToken(targetPhoneNumber: string, body: string,) {

    // @TODO: add phone regex
    try {
      return await this.twilioClient.messages.create({
        body,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: targetPhoneNumber,
      });
    } catch (e) {
      return e;
    }
  }
}
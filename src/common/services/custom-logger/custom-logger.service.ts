import { LoggerService } from '@nestjs/common';
import { BugsnagService } from 'nest-bugsnag';

export class CustomLogger implements LoggerService {
  bugsnagLogger: BugsnagService;

  constructor() {
    this.bugsnagLogger = new BugsnagService({
      apiKey: process.env.BUGSNAG_ACCOUNT_API_KEY,
    });
  }
  /**
   * Write a 'log' level log.
   */
  log(message: any, ...optionalParams: any[]) {
    this.bugsnagLogger.instance.notify(message, {
      ...optionalParams,
      severity: 'info',
    });
  }

  /**
   * Write an 'error' level log.
   */
  error(message: any, ...optionalParams: any[]) {
    this.bugsnagLogger.instance.notify(message, {
      ...optionalParams,
      severity: 'error',
    });
  }

  /**
   * Write a 'warn' level log.
   */
  warn(message: any, ...optionalParams: any[]) {
    this.bugsnagLogger.instance.notify(message, {
      ...optionalParams,
      severity: 'warning',
    });
  }

  /**
   * Write a 'debug' level log.
   */
  debug?(message: any, ...optionalParams: any[]) {
    this.bugsnagLogger.instance.notify(message, {
      ...optionalParams,
      severity: 'info',
    });
  }

  /**
   * Write a 'verbose' level log.
   */
  verbose?(message: any, ...optionalParams: any[]) {
    this.bugsnagLogger.instance.notify(message, {
      ...optionalParams,
      severity: 'info',
    });
  }
}

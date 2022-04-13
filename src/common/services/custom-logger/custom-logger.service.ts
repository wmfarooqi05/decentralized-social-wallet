import { Inject, LoggerService } from '@nestjs/common';
import { BugsnagService } from 'nest-bugsnag';
import * as winston from 'winston';
import {
  utilities as nestWinstonModuleUtilities,
  WinstonModule,
} from 'nest-winston';

export class CustomLogger implements LoggerService {
  bugsnagLogger: BugsnagService;
  winstonLogger: LoggerService;

  constructor() {
    // this.bugsnagLogger = new BugsnagService({
    //   apiKey: process.env.BUGSNAG_ACCOUNT_API_KEY,
    // });
    this.winstonLogger = WinstonModule.createLogger({
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.ms(),
            nestWinstonModuleUtilities.format.nestLike('MyApp', {
              prettyPrint: true,
            }),
          ),          
        }),
      ],
    });
  }
  /**
   * Write a 'log' level log.
   */
  log(message: any, ...optionalParams: any[]) {
    // this.bugsnagLogger.instance.notify(message, {
    //   ...optionalParams,
    //   severity: 'info',
    // });
    this.winstonLogger.log(message, optionalParams);
  }

  /**
   * Write an 'error' level log.
   */
  error(message: any, ...optionalParams: any[]) {
    // this.bugsnagLogger.instance.notify(message, {
    //   ...optionalParams,
    //   severity: 'error',
    // });
    this.winstonLogger.error(message, optionalParams);
  }

  /**
   * Write a 'warn' level log.
   */
  warn(message: any, ...optionalParams: any[]) {
    // this.bugsnagLogger.instance.notify(message, {
    //   ...optionalParams,
    //   severity: 'warning',
    // });

    this.winstonLogger.warn(message, optionalParams);
  }

  /**
   * Write a 'debug' level log.
   */
  debug?(message: any, ...optionalParams: any[]) {
    // this.bugsnagLogger.instance.notify(message, {
    //   ...optionalParams,
    //   severity: 'info',
    // });

    this.winstonLogger.debug(message, optionalParams);
  }

  /**
   * Write a 'verbose' level log.
   */
  verbose?(message: any, ...optionalParams: any[]) {
    // this.bugsnagLogger.instance.notify(message, {
    //   ...optionalParams,
    //   severity: 'info',
    // });

    this.winstonLogger.verbose(message, optionalParams);
  }
}

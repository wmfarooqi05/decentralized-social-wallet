import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
// import { CustomLogger } from './common/services/custom-logger/custom-logger.service';
import * as path from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';

dotenv.config();
declare const module: any;
async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    // logger: new CustomLogger(),
  });
  (app as any).set('etag', false);

  app.setGlobalPrefix('api');
  app.useStaticAssets(join(__dirname, '..', 'static'));

  // if (!configService.isProduction()) {
  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle('Item API')
      .setDescription('My Item API')
      .build(),
  );

  SwaggerModule.setup('api/docs', app, document);
  // }

  app.use((req, res, next) => {
    res.removeHeader('x-powered-by');
    res.removeHeader('date');
    next();
  });
  await app.listen(process.env.SERVER_PORT);
}
bootstrap();

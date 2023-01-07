import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { RequestContextMiddleware } from './core/middleware/request-context.middleware';
import { FallbackExceptionFilter } from './core/filters/fallback.filter';
import { HttpExceptionFilter } from './core/filters/http.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
/* It enables CORS for all routes. */
  app.enableCors();
/* Setting the global prefix for all routes. */
  app.setGlobalPrefix('api');
/* A middleware that is used to set the request context. */
  app.use(RequestContextMiddleware.rawExpressMiddleware);
  app.useGlobalFilters(
    new FallbackExceptionFilter(),
    new HttpExceptionFilter()
  );

  const options = new DocumentBuilder()
  .setTitle('Scanila APIs ')
  .setDescription('Scanila is a software application that enables users to create and download QR codes for various purposes. ')
  .setVersion('1.0')
  .addBearerAuth()
  .build();

const document = SwaggerModule.createDocument(app, options);
SwaggerModule.setup('docs', app, document);

  await app.listen(AppModule.port || 5000);
}
bootstrap();

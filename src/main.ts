import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';

import { AppModule } from '@/app.module';

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET'] as const;

function validateEnv() {
  const missing = REQUIRED_ENV.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

async function bootstrap() {
  validateEnv();

  const app = await NestFactory.create(AppModule);

  app.use(helmet());
  app.enableCors({ origin: true }); // 本番では origin を制限すること

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Swagger
  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Auth API')
      .setDescription('Lightweight authentication API')
      .setVersion('1.0.0')
      .addBearerAuth()
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
  }

  // Server
  const port = process.env.PORT ? Number(process.env.PORT) : 3000;
  await app.listen(port);

  console.log(`Auth API running on http://localhost:${port}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`Swagger available at http://localhost:${port}/docs`);
  }
}

bootstrap();

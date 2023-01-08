import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema, TokenVerifyEmailSchema , } from './user.model';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule } from '../core/config/config.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigService } from '../core/config/config.service';
import { SendEmailMiddleware } from '../core/middleware/send-email.middleware';
import { JwtRefreshStrategy } from './jwt.refresh.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: 'User', schema: UserSchema },
      { name: 'TokenVerifyEmail', schema: TokenVerifyEmailSchema }
    ]),
    // PassportModule.register({ defaultStrategy: 'jwt', session: true }),
    // JwtModule.registerAsync({
    //   imports: [ConfigModule],
    //   useFactory: async (configService: ConfigService) => ({
    //     secret: configService.get('JWT_ACCESS_TOKEN_SECRET'),
    //     signOptions: {
    //       expiresIn: configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME')
    //     }
    //   }),
    //   inject: [ConfigService],
    // }),
    PassportModule.register({}),
    JwtModule.register({}),
    MailerModule.forRootAsync({
      useFactory: () => ({
        transport: {
          host: 'smtp.gmail.com', port: 465, secure: true,
          auth: { user: 'shivenbist@gmail.com', pass: 'nmrcqsjtshbzrgbn' }
        },
        // defaults: {
        //   from: '',
        // },
      }),
    }),
    ConfigModule,
  ],
  providers: [AuthService, JwtStrategy, JwtRefreshStrategy, SendEmailMiddleware],
  controllers: [AuthController]
})
export class AuthModule { }

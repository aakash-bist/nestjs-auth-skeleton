import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { MongooseModule } from '@nestjs/mongoose';
import { WinstonModule } from 'nest-winston';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from './core/config/config.module';
import { ConfigService } from './core/config/config.service';
import { RolesGuard } from './core/guard/roles.guard';
import { SeedsModule } from './seeds/seed.module';

@Module({
  imports: [ConfigModule, MongooseModule.forRootAsync({
    imports: [ConfigModule],
    useFactory: async (configService: ConfigService) => ({
      uri: `${configService.get('DB_URL')}`,
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }),
    inject: [ConfigService]
  }), AuthModule, WinstonModule, SeedsModule],
  providers: [
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule {
  static port: number | string;
  constructor(private _configService: ConfigService) {
    AppModule.port = this._configService.get('PORT');
  }
}

import { Global, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { JWT_CONSTANTS } from 'src/constants/jwt';
import { JwtStrategy } from '../jwt/jwt.strategy';

@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const options: JwtModuleOptions = {
          privateKey: configService.get(JWT_CONSTANTS.PRIVATE_FULLKEY),
          publicKey: configService.get(JWT_CONSTANTS.PUBLIC_FULLKEY),
          signOptions: {
            expiresIn: '1d',
            algorithm: 'RS256',
          },
        };
        return options;
      },
      inject: [ConfigService],
    }),
  ],
  exports: [JwtModule],
  providers: [JwtStrategy],
})
export class CoreModule {}

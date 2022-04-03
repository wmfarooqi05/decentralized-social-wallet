import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CryptoKey } from './crypto-key.entity';
import { CryptoKeysController } from './crypto-keys.controller';
import { CryptoKeysService } from './crypto-keys.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([CryptoKey]),
  ],
  controllers: [CryptoKeysController],
  providers: [CryptoKeysService],
  exports: [CryptoKeysService],
})
export class CryptoKeysModule {}

import { Module } from '@nestjs/common';
import { CryptoKeysService } from './crypto-keys.service';

@Module({
  providers: [CryptoKeysService]
})
export class CryptoKeysModule {}

import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/common/modules/jwt/jwt-auth.guard';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import RequestWithUser from '../auth/interfaces/request-with-user';
import { User } from '../user/user.entity';
import { CryptoKeysService } from './crypto-keys.service';
import { AddCryptoPublicKey } from './dtos/add-public-key.dto';

@Controller('crypto-keys')
export class CryptoKeysController {
  constructor(private readonly cryptoKeysService: CryptoKeysService) {}
  @Post('/add-public-key')
  @UseGuards(JwtAuthGuard)
  async addPublicKey(

    @CurrentUser() { id }: IUserJwt,
    @Body() { publicKey }: AddCryptoPublicKey,
  ) {
    return this.cryptoKeysService.addPublicKeyByUserId(id, publicKey);
  }
}

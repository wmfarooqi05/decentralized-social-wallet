import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CryptoKey, KeyStatus } from './crypto-key.entity';

@Injectable()
export class CryptoKeysService {
  constructor(
    @InjectRepository(CryptoKey) private cryptoKeyRepo: Repository<CryptoKey>,
  ) {}

  async getPublicKeyByUserId(userId: string): Promise<string> {
    const cryptoKey = await this.cryptoKeyRepo.findOne({
      where: {
        user: {
          id: userId,
        },
      },
    });

    return cryptoKey.publicKey;
  }

  async addPublicKeyByUserId(userId: string, publicKey: string) {
    const existingPublicKey = this.cryptoKeyRepo.findOne({
      where: {
        user: {
          id: userId,
        },
      },
    });

    if (!existingPublicKey) {
      const cryptoKey: CryptoKey = this.cryptoKeyRepo.create({
        publicKey,
        status: KeyStatus.ACTIVE,
        user: { id: userId },
      });

      return this.cryptoKeyRepo.save(cryptoKey);
    } else {
      throw new BadRequestException(
        'Public key already exists against this username',
      );
    }
  }
}

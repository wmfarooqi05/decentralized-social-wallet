import { Test, TestingModule } from '@nestjs/testing';
import { CryptoKeysService } from './crypto-keys.service';

describe('CryptoKeysService', () => {
  let service: CryptoKeysService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CryptoKeysService],
    }).compile();

    service = module.get<CryptoKeysService>(CryptoKeysService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});

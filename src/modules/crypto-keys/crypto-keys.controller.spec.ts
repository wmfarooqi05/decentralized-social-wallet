import { Test, TestingModule } from '@nestjs/testing';
import { CryptoKeysController } from './crypto-keys.controller';

describe('CryptoKeysController', () => {
  let controller: CryptoKeysController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CryptoKeysController],
    }).compile();

    controller = module.get<CryptoKeysController>(CryptoKeysController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});

import { ApiProperty } from '@nestjs/swagger';
import { IsPhoneNumber, IsOptional, IsEmail, IsString, ValidateIf } from 'class-validator';

export class AddCryptoPublicKey {
  // @TODO validate public key
  @IsString()
  @ApiProperty({ type: String, description: 'publicKey' })
  publicKey: string;
}

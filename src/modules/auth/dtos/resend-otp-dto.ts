import { IsEnum, IsUUID } from 'class-validator';
import { TokenType } from 'src/modules/otp/otp.entity';

export class ResendOTPDTO {
  @IsUUID('4')
  userId: string;

  @IsEnum(TokenType)
  tokenType: TokenType;
}

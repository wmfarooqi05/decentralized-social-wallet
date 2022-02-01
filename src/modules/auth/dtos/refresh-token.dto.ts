import { ApiProperty } from '@nestjs/swagger';
import {
  IsNumber,
  IsString,
  ValidateIf,
} from 'class-validator';

export class RefreshTokenDTO {
  @IsString()
  @ValidateIf(val => val.refreshToken.length === 40)
  @ApiProperty({ type: String, description: 'refreshToken' })
  refreshToken: string;

  @IsString()
  @ApiProperty()
  jwtToken: string;
}

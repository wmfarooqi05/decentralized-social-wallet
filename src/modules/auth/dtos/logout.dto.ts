import { ApiProperty } from '@nestjs/swagger';
import {
  IsNumber,
  IsString,
  ValidateIf,
} from 'class-validator';

export class LogoutDTO {
  @IsString()
  @ValidateIf(val => val.refreshToken.length === 40)
  @ApiProperty({ type: String, description: 'refreshToken' })
  refreshToken: string;

  @IsNumber()
  @ApiProperty()
  userId: number;
}

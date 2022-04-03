import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches } from 'class-validator';
import { USERNAME_REGEX } from 'src/constants/auth';

export class UsernameDTO {
  @IsString()
  @Matches(USERNAME_REGEX, {
    message: 'Username not valid',
  })
  @ApiProperty({ type: String, description: 'username' })
  username: string;
}

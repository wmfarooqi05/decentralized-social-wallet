//@TODO: place password validations here

import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsPhoneNumber, IsString, ValidateIf } from "class-validator";

export class ValidateOTPDTO {
    @IsPhoneNumber()
    @ValidateIf(o => !o.email || o.phoneNumber)
    @ApiProperty({ type: String, description: 'phoneNumber' })
    phoneNumber: string;
    
    @IsEmail()
    @ValidateIf(o => o.email || !o.phoneNumber)
    @ApiProperty({ type: String, description: 'email' })
    email: string;
  
    @IsString()
    @ValidateIf(o => o.otp?.length === parseInt(process.env.OTP_LENGTH))
    @ApiProperty()
    otp: string;
}
import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsJSON, IsNumber, IsString } from 'class-validator';
import { TransactionChannel, TransactionStatus } from '../transaction.entity';

export class CreateTransactionDTO {
  @IsString()
  @ApiProperty({ type: String, description: 'publicKey' })
  publicKey: string;

  @IsEnum(TransactionChannel)
  @ApiProperty({ type: String, description: 'transactionChannel' })
  transactionChannel: string;

  @IsNumber()
  @ApiProperty({})
  senderId: number;

  @IsNumber()
  @ApiProperty({})
  recieverId: number;

  @IsEnum(TransactionStatus)
  @ApiProperty({})
  status: string;

  @IsJSON()
  @ApiProperty({})
  transactionPayload: JSON;
}

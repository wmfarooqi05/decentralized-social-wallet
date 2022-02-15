import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsJSON } from 'class-validator';
import { TransactionStatus } from '../transaction.entity';

export class UpdateTransactionDTO {
  @IsEnum(TransactionStatus)
  @ApiProperty({})
  status: string;

  @IsJSON()
  @ApiProperty({})
  transactionPayload: JSON;
}

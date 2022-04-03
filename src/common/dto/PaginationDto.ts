import { IsOptional, IsPositive } from 'class-validator';

export class PaginationDto {
  @IsPositive()
  @IsOptional()
  page: string;

  @IsPositive()
  @IsOptional()
  pageSize: string;
}

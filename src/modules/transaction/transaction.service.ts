import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateTransactionDTO } from './dto/create-transaction.dto';
import { UpdateTransactionDTO } from './dto/update-transaction.dto';
import { Transaction } from './transaction.entity';

@Injectable()
export class TransactionService {
  constructor(
    @InjectRepository(Transaction)
    private transactionRepo: Repository<Transaction>,
  ) {}

  async getTransactions() {
    return this.transactionRepo.find();
  }

  async getTransactionById(id: string) {
    return this.transactionRepo.findOne({
      where: { id }
    });
  }

  async createTransaction(payload: CreateTransactionDTO) {
    // @TODO: Add more logic and validations
    return this.transactionRepo.create(payload);
  }

  async updateTransaction(id: number, payload: UpdateTransactionDTO) {
    // @TODO: Add more logic and validations
    return this.transactionRepo.update(id, payload);
  }
}

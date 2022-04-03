import { Controller } from '@nestjs/common';

@Controller('transaction')
export class TransactionController {
  constructor() {}

  // @Get()
  // @Roles(Role.ADMIN_ROLE)
  // getTransactions() {
  //   return this.transactionService.getTransactions();
  // }

  // @Get("/:id")
  // @Roles(Role.ADMIN_ROLE)
  // getTransactionsById(@Param() param: { id: number }) {
  //   const { id } = param;
  //   return this.transactionService.getTransactionById(id);
  // }

  // @Post()
  // @Roles(Role.USER_ROLE)
  // createTransaction(@Body() body: CreateTransactionDTO) {
  //   return this.transactionService.createTransaction(body);
  // }

  // @Put("/:id")
  // @Roles(Role.ADMIN_ROLE)
  // updateTransaction(
  //   @Param() param: { id: number },
  //   @Body() body: UpdateTransactionDTO,
  // ) {
  //   const { id } = param;
  //   return this.transactionService.updateTransaction(id, body);
  // }
}

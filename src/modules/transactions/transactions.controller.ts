import { Controller, Get } from '@nestjs/common';
import { Roles } from 'src/common/modules/roles/roles.decorator';

@Controller('transactions')
export class TransactionsController {
    @Get()
    @Roles()
    async getAllTransactions() {
        return [{id:1}];
    }
}

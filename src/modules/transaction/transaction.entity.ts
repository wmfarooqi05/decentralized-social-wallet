import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  Timestamp,
} from 'typeorm';
import { User } from '../user/user.entity';

export enum TransactionChannel {
  ETHEREUM = 'ETHEREUM',
}

export enum TransactionStatus {
  SUCCESSFUL = 'SUCCESSFUL',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
}

@Entity()
export class Transaction {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  publicKey: string;

  @Column({
    type: 'enum',
    enum: TransactionChannel,
    default: TransactionChannel.ETHEREUM,
  })
  transactionChannel: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Timestamp;

  @ManyToOne(() => User, (user) => user.id)
  sender: User;

  @ManyToOne(() => User, (user) => user.id)
  reciever: User;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
  })
  updatedAt: Timestamp;

  @Column({
    type: 'enum',
    enum: TransactionStatus,
    default: TransactionStatus.PENDING,
  })
  status: string;

  @Column({ length: 1000, type: 'varchar' })
  transactionPayload: JSON;
}

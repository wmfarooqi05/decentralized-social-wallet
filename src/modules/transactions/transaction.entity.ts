import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, Timestamp } from 'typeorm';
import { User } from '../users/user.entity';

export enum TransactionChannel {
  ETHEREUM = 'ETHEREUM'
}

export enum TransactionStatus {
    SUCCESSFUL = "SUCCESSFUL",
    FAILED = "FAILED",
    CANCELLED = "CANCELLED",
    PENDING = "PENDING",
    IN_PROGRESS = "IN_PROGRESS"
}

@Entity()
export class Transaction {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: false })
  publicKey: string;

  @Column({
    type: 'enum',
    enum: TransactionChannel,
    default: TransactionChannel.ETHEREUM,
  })
  transactionChannel: boolean;

  @Column({ type: "timestamp", default: () => "CURRENT_TIMESTAMP"})
  createdAt: Timestamp;

  @ManyToOne(() => User, (user) => user.id)
  sender: User;

  @ManyToOne(() => User, (user) => user.id)
  reciever: User;

  @Column({ type: "timestamp", default: () => "CURRENT_TIMESTAMP"})
  updatedAt: Timestamp; // @TODO: check if working

  @Column({
      type: 'enum',
      enum: TransactionStatus,
      default: TransactionStatus.PENDING
  })
  status: string;
}

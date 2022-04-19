import {
  AfterInsert,
  AfterRemove,
  AfterUpdate,
  Entity,
  Column,
  Timestamp,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from '../user/user.entity';

export enum FriendRequest_Status {
  NOT_SENT = 'NOT_SENT',
  PENDING = 'PENDING',
  ACCEPTED = 'ACCEPTED',
  DECLINED = 'DECLINED',
  WAITING_FOR_CURRENT_USER_RESPONSE = 'WAITING_FOR_CURRENT_USER_RESPONSE',
  BLOCKED_BY_ME = 'BLOCKED_BY_ME',
  BLOCKED_BY_OTHER_USER = 'BLOCKED_BY_OTHER_USER',
}

@Entity()
export class FriendRequest {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.sentFriendRequests, { createForeignKeyConstraints: true })
  sender: User;

  @ManyToOne(() => User, (user) => user.receivedFriendRequests, {
    createForeignKeyConstraints: true,
  })
  receiver: User;

  @Column({
    type: 'enum',
    enum: FriendRequest_Status,
    default: FriendRequest_Status.PENDING,
  })
  friendshipStatus: FriendRequest_Status;

  @CreateDateColumn()
  createdAt: Timestamp;

  @UpdateDateColumn()
  updatedAt: Timestamp;

  @AfterInsert()
  logInsert() {
    console.log('Inserted User with id', this.sender, this.receiver);
  }

  @AfterUpdate()
  logUpdate() {
    console.log('Updated User with id', this.sender, this.receiver);
  }

  @AfterRemove()
  logRemove() {
    console.log('Removed User with id', this.sender, this.receiver);
  }
}

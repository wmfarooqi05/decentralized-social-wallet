import { Exclude } from 'class-transformer';
import {
  AfterInsert,
  AfterRemove,
  AfterUpdate,
  Entity,
  Column,
  PrimaryGeneratedColumn,
  Timestamp,
  ManyToOne,
} from 'typeorm';
import { User } from '../user/user.entity';
import * as moment from 'moment';

export enum SessionStatus {
  ACTIVE = 'ACTIVE',
  DELETED = 'DELETED',
  BLOCKED = 'BLOCKED',
  UNVERIFIED = 'UNVERIFIED',
}

@Entity()
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.id, {  onDelete: 'CASCADE' })
  user: User;

  @Column()
  refreshToken: string;

  @Column({ type: 'timestamp', default: () => "CURRENT_TIMESTAMP" })
  lastLogin: Timestamp;

  @Column({
    type: 'enum',
    enum: SessionStatus,
    default: SessionStatus.ACTIVE
  })
  status: SessionStatus;

  @Column()
  generatedIpAddress: string;

  @Column()
  lastLoginIpAddress: string;

  @Column({ type: "timestamp", default: moment().add(7, 'days') })
  exipredAt: Timestamp;
  // @AfterInsert()
  // logInsert() {
  //   console.log('Inserted User with id', this.id);
  // }

  // @AfterUpdate()
  // logUpdate() {
  //   console.log('Updated User with id', this.id);
  // }

  // @AfterRemove()
  // logRemove() {
  //   console.log('Removed User with id', this.id);
  // }
}

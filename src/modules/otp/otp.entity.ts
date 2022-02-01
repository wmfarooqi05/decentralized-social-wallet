import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, Timestamp } from 'typeorm';
import { User } from '../user/user.entity';
import * as moment from 'moment';

export enum TokenType {
  FORGOT_PASSWORD = 'FORGOT_PASSWORD',
  ACCOUNT_REGISTER = 'ACCOUNT_REGISTER',
}

@Entity()
export class Otp {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: false })
  token: string;

  @Column({
    type: "boolean", default: false, nullable: true
  })
  expired: boolean;

  @Column({
    type: "numeric", default: 5
  })
  expiry: number;

  @Column({ type: "timestamp", default: moment().add(1, 'minutes') })
  expiryTime: Timestamp;

  @Column({ type: "enum", enum: TokenType })
  type: TokenType;

  @Column({ type: "timestamp", default: moment() })
  createdAt: Timestamp;

  @ManyToOne(() => User, (user) => user.id)
  user: User;
}

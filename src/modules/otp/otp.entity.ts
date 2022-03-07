import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  Timestamp,
  AfterUpdate,
  AfterInsert,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../user/user.entity';
import * as moment from 'moment';

export enum TokenType {
  FORGOT_PASSWORD = 'FORGOT_PASSWORD',
  ACCOUNT_REGISTER = 'ACCOUNT_REGISTER', // unused
  LINK_EMAIL = 'LINK_EMAIL',
  LINK_PHONE_NUMBER = 'LINK_PHONE_NUMBER',
}

export enum TransportType {
  EMAIL = 'EMAIL',
  SMS = 'SMS',
}

@Entity()
export class Otp {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  token: string;

  @Column({
    type: 'boolean',
    default: false,
    nullable: true,
  })
  expired: boolean;

  @Column({ type: 'timestamp', default: moment().add(1, 'minutes') })
  expiryTime: Timestamp;

  @Column({ type: 'enum', enum: TokenType })
  type: TokenType;
  
  @CreateDateColumn({ type: "timestamp", default: () => "CURRENT_TIMESTAMP(6)" })
  createdAt: Date;

  @UpdateDateColumn({ type: "timestamp", default: () => "CURRENT_TIMESTAMP(6)", onUpdate: "CURRENT_TIMESTAMP(6)" })
  updatedAt: Date;

  @ManyToOne(() => User, (user) => user.id)
  user: User;

  @Column({ default: null, nullable: true })
  additionalItem: string;

  @AfterInsert()
  logInsert() {
    console.log('Inserted OTP with id', this.id, this.token);
  }

  @AfterUpdate()
  logUpdate() {
    console.log('Updated OTP with id', this.id, this.expired);
  }
}

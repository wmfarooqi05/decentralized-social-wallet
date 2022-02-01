import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, Timestamp } from 'typeorm';
import { User } from '../user/user.entity';

export enum KeyStatus {
  ACTIVE = 'ACTIVE',
  DEACTIVATED = 'DEACTIVATED',
  BLOCKED = 'BLOCKED',
  UNVERIFIED = 'UNVERIFIED'
}

@Entity()
export class Report {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: false })
  publicKey: string;

  @Column({
    type: 'enum',
    enum: KeyStatus,
    default: KeyStatus.UNVERIFIED,
  })
  status: boolean;

  @Column({ type: "timestamp", default: () => "CURRENT_TIMESTAMP"})
  createdAt: Timestamp;

  @ManyToOne(() => User, (user) => user.id)
  user: User;
}

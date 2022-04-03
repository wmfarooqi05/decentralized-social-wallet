import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, Timestamp } from 'typeorm';
import { User } from '../user/user.entity';

export enum KeyStatus {
  ACTIVE = 'ACTIVE',
  DEACTIVATED = 'DEACTIVATED',
  BLOCKED = 'BLOCKED',
  UNVERIFIED = 'UNVERIFIED'
}

@Entity()
export class CryptoKey {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  publicKey: string;

  @Column({
    type: 'enum',
    enum: KeyStatus,
    default: KeyStatus.UNVERIFIED,
  })
  status: KeyStatus;

  @ManyToOne(() => User, (user) => user.id)
  user: User;
  
  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP'
  })
  createdAt: Timestamp;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
  })
  updatedAt: Timestamp;

}

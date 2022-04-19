import { string } from 'joi';
import { User } from 'src/modules/user/user.entity';
import {
  AfterUpdate,
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  PrimaryGeneratedColumn,
  Timestamp,
  UpdateDateColumn,
} from 'typeorm';
import { MESSAGE_TYPE_ENUM, Reaction, SeenStatuses } from '../chat.types';
import { Chatroom } from '../chatroom/chatroom.entity';

@Entity()
export class ChatMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Chatroom, (chatroom) => chatroom.id)
  chatroom: Pick<Chatroom, 'id'>;

  @ManyToOne(() => User, (user) => user.id)
  user: Pick<User, 'id'>;

  @Column({ nullable: true })
  messageContent: string;

  @Column({
    type: 'enum',
    enum: MESSAGE_TYPE_ENUM,
    default: MESSAGE_TYPE_ENUM.TEXT,
  })
  messageType: MESSAGE_TYPE_ENUM;

  @Column({ nullable: true })
  messageRandomId: string;

  @Column({ type: 'jsonb' })
  seenStatuses: SeenStatuses[];

  @Column({ default: 0 })
  seenTicksCount: number;

  @Column({ default: false })
  isDeleted?: boolean;

  /**
   * @NOTE This will not be stored as jsonb
   */
  @Column({ type: 'json', default: [] })
  reactions: Reaction[];

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  sendingTime: Date;

  @CreateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  createdAt: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updatedAt: Date;
}

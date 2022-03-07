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
import { MESSAGE_TYPE, Reaction, SeenStatuses } from '../chat.types';
import { Chatroom } from '../chatroom/chatroom.entity';

@Entity()
export class ChatMessage {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Chatroom, (chatroom) => chatroom.id)
  chatroom: Chatroom;

  @ManyToOne(() => User, (user) => user.id)
  user: User;

  @Column({ nullable: true })
  messageContent: string;

  @Column({
    type: 'enum',
    enum: MESSAGE_TYPE,
    default: MESSAGE_TYPE.TEXT,
  })
  messageType: MESSAGE_TYPE;

  @Column({ nullable: true })
  messageRandomId: string;

  @Column({ type: 'jsonb' })
  seenStatuses: SeenStatuses[];

  /**
   * @NOTE This will not be stored as jsonb
   */
  @Column({ type: 'json', default: [] })
  reactions: Reaction[];

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

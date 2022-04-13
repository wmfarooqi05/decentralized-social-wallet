import { User } from 'src/modules/user/user.entity';
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  AfterUpdate,
  AfterInsert,
  ManyToMany,
  JoinTable,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ChatMessage } from '../chat-message/chat-message.entity';

const DEFAULT_CHATROOM_NAME = 'NEW CHATROOM';

@Entity()
export class Chatroom {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false, default: DEFAULT_CHATROOM_NAME })
  name: string;

  @Column({ nullable: true })
  icon: string;

  @ManyToMany(() => User)
  @JoinTable({
    joinColumn: {
      name: 'chatroomId',
      referencedColumnName: 'id',
    },
    inverseJoinColumn: {
      name: 'userId',
      referencedColumnName: 'id',
    },
  })
  participants: User[];

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

  @Column({ nullable: true, type: 'uuid' })
  lastMessageId: string;

  lastMessage: ChatMessage;

  @Column({
    name: 'lastMessageUpdatedAt',
    type: 'timestamp',
    nullable: true,
  })
  lastMessageUpdatedAt: Date;

  // @TODO: check if we need title column and why? (@Expera)
  //   @Column({ nullable: false })
  //   title: string;

  // @TODO: later on we have to link this with galleryMedia table
  //   @Column({ nullable: false })
  //   gallery: string;

  @AfterInsert()
  onInsert() {
    console.log('Inserted Chatroom with id', this.id, this.name);
  }

  @AfterUpdate()
  logUpdate() {
    console.log('Updated Chatroom with id', this.id, this.name);
  }
}

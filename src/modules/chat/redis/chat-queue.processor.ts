import { Process, Processor } from '@nestjs/bull';
import { Job } from 'bull';
import {
  chatQueueEvents,
  CHAT_QUEUE,
  SAVE_MESSAGE_JOB_DATA,
  UPDATE_MESSAGE_JOB_DATA,
} from './types';

import { ChatMessageService } from '../chat-message/chat-message.service';

@Processor(CHAT_QUEUE)
export class ChatDBQueueConsumer {
  constructor(private chatMessageService: ChatMessageService) {}

  @Process(chatQueueEvents.SAVE_MESSAGE_TO_DATABASE)
  async saveToDatabase(job: Job<SAVE_MESSAGE_JOB_DATA>) {
    const {
      data: { messages, currentRoomId, user },
    } = job.data;
    this.chatMessageService.createMessageBulk(messages, currentRoomId, user);
  }

  @Process(chatQueueEvents.UPDATE_MESSAGE_STATUS_IN_DATABASE)
  async updateEntry(job: Job<UPDATE_MESSAGE_JOB_DATA>) {
    const {
      data: { messages, seenStatus, currentRoomId, acknowledingUser },
    } = job.data;
    this.chatMessageService.updateMessageStatusesBulk(
      messages,
      seenStatus,
      currentRoomId,
      acknowledingUser,
    );
  }
}

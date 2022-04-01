import { Injectable } from '@nestjs/common';
import { Queue } from 'bull';
import { InjectQueue } from '@nestjs/bull';
import {
  IMESSAGE,
  INCOMING_MESSAGE_PAYLOAD,
} from 'src/modules/chat/socket/chat-socket.types';
import { SeenStatus } from 'src/modules/chat/chat.types';
import {
  CHAT_QUEUE,
  chatQueueEvents,
  UPDATE_MESSAGE_JOB_DATA,
  SAVE_MESSAGE_JOB_DATA,
} from './types';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';

@Injectable()
export class ChatQueueService {
  constructor(@InjectQueue(CHAT_QUEUE) private chatDatabaseQueue: Queue) {}

  saveToDB(messages: IMESSAGE[], currentRoomId: string, user: IUserJwt): void {
    const jobData: SAVE_MESSAGE_JOB_DATA = {
      type: chatQueueEvents.SAVE_MESSAGE_TO_DATABASE,
      data: { messages, currentRoomId, user },
    };
    this.chatDatabaseQueue.add(
      chatQueueEvents.SAVE_MESSAGE_TO_DATABASE,
      jobData,
    );
  }

  updateMessageStatusInDB(
    messages: INCOMING_MESSAGE_PAYLOAD[],
    seenStatus: SeenStatus,
    currentRoomId: string,
    acknowledingUser: IUserJwt,
  ): void {
    const jobData: UPDATE_MESSAGE_JOB_DATA = {
      type: chatQueueEvents.UPDATE_MESSAGE_STATUS_IN_DATABASE,
      data: { messages, seenStatus, currentRoomId, acknowledingUser },
    };
    this.chatDatabaseQueue.add(
      chatQueueEvents.SAVE_MESSAGE_TO_DATABASE,
      jobData,
    );
  }
}

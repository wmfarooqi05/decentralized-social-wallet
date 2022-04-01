import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import {
  IMESSAGE,
  INCOMING_MESSAGE_PAYLOAD,
} from 'src/modules/chat/socket/chat-socket.types';
import { SeenStatus } from '../chat.types';

export const CHAT_QUEUE = 'CHAT_QUEUE';
type CHAT_QUEUE_EVENT =
  | 'SAVE_MESSAGE_TO_DATABASE'
  | 'UPDATE_MESSAGE_STATUS_IN_DATABASE';

export const chatQueueEvents: Record<CHAT_QUEUE_EVENT, CHAT_QUEUE_EVENT> = {
  SAVE_MESSAGE_TO_DATABASE: 'SAVE_MESSAGE_TO_DATABASE',
  UPDATE_MESSAGE_STATUS_IN_DATABASE: 'UPDATE_MESSAGE_STATUS_IN_DATABASE',
};

interface JOB_DATA {
  type: CHAT_QUEUE_EVENT;
}

export interface SAVE_MESSAGE_JOB_DATA extends JOB_DATA {
  data: {
    messages: IMESSAGE[];
    currentRoomId: string;
    user: IUserJwt;
  };
}

export interface UPDATE_MESSAGE_JOB_DATA extends JOB_DATA {
  data: {
    messages: INCOMING_MESSAGE_PAYLOAD[];
    seenStatus: SeenStatus;
    currentRoomId: string;
    acknowledingUser: IUserJwt;
  };
}

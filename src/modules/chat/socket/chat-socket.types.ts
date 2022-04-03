import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';
import { Reaction, SeenStatus, SeenStatuses } from '../chat.types';

export type SOCKET_CUSTOM_INCOMING_EVENT_TYPE =
  | 'NEW_MESSAGE'
  | 'TYPING'
  | 'UPDATE_MESSAGE_STATUS'
  | 'JOIN_ROOM'
  | 'MESSAGE_RECEIVED'
  | 'DISCONNECT'
  | 'LEAVE_ROOM'
  // Check if we need these types
  | 'MESSAGE_DELIVERED'
  | 'MESSAGE_SEEN'
  | 'CHECK_UPDATES'
  | 'PRINT_MAP'; // remove this one

export const SocketCustomIncomingEventTypes: Record<
  SOCKET_CUSTOM_INCOMING_EVENT_TYPE,
  SOCKET_CUSTOM_INCOMING_EVENT_TYPE
> = {
  DISCONNECT: 'DISCONNECT',
  JOIN_ROOM: 'JOIN_ROOM',
  MESSAGE_RECEIVED: 'MESSAGE_RECEIVED',
  NEW_MESSAGE: 'NEW_MESSAGE',
  TYPING: 'TYPING',
  UPDATE_MESSAGE_STATUS: 'UPDATE_MESSAGE_STATUS',
  LEAVE_ROOM: 'LEAVE_ROOM',

  // Check if we need these types
  CHECK_UPDATES: 'CHECK_UPDATES',
  MESSAGE_DELIVERED: 'MESSAGE_DELIVERED',
  MESSAGE_SEEN: 'MESSAGE_SEEN',
  PRINT_MAP: 'PRINT_MAP', // remove this one
};

export type OUTGOING_CHANNEL_EVENT_TYPE =
  | 'CLIENT_JOINED_ROOM'
  | 'CLIENT_ON_NEW_MESSAGE'
  | 'CLIENT_ON_TYPING'
  | 'CLIENT_ROOM_LEFT';

export const OutgoingChannelEventTypes: Record<
  OUTGOING_CHANNEL_EVENT_TYPE,
  OUTGOING_CHANNEL_EVENT_TYPE
> = {
  CLIENT_JOINED_ROOM: 'CLIENT_JOINED_ROOM',
  CLIENT_ON_NEW_MESSAGE: 'CLIENT_ON_NEW_MESSAGE',
  CLIENT_ON_TYPING: 'CLIENT_ON_TYPING',
  CLIENT_ROOM_LEFT: 'CLIENT_ROOM_LEFT',
};

export type OUTGOING_SINGLE_CLIENT_EVENT_TYPE =
  | 'SINGLE_CLIENT_ON_MESSAGE_SENT'
  | 'SINGLE_CLIENT_UPDATE_MESSAGE_STATUS';

export const OutgoingSingleClientEventType: Record<
  OUTGOING_SINGLE_CLIENT_EVENT_TYPE,
  OUTGOING_SINGLE_CLIENT_EVENT_TYPE
> = {
  SINGLE_CLIENT_ON_MESSAGE_SENT: 'SINGLE_CLIENT_ON_MESSAGE_SENT',
  SINGLE_CLIENT_UPDATE_MESSAGE_STATUS: 'SINGLE_CLIENT_UPDATE_MESSAGE_STATUS',
};

export type MESSAGE_TYPE = 'TEXT' | 'IMAGE';

// @TODO: align this with chatroom message export type
export type IMESSAGE = {
  chatroomId: string;
  userId: string;
  messageContent: string;
  messageType: MESSAGE_TYPE;
  messageRandomId: string;
  seenStatuses?: SeenStatuses[];
  reactions?: Reaction[];
  sendingTime?: Date;
  seenTicksCount?: number;
};

export type EXTRA_DATA_INCOMING = {
  seenStatus?: SeenStatus;
  typing?: boolean;
};

export type EXTRA_DATA_OUTGOING = {
  seenStatus?: SeenStatus;
  typing?: boolean;
};

export type SOCKET_OUTGOING_PAYLOAD = {
  currentRoomId: string;
  user: IUserJwt; // @TODO: why we need this
  messages?: IMESSAGE[]; // change this to array
  extraData?: EXTRA_DATA_OUTGOING;
};

export type INCOMING_MESSAGE_PAYLOAD = {
  id: string;
  chatroomId?: string;
  userId?: string;
  messageContent: string;
  messageType: MESSAGE_TYPE;
  messageRandomId: string;
  seenStatuses?: SeenStatuses[];
  reactions?: Reaction[];
  sendingTime?: Date;
  seenTicksCount?: number;
};

export type SOCKET_INCOMING_PAYLOAD = {
  currentRoomId: string; //@TODO: fix this and rely on map
  user: IUserJwt;
  messages?: INCOMING_MESSAGE_PAYLOAD[];
  extraData?: EXTRA_DATA_INCOMING;
};

export type SOCKET_USER_STATUS = 'ONLINE' | 'OFFLINE';

export type USER_MAP_TYPE = {
  username: string;
  clientId: string;
  status: SOCKET_USER_STATUS;
  currentRoomId?: string | null;
};

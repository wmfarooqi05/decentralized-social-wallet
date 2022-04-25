export type SeenStatus =
  | 'SENT'
  | 'NOT_SENT'
  | 'SENDING'
  | 'NOT_DELIVERED'
  | 'DELIVERED'
  | 'SEEN'
  | 'READ';

export const SeenStatusTypes: SeenStatus[] = [
  'SENT',
  'SENDING',
  'NOT_SENT',
  'NOT_DELIVERED',
  'DELIVERED',
  'READ',
  'SEEN',
];

export type SeenStatuses = {
  userId: string;
  updatedAt: Date;
  status: SeenStatus;
};

export enum MESSAGE_TYPE_ENUM {
  TEXT = "TEXT",
  IMAGE = "IMAGE",
  VIDEO = "VIDEO",
  LOCATION = "LOCATION",
  AUDIO = "AUDIO",
  FILE = "FILE",
  CONTACT = "CONTACT",
}

export type Reaction = {
  userId: string;
  reaction: number;
};

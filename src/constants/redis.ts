// @TODO: remove all of this and place only in required placesß

import { BullModuleOptions } from '@nestjs/bull';

type QUEUE_TYPE = 'CHAT_QUEUE' | 'UPLOAD_QUEUE';
export const queues: Record<QUEUE_TYPE, QUEUE_TYPE> = {
  CHAT_QUEUE: 'CHAT_QUEUE',
  UPLOAD_QUEUE: 'UPLOAD_QUEUE',
};

export const registeredQueues: BullModuleOptions[] = Object.keys(queues).map(
  (key) => {
    return {
      name: queues[key],
    };
  },
);

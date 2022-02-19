import express from 'express';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';

declare global {
  namespace Express {
    interface Request {
      currentUser: IUserJwt;
    }
  }
}

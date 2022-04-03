import { Request } from 'express';
import { IUserJwt } from 'src/common/modules/jwt/jwt-payload.interface';

interface RequestWithUser extends Request {
  user: IUserJwt;
}

export default RequestWithUser;

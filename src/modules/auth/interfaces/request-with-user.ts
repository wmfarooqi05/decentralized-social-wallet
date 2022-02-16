import { Request } from 'express';
import { IUser_Jwt } from 'src/common/modules/jwt/jwt-payload.interface';
 
interface RequestWithUser extends Request {
  user: IUser_Jwt;
}
 
export default RequestWithUser;
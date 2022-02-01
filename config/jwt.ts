import { registerAs } from '@nestjs/config';
import { JWT_CONSTANTS } from '../src/constants/jwt';

import {readFileSync} from 'fs'
import * as path from 'path';
const publicKey = readFileSync(path.resolve(".", "jwtRS256.key.pub"), 'utf-8').replace(/\\n/gm, '\n');
const privateKey = readFileSync(path.resolve(".", "jwtRS256.key"), 'utf-8').replace(/\\n/gm, '\n');

export default registerAs(JWT_CONSTANTS.JWT_SECRET, () => ({
  [JWT_CONSTANTS.PUBLIC_KEY]: publicKey,
  [JWT_CONSTANTS.PRIVATE_KEY]: privateKey,
}));

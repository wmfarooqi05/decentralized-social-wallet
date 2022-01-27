import { Injectable } from '@nestjs/common';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';

const scrypt = promisify(_scrypt);

@Injectable()
export class PasswordService {
  async hashPassword(password: string): Promise<string> {
    // Hash the users password
    // Generate a salt
    const salt = randomBytes(8).toString('hex');
    // Hash the salt and the password together
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    // Join the hashed result and the salt together
    const result = salt + '.' + hash.toString('hex');

    return result;
  }

  async validatePassword(password: string, hashedPassword: string): Promise<boolean> {

    const [salt, storedHash] = hashedPassword.split('.');

    const hash = (await scrypt(password, salt, 32)) as Buffer;

    return storedHash === hash.toString('hex');
  }
}

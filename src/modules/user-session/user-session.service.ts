import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SessionStatus, UserSession } from './user-session.entity';
import { randomBytes } from 'crypto';
import { ConfigService } from '@nestjs/config';
import * as moment from 'moment';

@Injectable()
export class UserSessionService {
  constructor(
    @InjectRepository(UserSession)
    private userSessionRepository: Repository<UserSession>,
    private configService: ConfigService,
  ) {}

  async generateRefreshToken(user, ipAddress) {
    // create a refresh token that expires in 7 days
    const refreshToken = this.randomTokenString();
    const userSession = this.userSessionRepository.create({
      user: user.id,
      generatedIpAddress: ipAddress,
      lastLoginIpAddress: ipAddress,
      lastLogin: new Date(),
      refreshToken,
      status: SessionStatus.ACTIVE,
    });

    await this.userSessionRepository.save(userSession);
    return refreshToken;
  }

  randomTokenString() {
    return randomBytes(this.configService.get('REFRESH_TOKEN_LENGTH')).toString(
      'hex',
    );
  }

  async verifyTokenExists(user, refreshToken) {
    const tokenExists = await this.userSessionRepository.findOne({
      where: {
        user,
        refreshToken,
      },
    });
    const oldTime = moment(tokenExists.exipredAt.toString(), 'L');

    if (!tokenExists) {
      throw new UnauthorizedException("Refresh Token doesn't exist");
    } else if (oldTime.diff(moment()) < 0) {
      throw new UnauthorizedException(
        'Refresh Token expired, please Login again',
      );
    }
  }
  async logout(user, refreshToken) {
    const deletedSession = await this.userSessionRepository.delete({
      user: user,
      refreshToken,
    });

    if (!deletedSession.affected) {
      throw new NotFoundException(
        `No session found for User with Id:${user} against given refresh token`,
      );
    }

    return deletedSession;
  }
}

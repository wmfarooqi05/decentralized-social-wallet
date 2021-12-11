import { Test } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';

describe('AuthService', () => {
  let service: AuthService;
  let fakeUsersService: Partial<UsersService>;

  beforeEach(async () => {
    // Create a fake copy of the users service
    const users: User[] = [];
    fakeUsersService = {
      find: (phoneNumber: string) => {
        const filteredUsers = users.filter((user) => user.phoneNumber === phoneNumber);
        return Promise.resolve(filteredUsers);
      },
      create: (phoneNumber: string, password: string) => {
        const user = {
          id: Math.floor(Math.random() * 999999),
          phoneNumber,
          password,
        } as User;
        users.push(user);
        return Promise.resolve(user);
      },
    };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: fakeUsersService,
        },
      ],
    }).compile();

    service = module.get(AuthService);
  });

  it('can create an instance of auth service', async () => {
    expect(service).toBeDefined();
  });

  it('creates a new user with a salted and hashed password', async () => {
    const user = await service.signup('asdf@asdf.com', 'asdf');

    expect(user.password).not.toEqual('asdf');
    const [salt, hash] = user.password.split('.');
    expect(salt).toBeDefined();
    expect(hash).toBeDefined();
  });

  it('throws an error if user signs up with phoneNumber that is in use', async (done) => {
    await service.signup('asdf@asdf.com', 'asdf');
    try {
      await service.signup('asdf@asdf.com', 'asdf');
    } catch (err) {
      done();
    }
  });

  it('throws if signin is called with an unused phoneNumber', async (done) => {
    try {
      await service.signin('asdflkj@asdlfkj.com', 'passdflkj');
    } catch (err) {
      done();
    }
  });

  it('throws if an invalid password is provided', async (done) => {
    await service.signup('laskdjf@alskdfj.com', 'password');
    try {
      await service.signin('laskdjf@alskdfj.com', 'laksdlfkj');
    } catch (err) {
      done();
    }
  });

  it('returns a user if correct password is provided', async () => {
    await service.signup('asdf@asdf.com', 'mypassword');

    const user = await service.signin('asdf@asdf.com', 'mypassword');
    expect(user).toBeDefined();
  });
});
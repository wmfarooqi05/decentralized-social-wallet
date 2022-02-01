import { Test } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from '../user/user.service';
import { User } from '../user/user.entity';

describe('AuthService', () => {
  let service: AuthService;
  let fakeUserService: Partial<UserService>;

  beforeEach(async () => {
    // Create a fake copy of the user service
    const user: User[] = [];
    fakeUserService = {
      find: (phoneNumber: string) => {
        const filteredUser = user.filter((user) => user.phoneNumber === phoneNumber);
        return Promise.resolve(filteredUser);
      },
      create: (phoneNumber: string, password: string) => {
        const user = {
          id: Math.floor(Math.random() * 999999),
          phoneNumber,
          password,
        } as User;
        user.push(user);
        return Promise.resolve(user);
      },
    };

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: fakeUserService,
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

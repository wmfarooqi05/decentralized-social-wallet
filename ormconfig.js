var dbConfig = {
  type: 'postgres',
  port: 5432,
  host: 'localhost',
  username: 'postgres',
  password: 'root',
  database: 'crypto_wallet',
  synchronize: true,
  migrations: ['migrations/*.js'],
  cli: {
    migrationsDir: 'migrations',
  },
};

switch (process.env.NODE_ENV) {
  case 'development':
    Object.assign(dbConfig, {
      entities: ['**/*.entity.js'],
    });
    break;
  case 'test':
    Object.assign(dbConfig, {
      type: 'sqlite',
      database: 'test.sqlite',
      entities: ['**/*.entity.ts'],
      migrationsRun: true,
    });
    break;
  case 'production':
    break;
  default:
    throw new Error('unknown environment');
}

module.exports = dbConfig;

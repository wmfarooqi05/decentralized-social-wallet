const dbConfig = {
  type: process.env.DB_TYPE,
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE_NAME,
  entities: ['**/**/*.entity.js'],
  synchronize: true, // DEV only, do not use on PROD!
  migrations: ['migrations/*.js'],
  cli: {
    migrationsDir: 'migrations',
  },
};

switch (process.env.NODE_ENV) {
  case 'development':
    Object.assign(dbConfig, {
      entities: ['**/**/*.entity.js'],
    });
    break;

  case 'production': 
    Object.assign(dbConfig, {
      entities: ['**/**/*.entity.js'],
      synchronize: false,
    });
    break;

  case 'test':
    Object.assign(dbConfig, {
      type: 'sqlite',
      database: 'test.sqlite',
      entities: ['**/**/*.entity.js'],
      migrationsRun: true,
    });
    break;
  default:
    throw new Error('unknown environment');
}

module.exports = dbConfig;

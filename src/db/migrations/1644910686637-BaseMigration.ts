import { MigrationInterface, QueryRunner } from 'typeorm';

export class BaseMigration1644910686637 implements MigrationInterface {
  name = 'BaseMigration1644910686637';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "otp" ALTER COLUMN "expiryTime" SET DEFAULT '"2022-02-15T07:39:12.522Z"'`,
    );
    await queryRunner.query(
      `ALTER TABLE "otp" ALTER COLUMN "createdAt" SET DEFAULT '"2022-02-15T07:38:12.523Z"'`,
    );
    await queryRunner.query(
      `ALTER TABLE "transaction" DROP CONSTRAINT "PK_89eadb93a89810556e1cbcd6ab9"`,
    );
    await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "id"`);
    await queryRunner.query(
      `ALTER TABLE "transaction" ADD "id" uuid NOT NULL DEFAULT uuid_generate_v4()`,
    );
    await queryRunner.query(
      `ALTER TABLE "transaction" ADD CONSTRAINT "PK_89eadb93a89810556e1cbcd6ab9" PRIMARY KEY ("id")`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_session" ALTER COLUMN "exipredAt" SET DEFAULT '"2022-02-22T07:38:12.524Z"'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user_session" ALTER COLUMN "exipredAt" SET DEFAULT '2022-02-22 07:36:23.219'`,
    );
    await queryRunner.query(
      `ALTER TABLE "transaction" DROP CONSTRAINT "PK_89eadb93a89810556e1cbcd6ab9"`,
    );
    await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "id"`);
    await queryRunner.query(
      `ALTER TABLE "transaction" ADD "id" SERIAL NOT NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "transaction" ADD CONSTRAINT "PK_89eadb93a89810556e1cbcd6ab9" PRIMARY KEY ("id")`,
    );
    await queryRunner.query(
      `ALTER TABLE "otp" ALTER COLUMN "createdAt" SET DEFAULT '2022-02-15 07:36:23.149'`,
    );
    await queryRunner.query(
      `ALTER TABLE "otp" ALTER COLUMN "expiryTime" SET DEFAULT '2022-02-15 07:37:23.148'`,
    );
  }
}

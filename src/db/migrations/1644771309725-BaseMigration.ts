import {MigrationInterface, QueryRunner} from "typeorm";

export class UserMigration1644771309725 implements MigrationInterface {
    name = 'UserMigration1644771309725'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "report" ("id" SERIAL NOT NULL, "publicKey" character varying NOT NULL, "status" "public"."report_status_enum" NOT NULL DEFAULT 'UNVERIFIED', "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "userId" integer, CONSTRAINT "PK_99e4d0bea58cba73c57f935a546" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "transactionPayload"`);
        await queryRunner.query(`ALTER TABLE "otp" DROP CONSTRAINT "FK_db724db1bc3d94ad5ba38518433"`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP CONSTRAINT "FK_b5eb7aa08382591e7c2d1244fe5"`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP CONSTRAINT "FK_ed3e32981d7a640be5480effecf"`);
        await queryRunner.query(`ALTER TABLE "user" DROP CONSTRAINT "PK_cace4a159ff9f2512dd42373760"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "user" ADD "id" SERIAL NOT NULL`);
        await queryRunner.query(`ALTER TABLE "user" ADD CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "otp" DROP CONSTRAINT "PK_32556d9d7b22031d7d0e1fd6723"`);
        await queryRunner.query(`ALTER TABLE "otp" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "otp" ADD "id" SERIAL NOT NULL`);
        await queryRunner.query(`ALTER TABLE "otp" ADD CONSTRAINT "PK_32556d9d7b22031d7d0e1fd6723" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "otp" ALTER COLUMN "expiryTime" SET DEFAULT '"2022-02-13T16:56:15.144Z"'`);
        await queryRunner.query(`ALTER TABLE "otp" ALTER COLUMN "createdAt" SET DEFAULT '"2022-02-13T16:55:15.145Z"'`);
        await queryRunner.query(`ALTER TABLE "otp" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "otp" ADD "userId" integer`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "senderId"`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD "senderId" integer`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "recieverId"`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD "recieverId" integer`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP CONSTRAINT "PK_adf3b49590842ac3cf54cac451a"`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD "id" SERIAL NOT NULL`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD CONSTRAINT "PK_adf3b49590842ac3cf54cac451a" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "user_session" ALTER COLUMN "exipredAt" SET DEFAULT '"2022-02-20T16:55:15.147Z"'`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD "userId" integer`);
        await queryRunner.query(`ALTER TABLE "report" ADD CONSTRAINT "FK_e347c56b008c2057c9887e230aa" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "otp" ADD CONSTRAINT "FK_db724db1bc3d94ad5ba38518433" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD CONSTRAINT "FK_ed3e32981d7a640be5480effecf" FOREIGN KEY ("senderId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD CONSTRAINT "FK_db089844f082ef116acdd3e636d" FOREIGN KEY ("recieverId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD CONSTRAINT "FK_b5eb7aa08382591e7c2d1244fe5" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user_session" DROP CONSTRAINT "FK_b5eb7aa08382591e7c2d1244fe5"`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP CONSTRAINT "FK_db089844f082ef116acdd3e636d"`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP CONSTRAINT "FK_ed3e32981d7a640be5480effecf"`);
        await queryRunner.query(`ALTER TABLE "otp" DROP CONSTRAINT "FK_db724db1bc3d94ad5ba38518433"`);
        await queryRunner.query(`ALTER TABLE "report" DROP CONSTRAINT "FK_e347c56b008c2057c9887e230aa"`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD "userId" uuid`);
        await queryRunner.query(`ALTER TABLE "user_session" ALTER COLUMN "exipredAt" SET DEFAULT '2022-02-14 20:58:26.913'`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP CONSTRAINT "PK_adf3b49590842ac3cf54cac451a"`);
        await queryRunner.query(`ALTER TABLE "user_session" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD "id" uuid NOT NULL DEFAULT uuid_generate_v4()`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD CONSTRAINT "PK_adf3b49590842ac3cf54cac451a" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "recieverId"`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD "recieverId" uuid`);
        await queryRunner.query(`ALTER TABLE "transaction" DROP COLUMN "senderId"`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD "senderId" uuid`);
        await queryRunner.query(`ALTER TABLE "otp" DROP COLUMN "userId"`);
        await queryRunner.query(`ALTER TABLE "otp" ADD "userId" uuid`);
        await queryRunner.query(`ALTER TABLE "otp" ALTER COLUMN "createdAt" SET DEFAULT '2022-02-07 20:58:26.835'`);
        await queryRunner.query(`ALTER TABLE "otp" ALTER COLUMN "expiryTime" SET DEFAULT '2022-02-07 20:59:26.834'`);
        await queryRunner.query(`ALTER TABLE "otp" DROP CONSTRAINT "PK_32556d9d7b22031d7d0e1fd6723"`);
        await queryRunner.query(`ALTER TABLE "otp" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "otp" ADD "id" uuid NOT NULL DEFAULT uuid_generate_v4()`);
        await queryRunner.query(`ALTER TABLE "otp" ADD CONSTRAINT "PK_32556d9d7b22031d7d0e1fd6723" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "user" DROP CONSTRAINT "PK_cace4a159ff9f2512dd42373760"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "id"`);
        await queryRunner.query(`ALTER TABLE "user" ADD "id" uuid NOT NULL DEFAULT uuid_generate_v4()`);
        await queryRunner.query(`ALTER TABLE "user" ADD CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY ("id")`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD CONSTRAINT "FK_ed3e32981d7a640be5480effecf" FOREIGN KEY ("senderId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "user_session" ADD CONSTRAINT "FK_b5eb7aa08382591e7c2d1244fe5" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "otp" ADD CONSTRAINT "FK_db724db1bc3d94ad5ba38518433" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "transaction" ADD "transactionPayload" character varying(1000) NOT NULL`);
        await queryRunner.query(`DROP TABLE "report"`);
    }

}

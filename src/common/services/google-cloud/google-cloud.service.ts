import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DownloadResponse, Storage, Bucket } from '@google-cloud/storage';
import { StorageFile } from './storage-file';
import { GOOGLE_STORAGE_MEDIA_BUCKET } from 'src/constants/global-env';
import * as path from 'path';

@Injectable()
export class GoogleCloudService {
  private storage: Storage;
  private bucket: Bucket;

  constructor(
    // private readonly logger: Logger,
    private readonly configService: ConfigService,
  ) {
    try {
      const keyFilename = path.join(path.resolve('./'), '/google-keys.json');
      this.storage = new Storage({
        keyFilename,
      });
      this.bucket = this.storage.bucket(
        this.configService.get(GOOGLE_STORAGE_MEDIA_BUCKET),
      );
    } catch (error) {
      // this.logger.error(error);
    }
  }

  async save(filename: string, media: Buffer) {
    // const filePath = path.join(directory, image.name);
    const file = this.bucket.file(filename);

    // const options = metadata ? { metadata } : undefined;

    await file.save(media, {
      public: true,
    });
    const url =
      this.storage.apiEndpoint + '/' + this.bucket.name + '/' + filename;
    return url;
  }

  // async save(
  //   path: string,
  //   contentType: string,
  //   media: Buffer,
  //   metadata: { [key: string]: string }[],
  // ) {
  //   const object = metadata.reduce((obj, item) => Object.assign(obj, item), {});
  //   const file = this.storage
  //     .bucket('sls-my-service-dev-1638989791108')
  //     .file(path);
  //   const stream = file.createWriteStream();
  //   stream.on('finish', async () => {
  //     return await file.setMetadata({
  //       metadata: object,
  //     });
  //   });
  //   stream.end(media);
  //   // const url = this.bucket.baseUrl + path;
  //   // return url;
  // }

  async delete(path: string) {
    await this.bucket.file(path).delete({ ignoreNotFound: true });
  }

  async get(path: string): Promise<StorageFile> {
    const fileResponse: DownloadResponse = await this.bucket
      .file(path)
      .download();
    const [buffer] = fileResponse;
    const storageFile = new StorageFile();
    storageFile.buffer = buffer;
    storageFile.metadata = new Map<string, string>();
    return storageFile;
  }

  async getWithMetaData(path: string): Promise<StorageFile> {
    const [metadata] = await this.bucket.file(path).getMetadata();
    const fileResponse: DownloadResponse = await this.bucket
      .file(path)
      .download();
    const [buffer] = fileResponse;

    const storageFile = new StorageFile();
    storageFile.buffer = buffer;
    storageFile.metadata = new Map<string, string>(
      Object.entries(metadata || {}),
    );
    storageFile.contentType = storageFile.metadata.get('contentType');
    return storageFile;
  }
}

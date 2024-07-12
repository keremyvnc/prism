import { transformOas3Operations } from '@stoplight/http-spec/oas3/operation';
import { transformOas2Operations } from '@stoplight/http-spec/oas2/operation';
import { transformPostmanCollectionOperations } from '@stoplight/http-spec/postman/operation';
import * as $RefParser from '@stoplight/json-schema-ref-parser';
import { HTTPResolverOptions } from '@stoplight/json-schema-ref-parser';
import { bundleTarget, decycle } from '@stoplight/json';
import { IHttpOperation } from '@stoplight/types';
import { get } from 'lodash';
import * as os from 'os';
import type { Spec } from 'swagger-schema-official';
import type { OpenAPIObject } from 'openapi3-ts';
import type { CollectionDefinition } from 'postman-collection';

export async function getHttpOperationsFromSpec(specFilePathOrObject: string | object): Promise<IHttpOperation[]> {
  // yaml dosyamı runner.ts den aldı
  const prismVersion = require('../../package.json').version;
  const httpResolverOpts: HTTPResolverOptions = {
    headers: {
      'User-Agent': `PrismMockServer/${prismVersion} (${os.type()} ${os.arch()} ${os.release()})`,
    },
  };
  const result = decycle(
    await new $RefParser().dereference(specFilePathOrObject, { resolve: { http: httpResolverOpts } }) // buradan baştaki bilgileri çekiyoruz
  );
  getLatencyFromFromSpec(specFilePathOrObject);

  let operations: IHttpOperation[] = []; // buradan bu işlem hangi open api versiyonuna uygunsa onu alıyoruz
  if (isOpenAPI2(result)) operations = transformOas2Operations(result);
  else if (isOpenAPI3(result)) operations = transformOas3Operations(result);
  else if (isPostmanCollection(result)) operations = transformPostmanCollectionOperations(result);
  else throw new Error('Unsupported document format');

  operations.forEach((op, i, ops) => {
    console.log('OPS');
    //console.log(op);
    ops[i] = bundleTarget({
      document: {
        ...result,
        __target__: op,
      },
      path: '#/__target__',
      cloneDocument: false,
    });
    console.log(ops[i]);
  });

  return operations;
}

export async function getLatencyFromFromSpec(specFilePathOrObject: string | object): Promise<IHttpOperation[]> {
  const prismVersion = require('../../package.json').version;
  const httpResolverOpts: HTTPResolverOptions = {
    headers: {
      'User-Agent': `PrismMockServer/${prismVersion} (${os.type()} ${os.arch()} ${os.release()})`,
    },
  };
  const result = decycle(
    await new $RefParser().dereference(specFilePathOrObject, { resolve: { http: httpResolverOpts } })
  );
  console.log(result.latency);
  return result;
}

function isOpenAPI2(document: unknown): document is Spec {
  return get(document, 'swagger') !== undefined;
}

function isOpenAPI3(document: unknown): document is OpenAPIObject {
  return get(document, 'openapi') !== undefined;
}

function isPostmanCollection(document: unknown): document is CollectionDefinition {
  return Array.isArray(get(document, 'item')) && get(document, 'info.name') !== undefined;
}

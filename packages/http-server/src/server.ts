import {
  createInstance,
  IHttpNameValue,
  IHttpNameValues,
  ProblemJsonError,
  VIOLATIONS,
  IHttpConfig,
} from '@stoplight/prism-http';
import { DiagnosticSeverity, HttpMethod, IHttpOperation, Dictionary } from '@stoplight/types';
import { IncomingMessage, ServerResponse, IncomingHttpHeaders } from 'http';
import { AddressInfo } from 'net';
import { IPrismHttpServer, IPrismHttpServerOpts } from './types';
import { IPrismDiagnostic } from '@stoplight/prism-core';
import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import * as typeIs from 'type-is';
import { getHttpConfigFromRequest } from './getHttpConfigFromRequest';
import { serialize } from './serialize';
import { merge } from 'lodash/fp';
import { pipe } from 'fp-ts/function';
import * as TE from 'fp-ts/TaskEither';
import * as E from 'fp-ts/Either';
import * as IOE from 'fp-ts/IOEither';

function searchParamsToNameValues(searchParams: URLSearchParams): IHttpNameValues {
  const params = {};
  for (const key of searchParams.keys()) {
    const values = searchParams.getAll(key);
    params[key] = values.length === 1 ? values[0] : values;
  }
  return params;
}

function addressInfoToString(addressInfo: AddressInfo | string | null) {
  if (!addressInfo) return '';
  if (typeof addressInfo === 'string') return addressInfo;
  return `http://${addressInfo.address}:${addressInfo.port}`;
}

type ValidationError = {
  location: string[];
  severity: string;
  code: string | number | undefined;
  message: string | undefined;
};

const MAX_SAFE_HEADER_LENGTH = 8 * 1024 - 100; // 8kb minus some
function addViolationHeader(reply: FastifyReply, validationErrors: ValidationError[]) {
  if (validationErrors.length === 0) {
    return;
  }

  let value = JSON.stringify(validationErrors);
  if (value.length > MAX_SAFE_HEADER_LENGTH) {
    value = `Too many violations! ${value.substring(0, MAX_SAFE_HEADER_LENGTH)}`;
  }

  reply.header('sl-violations', value);
}

function parseRequestBody(request: FastifyRequest) {
  // if no body provided then return null instead of empty string
  if (
    // If the body size is null, it means the body itself is null so the promise can resolve with a null value
    request.headers['content-length'] === '0' ||
    // Per HTTP 1.1 - these 2 headers are the valid way to indicate that a body exists:
    // > The presence of a message body in a request is signaled by a Content-Length or Transfer-Encoding header field.
    // https://httpwg.org/specs/rfc9112.html#message.body
    (request.headers['transfer-encoding'] === undefined && request.headers['content-length'] === undefined)
  ) {
    return null;
  }

  if (typeIs(request.raw, ['application/json', 'application/*+json'])) {
    return request.body;
  } else {
    return request.body;
  }
}

async function addLatency(duration: number, startTime: [number, number]): Promise<void> {
  const [seconds, nanoseconds] = process.hrtime(startTime);
  const elapsedTime = seconds * 1000 + nanoseconds / 1e6; // Milisaniye cinsinden süre
  const remainingTime = duration - elapsedTime;

  if (remainingTime > 0) {
    return new Promise(resolve => setTimeout(resolve, remainingTime));
  } else {
    return Promise.resolve();
  }
}

export const createServer = (
  operations: IHttpOperation[],
  opts: IPrismHttpServerOpts,
  timeout: number
): IPrismHttpServer => {
  const { components, config } = opts;
  const server: FastifyInstance = fastify();

  server.addHook('preHandler', async (request, reply) => {
    const startTime = process.hrtime();
    const { url, method, headers } = request;
    const body = await parseRequestBody(request);

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
    const { searchParams, pathname } = new URL(url!, 'http://example.com');

    const input = {
      method: (method ? method.toLowerCase() : 'get') as HttpMethod,
      url: {
        path: pathname,
        baseUrl: searchParams.get('__server') || undefined,
        query: searchParamsToNameValues(searchParams),
      },
      headers: headers as IHttpNameValue,
      body,
    };

    components.logger.info({ input }, 'Request received');

    const requestConfig: E.Either<Error, IHttpConfig> = pipe(
      getHttpConfigFromRequest(input),
      E.map(operationSpecificConfig => ({ ...config, mock: merge(config.mock, operationSpecificConfig) }))
    );

    await pipe(
      TE.fromEither(requestConfig),
      TE.chain(requestConfig => prism.request(input, operations, requestConfig)),
      TE.chain(response =>
        TE.tryCatch(
          async () => {
            const { output } = response;

            const inputValidationErrors = response.validations.input.map(createErrorObjectWithPrefix('request'));
            const outputValidationErrors = response.validations.output.map(createErrorObjectWithPrefix('response'));
            const inputOutputValidationErrors = inputValidationErrors.concat(outputValidationErrors);

            if (inputOutputValidationErrors.length > 0) {
              addViolationHeader(reply, inputOutputValidationErrors);

              const errorViolations = outputValidationErrors.filter(
                v => v.severity === DiagnosticSeverity[DiagnosticSeverity.Error]
              );

              if (opts.config.errors && errorViolations.length > 0) {
                return IOE.left(
                  ProblemJsonError.fromTemplate(
                    VIOLATIONS,
                    'Your request/response is not valid and the --errors flag is set, so Prism is generating this error for you.',
                    { validation: errorViolations }
                  )
                );
              }
            }

            inputOutputValidationErrors.forEach(validation => {
              const message = `Violation: ${validation.location.join('.') || ''} ${validation.message}`;
              if (validation.severity === DiagnosticSeverity[DiagnosticSeverity.Error]) {
                components.logger.error({ name: 'VALIDATOR' }, message);
              } else if (validation.severity === DiagnosticSeverity[DiagnosticSeverity.Warning]) {
                components.logger.warn({ name: 'VALIDATOR' }, message);
              } else {
                components.logger.info({ name: 'VALIDATOR' }, message);
              }
            });

            if (output.headers) Object.entries(output.headers).forEach(([name, value]) => reply.header(name, value));

            // Latency ekleyerek asenkron yap
            await addLatency(timeout, startTime);

            reply
              .status(output.statusCode)
              //.type(reply.getHeader('content-type') as string | undefined)
              .send(serialize(output.body, reply.getHeader('content-type') as string | undefined));

            return undefined;
          },
          reason => new Error(String(reason))
        )
      ),
      TE.mapLeft(async (e: Error & { status?: number; additional?: { headers?: Dictionary<string> } }) => {
        if (!reply.sent) {
          reply.type('application/problem+json');

          if (e.additional && e.additional.headers)
            Object.entries(e.additional.headers).forEach(([name, value]) => reply.header(name, value));

          // Latency ekleyerek asenkron yap
          await addLatency(4000, startTime);

          reply.status(e.status || 500).send(ProblemJsonError.toProblemJson(e));
        } else {
          reply.raw.end();
        }

        components.logger.error({ input }, `Request terminated with error: ${e}`);
      })
    )();

    components.logger.info(`Request processed`);
  });

  const prism = createInstance(config, components);

  return {
    get prism() {
      console.log('prism');
      return prism;
    },

    get logger() {
      return components.logger;
    },

    close() {
      return new Promise((resolve, reject) =>
        server.close(() => {
          resolve();
        })
      );
    },

    listen: (port: number, host?: string, ...args: any[]) =>
      new Promise<string>((resolve, reject) => {
        const options: { port: number; host?: string } = { port };
        if (host) {
          options.host = host;
        }

        server.listen(options, (err: Error | null, address: string) => {
          if (err) return reject(err);
          return resolve(addressInfoToString(address));
        });
      }),
  };
};

const createErrorObjectWithPrefix = (locationPrefix: string) => (detail: IPrismDiagnostic) => ({
  location: [locationPrefix].concat(detail.path || []),
  severity: DiagnosticSeverity[detail.severity],
  code: detail.code,
  message: detail.message,
});
